"""The service tests pin the proof lifecycle at its trust boundaries."""

from __future__ import annotations

import base64
import concurrent.futures
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from onceproof.errors import RateLimitError, RestoreRequiredError, StoreCorruptionError
from onceproof.keyring import KeyRing
from onceproof.service import OnceproofService
from onceproof.store import Store


class MutableClock:
    """Expose an explicit clock so expiry tests never race wall time."""

    def __init__(self, now: int = 1_800_000_000) -> None:
        self.now = now

    def __call__(self) -> int:
        return self.now


class OnceproofServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.keyring = KeyRing.create(self.root / "keyring.json")
        self.clock = MutableClock()
        Store.create(self.root / "onceproof.sqlite3")
        self.service = OnceproofService(
            database_path=self.root / "onceproof.sqlite3",
            keyring=self.keyring,
            clock=self.clock,
        )
        self.client = self.service.create_client(
            name="checkout",
            allowed_audiences=("https://api.example.test/checkout",),
            proof_ttl_seconds=120,
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def issue(self, **overrides: object):
        request = {
            "issuance_secret": self.client.issuance_secret,
            "subject": "user_123",
            "purpose": "checkout",
            "audience": "https://api.example.test/checkout",
        }
        request.update(overrides)
        return self.service.issue_proof(**request)

    def verify(self, proof: str, **overrides: object):
        request = {
            "verification_secret": self.client.verification_secret,
            "proof": proof,
            "subject": "user_123",
            "purpose": "checkout",
            "audience": "https://api.example.test/checkout",
        }
        request.update(overrides)
        return self.service.verify_proof(**request)

    def test_issued_proof_verifies_once_then_replay_is_rejected(self) -> None:
        issued = self.issue()

        first = self.verify(issued.proof)
        replay = self.verify(issued.proof)

        self.assertEqual("issued", issued.receipt.state)
        self.assertNotIn(issued.proof, json.dumps(issued.receipt.to_dict()))
        self.assertTrue(first.verified)
        self.assertEqual("verified_once", first.witness.state)
        self.assertFalse(replay.verified)
        self.assertEqual("already_consumed", replay.reason)
        self.assertEqual("replay_rejected", replay.witness.state)

    def test_issuance_ttl_starts_after_the_write_lock_is_acquired(self) -> None:
        moments = iter((self.clock.now, self.clock.now + 10))
        self.service.clock = lambda: next(moments)

        issued = self.issue(ttl_seconds=30)

        self.assertEqual(self.clock.now + 10, issued.receipt.issued_at)
        self.assertEqual(self.clock.now + 40, issued.receipt.expires_at)

    def test_expired_proof_is_rejected_without_claims(self) -> None:
        issued = self.issue(ttl_seconds=10)
        self.clock.now += 11

        result = self.verify(issued.proof)

        self.assertFalse(result.verified)
        self.assertEqual("expired", result.reason)
        self.assertIsNone(result.claims)
        self.assertEqual("rejected", result.witness.state)

    def test_consumed_proof_remains_a_replay_after_its_ttl(self) -> None:
        issued = self.issue(ttl_seconds=10)
        self.assertTrue(self.verify(issued.proof).verified)
        self.clock.now += 11

        replay = self.verify(issued.proof)

        self.assertEqual("already_consumed", replay.reason)
        self.assertEqual("replay_rejected", replay.witness.state)

    def test_verification_time_is_sampled_after_the_write_lock_is_acquired(self) -> None:
        issued = self.issue(ttl_seconds=10)
        moments = iter((issued.receipt.expires_at - 1, issued.receipt.expires_at + 1))
        self.service.clock = lambda: next(moments)

        result = self.verify(issued.proof)

        self.assertEqual("expired", result.reason)
        self.assertEqual(issued.receipt.expires_at + 1, result.witness.decided_at)

    def test_binding_mismatch_does_not_consume_the_proof(self) -> None:
        issued = self.issue()

        mismatch = self.verify(issued.proof, purpose="password_reset")
        correct = self.verify(issued.proof)

        self.assertFalse(mismatch.verified)
        self.assertEqual("binding_mismatch", mismatch.reason)
        self.assertTrue(correct.verified)

    def test_unlisted_audience_cannot_be_issued(self) -> None:
        with self.assertRaisesRegex(ValueError, "audience_not_allowed"):
            self.issue(audience="https://attacker.example/")

    def test_issuance_quota_is_durable_and_resets_after_the_window(self) -> None:
        limited = self.service.create_client(
            name="limited-issuer",
            allowed_audiences=("urn:onceproof:limited-issuer",),
            issue_limit_per_minute=2,
        )

        def issue_limited(subject: str):
            return self.service.issue_proof(
                issuance_secret=limited.issuance_secret,
                subject=subject,
                purpose="quota",
                audience="urn:onceproof:limited-issuer",
            )

        issue_limited("one")
        issue_limited("two")
        with self.assertRaises(RateLimitError) as blocked:
            issue_limited("three")
        self.assertEqual(60, blocked.exception.retry_after_seconds)

        self.clock.now -= 10
        with self.assertRaises(RateLimitError) as backward_clock:
            issue_limited("three")
        self.assertEqual(60, backward_clock.exception.retry_after_seconds)

        self.clock.now += 70
        self.assertEqual("issued", issue_limited("three").receipt.state)

    def test_verification_quota_rejects_before_mutation(self) -> None:
        limited = self.service.create_client(
            name="limited-verifier",
            allowed_audiences=("urn:onceproof:limited-verifier",),
            verify_limit_per_minute=1,
        )
        issued = self.service.issue_proof(
            issuance_secret=limited.issuance_secret,
            subject="subject",
            purpose="quota",
            audience="urn:onceproof:limited-verifier",
        )

        mismatch = self.service.verify_proof(
            verification_secret=limited.verification_secret,
            proof=issued.proof,
            subject="wrong",
            purpose="quota",
            audience="urn:onceproof:limited-verifier",
        )
        with self.assertRaises(RateLimitError):
            self.service.verify_proof(
                verification_secret=limited.verification_secret,
                proof=issued.proof,
                subject="subject",
                purpose="quota",
                audience="urn:onceproof:limited-verifier",
            )
        self.clock.now += 60
        accepted = self.service.verify_proof(
            verification_secret=limited.verification_secret,
            proof=issued.proof,
            subject="subject",
            purpose="quota",
            audience="urn:onceproof:limited-verifier",
        )

        self.assertEqual("binding_mismatch", mismatch.reason)
        self.assertTrue(accepted.verified)

    def test_idempotent_verification_retry_does_not_spend_a_second_quota_slot(self) -> None:
        limited = self.service.create_client(
            name="limited-idempotency",
            allowed_audiences=("urn:onceproof:limited-idempotency",),
            verify_limit_per_minute=1,
        )
        issued = self.service.issue_proof(
            issuance_secret=limited.issuance_secret,
            subject="subject",
            purpose="quota",
            audience="urn:onceproof:limited-idempotency",
        )
        request = {
            "verification_secret": limited.verification_secret,
            "proof": issued.proof,
            "subject": "subject",
            "purpose": "quota",
            "audience": "urn:onceproof:limited-idempotency",
            "idempotency_key": "quota-request-1",
        }

        first = self.service.verify_proof(**request)
        retry = self.service.verify_proof(**request)

        self.assertTrue(first.verified)
        self.assertEqual(first, retry)

    def test_rotation_does_not_reset_or_double_the_client_role_quota(self) -> None:
        limited = self.service.create_client(
            name="rotation-limit",
            allowed_audiences=("urn:onceproof:rotation-limit",),
            issue_limit_per_minute=1,
        )
        self.service.issue_proof(
            issuance_secret=limited.issuance_secret,
            subject="one",
            purpose="quota",
            audience="urn:onceproof:rotation-limit",
        )
        rotated = self.service.rotate_credential(
            client_id=limited.client_id,
            role="issuance",
            grace_seconds=30,
        )

        for secret in (limited.issuance_secret, rotated.secret):
            with self.subTest(secret_prefix=secret[:4]), self.assertRaises(RateLimitError):
                self.service.issue_proof(
                    issuance_secret=secret,
                    subject="two",
                    purpose="quota",
                    audience="urn:onceproof:rotation-limit",
                )

    def test_other_tenant_cannot_verify_or_consume_the_proof(self) -> None:
        other = self.service.create_client(
            name="other",
            allowed_audiences=("https://api.example.test/checkout",),
        )
        issued = self.issue()

        cross_tenant = self.verify(
            issued.proof,
            verification_secret=other.verification_secret,
        )
        owner = self.verify(issued.proof)

        self.assertFalse(cross_tenant.verified)
        self.assertEqual("invalid", cross_tenant.reason)
        self.assertTrue(owner.verified)

    def test_exact_idempotent_retry_returns_the_original_success(self) -> None:
        issued = self.issue()

        first = self.verify(issued.proof, idempotency_key="verify-request-1")
        retry = self.verify(issued.proof, idempotency_key="verify-request-1")

        self.assertEqual(first, retry)
        self.assertEqual(first.witness.verification_id, retry.witness.verification_id)

    def test_idempotent_retry_uses_the_read_path_before_a_write_lock(self) -> None:
        issued = self.issue()
        first = self.verify(issued.proof, idempotency_key="verify-request-1")

        with patch.object(self.service.store, "_write", side_effect=AssertionError("write lock")):
            retry = self.verify(issued.proof, idempotency_key="verify-request-1")

        self.assertEqual(first, retry)

    def test_cached_retry_rechecks_rotation_grace_with_fresh_time(self) -> None:
        issued = self.issue()
        self.verify(issued.proof, idempotency_key="verify-request-1")
        rotated = self.service.rotate_credential(
            client_id=self.client.client_id,
            role="verification",
            grace_seconds=10,
        )
        moments = iter(
            (
                rotated.previous_valid_until - 1,
                rotated.previous_valid_until + 1,
                rotated.previous_valid_until + 1,
            )
        )
        self.service.clock = lambda: next(moments)

        retry = self.verify(issued.proof, idempotency_key="verify-request-1")

        self.assertEqual("credential_rejected", retry.reason)

    def test_cached_retry_rechecks_revocation_after_early_authentication(self) -> None:
        issued = self.issue()
        self.verify(issued.proof, idempotency_key="verify-request-1")
        cached_verification = self.service.store.cached_verification

        def revoke_then_read(**arguments: object):
            self.service.revoke_client(self.client.client_id)
            return cached_verification(**arguments)

        with patch.object(
            self.service.store,
            "cached_verification",
            side_effect=revoke_then_read,
        ):
            retry = self.verify(issued.proof, idempotency_key="verify-request-1")

        self.assertEqual("credential_rejected", retry.reason)

    def test_malformed_persisted_idempotent_result_fails_closed(self) -> None:
        issued = self.issue()
        self.verify(issued.proof, idempotency_key="verify-request-1")
        with closing(sqlite3.connect(self.root / "onceproof.sqlite3")) as database:
            database.execute(
                "UPDATE verifications SET result_json = ? WHERE idempotency_key = ?",
                ('{"claims":null,"reason":null,"verified":"false","witness":{}}', "verify-request-1"),
            )
            database.commit()

        with self.assertRaises(StoreCorruptionError):
            self.verify(issued.proof, idempotency_key="verify-request-1")

    def test_malformed_persisted_client_policy_fails_closed(self) -> None:
        with closing(sqlite3.connect(self.root / "onceproof.sqlite3")) as database:
            database.execute(
                "UPDATE clients SET allowed_audiences_json = 'not-json' WHERE client_id = ?",
                (self.client.client_id,),
            )
            database.commit()

        with self.assertRaises(StoreCorruptionError):
            self.issue()

    def test_idempotency_key_cannot_be_reused_for_a_different_request(self) -> None:
        first = self.issue(subject="user_1")
        second = self.issue(subject="user_2")
        self.verify(
            first.proof,
            subject="user_1",
            idempotency_key="verify-request-1",
        )

        with self.assertRaisesRegex(ValueError, "idempotency_conflict"):
            self.verify(
                second.proof,
                subject="user_2",
                idempotency_key="verify-request-1",
            )

    def test_idempotency_decision_is_retained_for_at_least_24_hours(self) -> None:
        issued = self.issue()
        first = self.verify(issued.proof, idempotency_key="verify-request-1")
        self.clock.now += 86_400
        retained = self.verify(issued.proof, idempotency_key="verify-request-1")

        self.clock.now += 1
        self.service.cleanup()
        after_horizon = self.verify(issued.proof, idempotency_key="verify-request-1")

        self.assertEqual(first, retained)
        self.assertEqual("invalid", after_horizon.reason)
        self.assertNotEqual(first.witness.verification_id, after_horizon.witness.verification_id)

    def test_concurrent_verification_has_exactly_one_winner(self) -> None:
        issued = self.issue()

        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
            results = list(pool.map(lambda _: self.verify(issued.proof), range(100)))

        winners = [result for result in results if result.verified]
        replays = [result for result in results if result.reason == "already_consumed"]
        self.assertEqual(1, len(winners))
        self.assertEqual(99, len(replays))

    def test_concurrent_idempotent_retry_returns_one_committed_witness(self) -> None:
        issued = self.issue()

        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
            results = list(
                pool.map(
                    lambda _: self.verify(issued.proof, idempotency_key="verify-request-1"),
                    range(64),
                )
            )

        self.assertTrue(all(result.verified for result in results))
        self.assertEqual(1, len({result.witness.verification_id for result in results}))

    def test_credential_rotation_has_an_explicit_grace_then_revocation(self) -> None:
        issued_before_rotation = self.issue()
        rotated = self.service.rotate_credential(
            client_id=self.client.client_id,
            role="verification",
            grace_seconds=30,
        )

        during_grace = self.verify(issued_before_rotation.proof)
        self.assertTrue(during_grace.verified)

        issued_after_rotation = self.issue(subject="user_456")
        self.clock.now += 31
        old_secret = self.service.verify_proof(
            verification_secret=self.client.verification_secret,
            proof=issued_after_rotation.proof,
            subject="user_456",
            purpose="checkout",
            audience="https://api.example.test/checkout",
        )
        new_secret = self.service.verify_proof(
            verification_secret=rotated.secret,
            proof=issued_after_rotation.proof,
            subject="user_456",
            purpose="checkout",
            audience="https://api.example.test/checkout",
        )

        self.assertFalse(old_secret.verified)
        self.assertEqual("credential_rejected", old_secret.reason)
        self.assertTrue(new_secret.verified)

    def test_revoked_issuance_credential_cannot_mint(self) -> None:
        rotated = self.service.rotate_credential(
            client_id=self.client.client_id,
            role="issuance",
            grace_seconds=0,
        )

        with self.assertRaisesRegex(PermissionError, "credential_rejected"):
            self.issue()

        issued = self.issue(issuance_secret=rotated.secret)
        self.assertTrue(self.verify(issued.proof).verified)

    def test_client_revocation_stops_both_roles_and_outstanding_proofs(self) -> None:
        issued = self.issue()

        first_revoke = self.service.revoke_client(self.client.client_id)
        repeated_revoke = self.service.revoke_client(self.client.client_id)
        verification = self.verify(issued.proof)

        self.assertTrue(first_revoke)
        self.assertFalse(repeated_revoke)
        with self.assertRaisesRegex(PermissionError, "credential_rejected"):
            self.issue()
        self.assertFalse(verification.verified)
        self.assertEqual("credential_rejected", verification.reason)
        self.assertIsNone(verification.claims)

    def test_store_contains_no_raw_proof_or_credentials(self) -> None:
        issued = self.issue()
        self.verify(issued.proof)

        with closing(sqlite3.connect(self.root / "onceproof.sqlite3")) as database:
            rows = []
            for table in ("clients", "credentials", "proofs", "verifications", "audit_events"):
                rows.extend(database.execute(f"SELECT * FROM {table}").fetchall())
        serialized = repr(rows)

        self.assertNotIn(issued.proof, serialized)
        self.assertNotIn(self.client.issuance_secret, serialized)
        self.assertNotIn(self.client.verification_secret, serialized)
        persisted = (self.root / "onceproof.sqlite3").read_bytes()
        self.assertNotIn(issued.proof.encode("utf-8"), persisted)
        self.assertNotIn(self.client.issuance_secret.encode("utf-8"), persisted)
        self.assertNotIn(self.client.verification_secret.encode("utf-8"), persisted)
        backup_path = self.service.store.backup(self.root / "backup.sqlite3")
        backup = backup_path.read_bytes()
        self.assertNotIn(issued.proof.encode("utf-8"), backup)
        self.assertNotIn(self.client.issuance_secret.encode("utf-8"), backup)
        self.assertNotIn(self.client.verification_secret.encode("utf-8"), backup)
        restored = OnceproofService(
            database_path=backup_path,
            keyring=KeyRing.load(self.root / "keyring.json"),
            clock=self.clock,
        )
        self.assertFalse(restored.ready())
        with self.assertRaises(RestoreRequiredError):
            restored.verify_proof(
                verification_secret=self.client.verification_secret,
                proof=issued.proof,
                subject="user_123",
                purpose="checkout",
                audience="https://api.example.test/checkout",
            )
        restored.activate_restored_backup()
        restored_replay = restored.verify_proof(
            verification_secret=self.client.verification_secret,
            proof=issued.proof,
            subject="user_123",
            purpose="checkout",
            audience="https://api.example.test/checkout",
        )
        self.assertTrue(restored.ready())
        self.assertEqual("credential_rejected", restored_replay.reason)

    def test_backup_restore_cannot_resurrect_a_later_consumed_proof(self) -> None:
        issued = self.issue()
        backup_path = self.service.store.backup(self.root / "rollback.sqlite3")
        self.assertTrue(self.verify(issued.proof).verified)
        restored = OnceproofService(
            database_path=backup_path,
            keyring=KeyRing.load(self.root / "keyring.json"),
            clock=self.clock,
        )

        with self.assertRaises(RestoreRequiredError):
            restored.verify_proof(
                verification_secret=self.client.verification_secret,
                proof=issued.proof,
                subject="user_123",
                purpose="checkout",
                audience="https://api.example.test/checkout",
            )
        restored.activate_restored_backup()
        result = restored.verify_proof(
            verification_secret=self.client.verification_secret,
            proof=issued.proof,
            subject="user_123",
            purpose="checkout",
            audience="https://api.example.test/checkout",
        )

        self.assertEqual("credential_rejected", result.reason)

    def test_live_database_cannot_be_activated_as_a_restore(self) -> None:
        with self.assertRaisesRegex(ValueError, "restore_activation_not_required"):
            self.service.activate_restored_backup()

    def test_missing_or_changed_hash_key_check_fails_closed(self) -> None:
        with closing(sqlite3.connect(self.root / "onceproof.sqlite3")) as database:
            database.execute(
                "UPDATE hash_keys SET key_check = 'wrong' WHERE hash_kid = ?",
                (self.keyring.current_kid,),
            )
            database.commit()

        self.assertFalse(self.service.ready())
        with self.assertRaises(StoreCorruptionError):
            self.issue()

    def test_exception_after_consume_update_rolls_back_every_boundary_record(self) -> None:
        issued = self.issue()

        with patch.object(self.service.store, "_insert_verification", side_effect=RuntimeError("fault")):
            with self.assertRaisesRegex(RuntimeError, "fault"):
                self.verify(issued.proof, idempotency_key="verify-request-1")

        reopened = OnceproofService(
            database_path=self.root / "onceproof.sqlite3",
            keyring=KeyRing.load(self.root / "keyring.json"),
            clock=self.clock,
        )
        recovered = reopened.verify_proof(
            verification_secret=self.client.verification_secret,
            proof=issued.proof,
            subject="user_123",
            purpose="checkout",
            audience="https://api.example.test/checkout",
            idempotency_key="verify-request-1",
        )
        self.assertTrue(recovered.verified)

    def test_exception_after_result_insert_rolls_back_consume_and_idempotency(self) -> None:
        issued = self.issue()

        with patch.object(self.service.store, "_insert_audit", side_effect=RuntimeError("fault")):
            with self.assertRaisesRegex(RuntimeError, "fault"):
                self.verify(issued.proof, idempotency_key="verify-request-1")

        recovered = self.verify(issued.proof, idempotency_key="verify-request-1")
        self.assertTrue(recovered.verified)

    def test_restart_preserves_consumption_and_idempotent_result(self) -> None:
        issued = self.issue()
        first = self.verify(issued.proof, idempotency_key="verify-request-1")

        reopened = OnceproofService(
            database_path=self.root / "onceproof.sqlite3",
            keyring=KeyRing.load(self.root / "keyring.json"),
            clock=self.clock,
        )
        retry = reopened.verify_proof(
            verification_secret=self.client.verification_secret,
            proof=issued.proof,
            subject="user_123",
            purpose="checkout",
            audience="https://api.example.test/checkout",
            idempotency_key="verify-request-1",
        )

        self.assertEqual(first, retry)

    def test_missing_or_uninitialized_database_is_not_created_on_open(self) -> None:
        missing = self.root / "missing.sqlite3"
        with self.assertRaisesRegex(ValueError, "database_missing"):
            OnceproofService(
                database_path=missing,
                keyring=KeyRing.load(self.root / "keyring.json"),
                clock=self.clock,
            )
        self.assertFalse(missing.exists())

        empty = self.root / "empty.sqlite3"
        empty.touch()
        empty.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "uninitialized_database"):
            OnceproofService(
                database_path=empty,
                keyring=KeyRing.load(self.root / "keyring.json"),
                clock=self.clock,
            )

    def test_incomplete_schema_fails_closed(self) -> None:
        broken = self.root / "broken.sqlite3"
        Store.create(broken)
        with closing(sqlite3.connect(broken)) as database:
            database.execute("DROP INDEX rate_events_window")

        with self.assertRaisesRegex(ValueError, "incomplete_schema:index:rate_events_window"):
            OnceproofService(
                database_path=broken,
                keyring=KeyRing.load(self.root / "keyring.json"),
                clock=self.clock,
            )

    def test_live_request_path_runs_bounded_opportunistic_cleanup(self) -> None:
        self.assertIsNone(self.service.store.status()["last_cleanup_at"])
        self.clock.now += 301

        self.issue(subject="after-cleanup-window")

        self.assertEqual(self.clock.now, self.service.store.status()["last_cleanup_at"])

    def test_hash_key_rotation_keeps_old_material_until_safe_retirement(self) -> None:
        issued = self.issue()
        old_kid = self.keyring.current_kid
        self.keyring.rotate()

        self.assertTrue(self.verify(issued.proof).verified)
        with self.assertRaisesRegex(ValueError, "key_still_in_use"):
            self.service.retire_hash_key(old_kid)

        rotated_issue = self.service.rotate_credential(
            client_id=self.client.client_id,
            role="issuance",
            grace_seconds=0,
        )
        rotated_verify = self.service.rotate_credential(
            client_id=self.client.client_id,
            role="verification",
            grace_seconds=0,
        )
        self.service.cleanup(self.clock.now + 10_000)
        self.service.retire_hash_key(old_kid)

        fresh = self.service.issue_proof(
            issuance_secret=rotated_issue.secret,
            subject="user_789",
            purpose="checkout",
            audience="https://api.example.test/checkout",
        )
        result = self.service.verify_proof(
            verification_secret=rotated_verify.secret,
            proof=fresh.proof,
            subject="user_789",
            purpose="checkout",
            audience="https://api.example.test/checkout",
        )
        self.assertTrue(result.verified)

    def test_readiness_fails_when_a_referenced_hash_key_is_missing(self) -> None:
        old_kid = self.keyring.current_kid
        self.keyring.rotate()
        self.keyring.retire(old_kid)

        self.assertFalse(self.service.ready())

    def test_readiness_fails_when_a_kid_maps_to_different_key_material(self) -> None:
        payload = json.loads((self.root / "keyring.json").read_text(encoding="utf-8"))
        payload["keys"][self.keyring.current_kid] = base64.urlsafe_b64encode(bytes(32)).decode(
            "ascii"
        ).rstrip("=")
        mismatched_path = self.root / "mismatched-keyring.json"
        mismatched_path.write_text(json.dumps(payload), encoding="utf-8")
        mismatched_path.chmod(0o600)

        mismatched = OnceproofService(
            database_path=self.root / "onceproof.sqlite3",
            keyring=KeyRing.load(mismatched_path),
            clock=self.clock,
        )

        self.assertFalse(mismatched.ready())

    def test_public_input_validation_rejects_ambiguous_values(self) -> None:
        invalid_clients = (
            ({"name": "", "allowed_audiences": ("urn:onceproof:test",)}, "invalid_name"),
            ({"name": "name", "allowed_audiences": ()}, "invalid_allowed_audiences"),
            (
                {"name": "name", "allowed_audiences": ("http://example.test",)},
                "invalid_audience",
            ),
            (
                {
                    "name": "name",
                    "allowed_audiences": ("urn:onceproof:test",),
                    "proof_ttl_seconds": True,
                },
                "invalid_proof_ttl_seconds",
            ),
            (
                {
                    "name": "name",
                    "allowed_audiences": ("urn:onceproof:test",),
                    "issue_limit_per_minute": 0,
                },
                "invalid_issue_limit_per_minute",
            ),
        )
        for arguments, error in invalid_clients:
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                self.service.create_client(**arguments)

        with self.assertRaisesRegex(ValueError, "invalid_purpose"):
            self.issue(purpose="not a purpose")
        with self.assertRaisesRegex(ValueError, "invalid_ttl_seconds"):
            self.issue(ttl_seconds=121)
        with self.assertRaisesRegex(ValueError, "invalid_idempotency_key"):
            self.verify(self.issue().proof, idempotency_key="")
        with self.assertRaisesRegex(ValueError, "invalid_role"):
            self.service.rotate_credential(client_id=self.client.client_id, role="admin")
        with self.assertRaisesRegex(ValueError, "invalid_grace_seconds"):
            self.service.rotate_credential(
                client_id=self.client.client_id,
                role="issuance",
                grace_seconds=-1,
            )
        with self.assertRaisesRegex(ValueError, "invalid_cleanup_time"):
            self.service.cleanup(True)

    def test_schema_mismatch_and_backup_path_errors_fail_before_mutation(self) -> None:
        unsupported = self.root / "unsupported.sqlite3"
        with closing(sqlite3.connect(unsupported)) as database:
            database.execute("PRAGMA user_version = 99")
        unsupported.chmod(0o600)

        with self.assertRaisesRegex(ValueError, "unsupported_schema_version:99"):
            OnceproofService(
                database_path=unsupported,
                keyring=KeyRing.load(self.root / "keyring.json"),
                clock=self.clock,
            )
        with self.assertRaisesRegex(ValueError, "backup_path_collision"):
            self.service.store.backup(self.root / "onceproof.sqlite3")
        with self.assertRaisesRegex(ValueError, "backup_parent_missing"):
            self.service.store.backup(self.root / "missing" / "backup.sqlite3")

    def test_malformed_credentials_and_proofs_do_not_cross_roles(self) -> None:
        with self.assertRaisesRegex(PermissionError, "credential_rejected"):
            self.issue(issuance_secret="malformed")
        malformed = self.verify("not-a-proof")

        self.assertFalse(malformed.verified)
        self.assertEqual("invalid", malformed.reason)


if __name__ == "__main__":
    unittest.main()
