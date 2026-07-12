"""Persisted-model tests reject every shape that could falsely upgrade trust."""

from __future__ import annotations

import copy
import unittest

from onceproof.model import VerificationResult


def _accepted() -> dict[str, object]:
    return {
        "verified": True,
        "reason": None,
        "witness": {
            "state": "verified_once",
            "verification_id": "vr_0123456789abcdef0123456789abcdef",
            "proof_tag": "pf_0123456789abcdef01234567",
            "client_id": "opc_0123456789abcdef01234567",
            "decided_at": 100,
            "reason": None,
        },
        "claims": {
            "client_id": "opc_0123456789abcdef01234567",
            "subject": "subject",
            "purpose": "purpose",
            "audience": "urn:onceproof:test",
            "issued_at": 90,
            "expires_at": 120,
        },
    }


def _rejected() -> dict[str, object]:
    return {
        "verified": False,
        "reason": "invalid",
        "witness": {
            "state": "rejected",
            "verification_id": "vr_0123456789abcdef0123456789abcdef",
            "proof_tag": None,
            "client_id": "opc_0123456789abcdef01234567",
            "decided_at": 100,
            "reason": "invalid",
        },
        "claims": None,
    }


class PersistedModelTests(unittest.TestCase):
    def assert_invalid(self, value: object) -> None:
        with self.assertRaisesRegex(ValueError, "invalid_persisted_verification"):
            VerificationResult.from_dict(value)

    def test_valid_accepted_rejected_and_replay_shapes_round_trip(self) -> None:
        accepted = VerificationResult.from_dict(_accepted())
        rejected = VerificationResult.from_dict(_rejected())
        replay_value = _rejected()
        replay_value["reason"] = "already_consumed"
        replay_value["witness"]["state"] = "replay_rejected"  # type: ignore[index]
        replay_value["witness"]["proof_tag"] = "pf_0123456789abcdef01234567"  # type: ignore[index]
        replay_value["witness"]["reason"] = "already_consumed"  # type: ignore[index]
        replay = VerificationResult.from_dict(replay_value)

        self.assertTrue(accepted.verified)
        self.assertEqual("invalid", rejected.reason)
        self.assertEqual("replay_rejected", replay.witness.state)

    def test_wrong_top_level_types_and_claim_times_fail_closed(self) -> None:
        self.assert_invalid([])
        wrong_boolean = _accepted()
        wrong_boolean["verified"] = "true"
        self.assert_invalid(wrong_boolean)
        wrong_time = _accepted()
        wrong_time["witness"]["decided_at"] = True  # type: ignore[index]
        self.assert_invalid(wrong_time)
        inverted_expiry = _accepted()
        inverted_expiry["claims"]["expires_at"] = 90  # type: ignore[index]
        self.assert_invalid(inverted_expiry)

    def test_invalid_witness_members_fail_closed(self) -> None:
        for field, value in (
            ("proof_tag", 7),
            ("client_id", ""),
            ("reason", "invented"),
            ("verification_id", ""),
        ):
            candidate = _rejected()
            candidate["witness"][field] = value  # type: ignore[index]
            with self.subTest(field=field):
                self.assert_invalid(candidate)

    def test_impossible_result_invariants_fail_closed(self) -> None:
        accepted_with_reason = _accepted()
        accepted_with_reason["reason"] = "invalid"
        self.assert_invalid(accepted_with_reason)

        rejected_with_claims = _rejected()
        rejected_with_claims["claims"] = copy.deepcopy(_accepted()["claims"])
        self.assert_invalid(rejected_with_claims)

        rejected_with_accepted_state = _rejected()
        rejected_with_accepted_state["witness"]["state"] = "verified_once"  # type: ignore[index]
        self.assert_invalid(rejected_with_accepted_state)


if __name__ == "__main__":
    unittest.main()
