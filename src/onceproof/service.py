"""The service binds trusted issuance to an atomic one-time verifier boundary."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from collections.abc import Callable
from pathlib import Path

from .crypto import credential_digest, key_check, proof_digest
from .errors import StoreCorruptionError
from .keyring import KeyRing
from .model import (
    ClientCredentials,
    IssuedProof,
    PreparedCredential,
    ProofReceipt,
    RotatedCredential,
    VerificationResult,
    VerificationWitness,
)
from .store import CredentialRecord, ProofRecord, Store

_PURPOSE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_IDEMPOTENCY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_AUDIENCE_PATTERN = re.compile(r"^(?:https://[^/?#\s]+(?:[/?#]\S*)?|urn:\S+)$")
_MAX_SUBJECT_LENGTH = 256
_MAX_AUDIENCE_LENGTH = 512
_MAX_NAME_LENGTH = 128
_MAX_TTL_SECONDS = 3600
_MAX_ROTATION_GRACE_SECONDS = 86_400
_MAX_RATE_LIMIT_PER_MINUTE = 100_000
_CLEANUP_INTERVAL_SECONDS = 300


def _now() -> int:
    return int(time.time())


def _new_secret(role: str, credential_id: str) -> str:
    prefix = "opi1" if role == "issuance" else "opv1"
    return f"{prefix}.{credential_id}.{secrets.token_urlsafe(32)}"


def _new_credential(role: str, client_id: str, keyring: KeyRing) -> tuple[CredentialRecord, str]:
    prefix = "ic" if role == "issuance" else "vc"
    credential_id = f"{prefix}_{secrets.token_hex(12)}"
    secret = _new_secret(role, credential_id)
    kid, key = keyring.current_key()
    record = CredentialRecord(
        credential_id=credential_id,
        client_id=client_id,
        role=role,
        hash_kid=kid,
        secret_digest=credential_digest(key, secret),
        status="current",
        valid_until=None,
    )
    return record, secret


def _credential_id_from_secret(secret: str, role: str) -> str | None:
    prefix = "opi1" if role == "issuance" else "opv1"
    parts = secret.split(".")
    if len(parts) != 3 or parts[0] != prefix or not parts[1] or not parts[2]:
        return None
    expected_id_prefix = "ic_" if role == "issuance" else "vc_"
    return parts[1] if parts[1].startswith(expected_id_prefix) else None


def _proof_kid(proof: str) -> str | None:
    parts = proof.split(".")
    if len(parts) != 3 or parts[0] != "op1" or not parts[2]:
        return None
    return parts[1] if parts[1].startswith("hk_") else None


def _text(value: object, field: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"invalid_{field}")
    if any(ord(character) < 32 for character in value):
        raise ValueError(f"invalid_{field}")
    return value


def _purpose(value: object) -> str:
    if not isinstance(value, str) or _PURPOSE_PATTERN.fullmatch(value) is None:
        raise ValueError("invalid_purpose")
    return value


def _audience(value: object) -> str:
    audience = _text(value, "audience", _MAX_AUDIENCE_LENGTH)
    if _AUDIENCE_PATTERN.fullmatch(audience) is None:
        raise ValueError("invalid_audience")
    return audience


def _idempotency_key(value: object | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or _IDEMPOTENCY_PATTERN.fullmatch(value) is None:
        raise ValueError("invalid_idempotency_key")
    return value


def _request_fingerprint(
    *,
    proof: str,
    subject: str,
    purpose: str,
    audience: str,
) -> str:
    payload = {
        "proof_sha256": hashlib.sha256(proof.encode("utf-8")).hexdigest(),
        "subject": subject,
        "purpose": purpose,
        "audience": audience,
    }
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class OnceproofService:
    """Issue opaque proofs and consume each accepted proof at most once."""

    def __init__(
        self,
        *,
        database_path: str | Path,
        keyring: KeyRing,
        clock: Callable[[], int] = _now,
    ) -> None:
        self.store = Store(database_path)
        self.keyring = keyring
        self.clock = clock
        self._key_lock = threading.RLock()
        self._maintenance_lock = threading.Lock()
        self._next_cleanup_at = self.clock() + _CLEANUP_INTERVAL_SECONDS

    def create_client(
        self,
        *,
        name: str,
        allowed_audiences: tuple[str, ...],
        proof_ttl_seconds: int = 120,
        issue_limit_per_minute: int = 120,
        verify_limit_per_minute: int = 600,
        credential_sink: Callable[[ClientCredentials], None] | None = None,
    ) -> ClientCredentials:
        client_name = _text(name, "name", _MAX_NAME_LENGTH)
        if not isinstance(allowed_audiences, tuple) or not allowed_audiences:
            raise ValueError("invalid_allowed_audiences")
        audiences = tuple(dict.fromkeys(_audience(value) for value in allowed_audiences))
        if isinstance(proof_ttl_seconds, bool) or not isinstance(proof_ttl_seconds, int):
            raise ValueError("invalid_proof_ttl_seconds")
        if not 1 <= proof_ttl_seconds <= _MAX_TTL_SECONDS:
            raise ValueError("invalid_proof_ttl_seconds")
        for field, value in (
            ("issue_limit_per_minute", issue_limit_per_minute),
            ("verify_limit_per_minute", verify_limit_per_minute),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"invalid_{field}")
            if not 1 <= value <= _MAX_RATE_LIMIT_PER_MINUTE:
                raise ValueError(f"invalid_{field}")

        with self._key_lock:
            with self.keyring.stable():
                client_id = f"opc_{secrets.token_hex(12)}"
                issuance, issuance_secret = _new_credential("issuance", client_id, self.keyring)
                verification, verification_secret = _new_credential("verification", client_id, self.keyring)
                credentials = ClientCredentials(
                    client_id=client_id,
                    issuance_credential_id=issuance.credential_id,
                    issuance_secret=issuance_secret,
                    verification_credential_id=verification.credential_id,
                    verification_secret=verification_secret,
                )
                if credential_sink is not None:
                    credential_sink(credentials)
                _, root_key = self.keyring.current_key()
                self.store.create_client(
                    client_id=client_id,
                    name=client_name,
                    allowed_audiences=audiences,
                    proof_ttl_seconds=proof_ttl_seconds,
                    issue_limit_per_minute=issue_limit_per_minute,
                    verify_limit_per_minute=verify_limit_per_minute,
                    issuance_credential=issuance,
                    verification_credential=verification,
                    hash_key_check=key_check(root_key),
                    now=self.clock(),
                )
        return credentials

    def issue_proof(
        self,
        *,
        issuance_secret: str,
        subject: str,
        purpose: str,
        audience: str,
        ttl_seconds: int | None = None,
    ) -> IssuedProof:
        accepted_subject = _text(subject, "subject", _MAX_SUBJECT_LENGTH)
        accepted_purpose = _purpose(purpose)
        accepted_audience = _audience(audience)
        now = self.clock()
        self._maybe_cleanup(now)

        with self._key_lock:
            credential = self._authenticate(issuance_secret, "issuance", now)
            if credential is None:
                raise PermissionError("credential_rejected")
            client = self.store.client(credential.client_id)
            if client is None or client.status != "active":
                raise PermissionError("credential_rejected")
            if accepted_audience not in client.allowed_audiences:
                raise ValueError("audience_not_allowed")
            ttl = client.proof_ttl_seconds if ttl_seconds is None else ttl_seconds
            if isinstance(ttl, bool) or not isinstance(ttl, int) or not 1 <= ttl <= client.proof_ttl_seconds:
                raise ValueError("invalid_ttl_seconds")

            kid, key = self.keyring.current_key()
            proof = f"op1.{kid}.{secrets.token_urlsafe(32)}"
            token_digest = proof_digest(key, proof)
            proof_tag = f"pf_{token_digest[:24]}"
            record = ProofRecord(
                token_digest=token_digest,
                proof_tag=proof_tag,
                hash_kid=kid,
                client_id=credential.client_id,
                issue_credential_id=credential.credential_id,
                subject=accepted_subject,
                purpose=accepted_purpose,
                audience=accepted_audience,
                issued_at=now,
                expires_at=now + ttl,
                consumed_at=None,
            )
            committed = self.store.issue_proof(
                record,
                hash_key_check=key_check(key),
                clock=self.clock,
            )

        receipt = ProofReceipt(
            state="issued",
            proof_tag=proof_tag,
            client_id=credential.client_id,
            subject=accepted_subject,
            purpose=accepted_purpose,
            audience=accepted_audience,
            issued_at=committed.issued_at,
            expires_at=committed.expires_at,
        )
        return IssuedProof(proof=proof, receipt=receipt)

    def verify_proof(
        self,
        *,
        verification_secret: str,
        proof: str,
        purpose: str,
        audience: str,
        subject: str,
        idempotency_key: str | None = None,
    ) -> VerificationResult:
        accepted_proof = _text(proof, "proof", 512)
        accepted_subject = _text(subject, "subject", _MAX_SUBJECT_LENGTH)
        accepted_purpose = _purpose(purpose)
        accepted_audience = _audience(audience)
        accepted_idempotency_key = _idempotency_key(idempotency_key)
        now = self.clock()
        self._maybe_cleanup(now)

        credential = self._authenticate(verification_secret, "verification", now)
        if credential is None:
            return VerificationResult(
                verified=False,
                reason="credential_rejected",
                witness=VerificationWitness(
                    state="rejected",
                    verification_id=f"vr_{secrets.token_hex(16)}",
                    proof_tag=None,
                    client_id=None,
                    decided_at=now,
                    reason="credential_rejected",
                ),
            )

        kid = _proof_kid(accepted_proof)
        key = self.keyring.key_for(kid) if kid is not None else None
        token_digest = proof_digest(key, accepted_proof) if key is not None else hashlib.sha256(
            accepted_proof.encode("utf-8")
        ).hexdigest()
        fingerprint = _request_fingerprint(
            proof=accepted_proof,
            subject=accepted_subject,
            purpose=accepted_purpose,
            audience=accepted_audience,
        )
        cached = self.store.cached_verification(
            credential_id=credential.credential_id,
            client_id=credential.client_id,
            idempotency_key=accepted_idempotency_key,
            request_fingerprint=fingerprint,
            clock=self.clock,
        )
        if cached is not None:
            return cached
        return self.store.consume_proof(
            credential_id=credential.credential_id,
            client_id=credential.client_id,
            token_digest=token_digest,
            subject=accepted_subject,
            purpose=accepted_purpose,
            audience=accepted_audience,
            request_fingerprint=fingerprint,
            idempotency_key=accepted_idempotency_key,
            clock=self.clock,
        )

    def rotate_credential(
        self,
        *,
        client_id: str,
        role: str,
        grace_seconds: int = 300,
        credential_sink: Callable[[PreparedCredential], None] | None = None,
    ) -> RotatedCredential:
        if role not in ("issuance", "verification"):
            raise ValueError("invalid_role")
        if isinstance(grace_seconds, bool) or not isinstance(grace_seconds, int):
            raise ValueError("invalid_grace_seconds")
        if not 0 <= grace_seconds <= _MAX_ROTATION_GRACE_SECONDS:
            raise ValueError("invalid_grace_seconds")
        accepted_client_id = _text(client_id, "client_id", 128)
        now = self.clock()

        with self._key_lock:
            with self.keyring.stable():
                replacement, secret = _new_credential(role, accepted_client_id, self.keyring)
                prepared = PreparedCredential(
                    client_id=accepted_client_id,
                    credential_id=replacement.credential_id,
                    role=role,
                    secret=secret,
                )
                if credential_sink is not None:
                    credential_sink(prepared)
                _, root_key = self.keyring.current_key()
                previous_id, valid_until = self.store.rotate_credential(
                    client_id=accepted_client_id,
                    role=role,
                    replacement=replacement,
                    hash_key_check=key_check(root_key),
                    grace_seconds=grace_seconds,
                    now=now,
                )
        return RotatedCredential(
            client_id=accepted_client_id,
            credential_id=replacement.credential_id,
            role=role,
            secret=secret,
            previous_credential_id=previous_id,
            previous_valid_until=valid_until,
        )

    def revoke_client(self, client_id: str) -> bool:
        accepted_client_id = _text(client_id, "client_id", 128)
        return self.store.revoke_client(accepted_client_id, now=self.clock())

    def cleanup(self, now: int | None = None) -> dict[str, int]:
        cleanup_at = self.clock() if now is None else now
        if isinstance(cleanup_at, bool) or not isinstance(cleanup_at, int):
            raise ValueError("invalid_cleanup_time")
        return self.store.cleanup(cleanup_at)

    def activate_restored_backup(self) -> None:
        self.store.activate_restored_backup(now=self.clock())

    def retire_hash_key(self, kid: str) -> None:
        with self._key_lock:
            self.keyring.retire(kid, in_use=self.store.hash_key_is_in_use)

    def ready(self) -> bool:
        if not self.store.ready() or self.keyring.key_for(self.keyring.current_kid) is None:
            return False
        try:
            checks = self.store.referenced_hash_key_checks()
        except StoreCorruptionError:
            return False
        for kid, expected in checks.items():
            key = self.keyring.key_for(kid)
            if key is None or not hmac.compare_digest(key_check(key), expected):
                return False
        return True

    def credential_is_accepted(self, secret: object, role: str) -> bool:
        if role not in ("issuance", "verification"):
            return False
        return self._authenticate(secret, role, self.clock()) is not None

    def _authenticate(self, secret: object, role: str, now: int) -> CredentialRecord | None:
        if not isinstance(secret, str):
            return None
        credential_id = _credential_id_from_secret(secret, role)
        if credential_id is None:
            return None
        record = self.store.credential(credential_id)
        if record is None or record.role != role:
            return None
        key = self.keyring.key_for(record.hash_kid)
        if key is None or not hmac.compare_digest(record.secret_digest, credential_digest(key, secret)):
            return None
        if record.status == "current":
            return record
        if record.status == "previous" and record.valid_until is not None and now < record.valid_until:
            return record
        return None

    def _maybe_cleanup(self, now: int) -> None:
        if now < self._next_cleanup_at or not self._maintenance_lock.acquire(blocking=False):
            return
        try:
            if now >= self._next_cleanup_at:
                self.store.cleanup(now)
                self._next_cleanup_at = now + _CLEANUP_INTERVAL_SECONDS
        finally:
            self._maintenance_lock.release()


__all__ = ["OnceproofService"]
