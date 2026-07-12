"""Typed records keep proof issuance distinct from verifier acceptance."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

_CLAIM_FIELDS = frozenset({"client_id", "subject", "purpose", "audience", "issued_at", "expires_at"})
_WITNESS_FIELDS = frozenset(
    {"state", "verification_id", "proof_tag", "client_id", "decided_at", "reason"}
)
_RESULT_FIELDS = frozenset({"verified", "reason", "witness", "claims"})
_REJECTION_REASONS = frozenset(
    {"credential_rejected", "invalid", "expired", "already_consumed", "binding_mismatch"}
)


def _persisted_object(value: object, fields: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("invalid_persisted_verification")
    return value


def _persisted_text(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("invalid_persisted_verification")
    return value


def _persisted_time(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("invalid_persisted_verification")
    return value


@dataclass(frozen=True)
class ClientCredentials:
    """Return newly generated credentials exactly once to the local operator."""

    client_id: str
    issuance_credential_id: str
    issuance_secret: str
    verification_credential_id: str
    verification_secret: str


@dataclass(frozen=True)
class PreparedCredential:
    """Carry one replacement secret to durable delivery before activation."""

    client_id: str
    credential_id: str
    role: str
    secret: str


@dataclass(frozen=True)
class RotatedCredential:
    """Carry the replacement secret without persisting its raw value."""

    client_id: str
    credential_id: str
    role: str
    secret: str
    previous_credential_id: str
    previous_valid_until: int


@dataclass(frozen=True)
class ProofReceipt:
    """Describe issuer output without claiming that a verifier accepted it."""

    state: str
    proof_tag: str
    client_id: str
    subject: str
    purpose: str
    audience: str
    issued_at: int
    expires_at: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "proof_tag": self.proof_tag,
            "client_id": self.client_id,
            "subject": self.subject,
            "purpose": self.purpose,
            "audience": self.audience,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True)
class IssuedProof:
    """Keep the bearer proof separate from its non-secret receipt."""

    proof: str
    receipt: ProofReceipt

    def to_dict(self) -> dict[str, Any]:
        return {"proof": self.proof, "receipt": self.receipt.to_dict()}


@dataclass(frozen=True)
class ProofClaims:
    """Expose only claims read from an accepted, atomically consumed proof."""

    client_id: str
    subject: str
    purpose: str
    audience: str
    issued_at: int
    expires_at: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "client_id": self.client_id,
            "subject": self.subject,
            "purpose": self.purpose,
            "audience": self.audience,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_dict(cls, value: object) -> ProofClaims:
        record = _persisted_object(value, _CLAIM_FIELDS)
        issued_at = _persisted_time(record["issued_at"])
        expires_at = _persisted_time(record["expires_at"])
        if expires_at <= issued_at:
            raise ValueError("invalid_persisted_verification")
        return cls(
            client_id=_persisted_text(record["client_id"]),
            subject=_persisted_text(record["subject"]),
            purpose=_persisted_text(record["purpose"]),
            audience=_persisted_text(record["audience"]),
            issued_at=issued_at,
            expires_at=expires_at,
        )


@dataclass(frozen=True)
class VerificationWitness:
    """Name the exact boundary state reached by one verification attempt."""

    state: str
    verification_id: str
    proof_tag: str | None
    client_id: str | None
    decided_at: int
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "verification_id": self.verification_id,
            "proof_tag": self.proof_tag,
            "client_id": self.client_id,
            "decided_at": self.decided_at,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, value: object) -> VerificationWitness:
        record = _persisted_object(value, _WITNESS_FIELDS)
        proof_tag = record["proof_tag"]
        client_id = record["client_id"]
        reason = record["reason"]
        if proof_tag is not None and (not isinstance(proof_tag, str) or not proof_tag):
            raise ValueError("invalid_persisted_verification")
        if client_id is not None and (not isinstance(client_id, str) or not client_id):
            raise ValueError("invalid_persisted_verification")
        if reason is not None and reason not in _REJECTION_REASONS:
            raise ValueError("invalid_persisted_verification")
        return cls(
            state=_persisted_text(record["state"]),
            verification_id=_persisted_text(record["verification_id"]),
            proof_tag=proof_tag,
            client_id=client_id,
            decided_at=_persisted_time(record["decided_at"]),
            reason=reason,
        )


@dataclass(frozen=True)
class VerificationResult:
    """Return claims only when the verifier boundary was crossed once."""

    verified: bool
    reason: str | None
    witness: VerificationWitness
    claims: ProofClaims | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "verified": self.verified,
            "reason": self.reason,
            "witness": self.witness.to_dict(),
            "claims": self.claims.to_dict() if self.claims is not None else None,
        }

    @classmethod
    def from_dict(cls, value: object) -> VerificationResult:
        record = _persisted_object(value, _RESULT_FIELDS)
        verified = record["verified"]
        if not isinstance(verified, bool):
            raise ValueError("invalid_persisted_verification")
        witness = VerificationWitness.from_dict(record["witness"])
        reason = record["reason"]
        claims_value = record["claims"]

        if verified:
            claims = ProofClaims.from_dict(claims_value)
            if (
                reason is not None
                or witness.state != "verified_once"
                or witness.reason is not None
                or witness.proof_tag is None
                or witness.client_id != claims.client_id
            ):
                raise ValueError("invalid_persisted_verification")
            return cls(verified=True, reason=None, witness=witness, claims=claims)

        if reason not in _REJECTION_REASONS or claims_value is not None or witness.reason != reason:
            raise ValueError("invalid_persisted_verification")
        expected_state = "replay_rejected" if reason == "already_consumed" else "rejected"
        if witness.state != expected_state:
            raise ValueError("invalid_persisted_verification")
        return cls(verified=False, reason=reason, witness=witness, claims=None)


__all__ = [
    "ClientCredentials",
    "IssuedProof",
    "PreparedCredential",
    "ProofClaims",
    "ProofReceipt",
    "RotatedCredential",
    "VerificationResult",
    "VerificationWitness",
]
