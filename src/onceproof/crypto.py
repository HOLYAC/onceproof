"""Domain-separated keyed digests keep credential and proof namespaces apart."""

from __future__ import annotations

import hashlib
import hmac

_HKDF_SALT = b"onceproof:v1:hkdf-sha256"
_CREDENTIAL_INFO = b"credential-digest"
_PROOF_INFO = b"proof-digest"
_KEY_CHECK_INFO = b"key-check"
_KEY_CHECK_VALUE = b"onceproof:v1:key-check"


def _hkdf_sha256(root_key: bytes, info: bytes) -> bytes:
    if len(root_key) != 32:
        raise ValueError("invalid_root_key_length")
    extracted = hmac.new(_HKDF_SALT, root_key, hashlib.sha256).digest()
    return hmac.new(extracted, info + b"\x01", hashlib.sha256).digest()


def _digest(derived_key: bytes, value: str) -> str:
    return hmac.new(derived_key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def credential_digest(root_key: bytes, credential: str) -> str:
    return _digest(_hkdf_sha256(root_key, _CREDENTIAL_INFO), credential)


def proof_digest(root_key: bytes, proof: str) -> str:
    return _digest(_hkdf_sha256(root_key, _PROOF_INFO), proof)


def key_check(root_key: bytes) -> str:
    return hmac.new(
        _hkdf_sha256(root_key, _KEY_CHECK_INFO),
        _KEY_CHECK_VALUE,
        hashlib.sha256,
    ).hexdigest()


__all__ = ["credential_digest", "key_check", "proof_digest"]
