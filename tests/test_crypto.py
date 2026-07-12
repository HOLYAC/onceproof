"""Cryptographic tests pin entropy length and digest-domain separation."""

from __future__ import annotations

import base64
import tempfile
import unittest
from pathlib import Path

from onceproof.crypto import credential_digest, key_check, proof_digest
from onceproof.keyring import KeyRing
from onceproof.service import OnceproofService
from onceproof.store import Store


def _decode_token_part(value: str) -> bytes:
    encoded = value.rsplit(".", 1)[1]
    return base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))


class CryptoTests(unittest.TestCase):
    def test_digest_domains_are_deterministic_and_distinct(self) -> None:
        root = bytes(range(32))

        credential = credential_digest(root, "same-value")
        proof = proof_digest(root, "same-value")

        self.assertEqual(credential, credential_digest(root, "same-value"))
        self.assertEqual(proof, proof_digest(root, "same-value"))
        self.assertNotEqual(credential, proof)
        self.assertNotIn(key_check(root), (credential, proof))

    def test_invalid_root_key_length_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid_root_key_length"):
            proof_digest(b"short", "value")

    def test_every_bearer_value_contains_exactly_32_random_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            Store.create(root / "onceproof.sqlite3")
            service = OnceproofService(
                database_path=root / "onceproof.sqlite3",
                keyring=KeyRing.create(root / "keyring.json"),
            )
            client = service.create_client(
                name="entropy",
                allowed_audiences=("urn:onceproof:entropy",),
            )
            issued = service.issue_proof(
                issuance_secret=client.issuance_secret,
                subject="subject",
                purpose="entropy",
                audience="urn:onceproof:entropy",
            )

        self.assertEqual(32, len(_decode_token_part(client.issuance_secret)))
        self.assertEqual(32, len(_decode_token_part(client.verification_secret)))
        self.assertEqual(32, len(_decode_token_part(issued.proof)))


if __name__ == "__main__":
    unittest.main()
