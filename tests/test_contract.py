"""The published schema is exercised against real service values and false upgrades."""

from __future__ import annotations

import asyncio
import copy
import json
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from onceproof.http import create_app
from onceproof.keyring import KeyRing
from onceproof.service import OnceproofService
from onceproof.store import Store


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        contract_path = files("onceproof").joinpath("openapi.json")
        cls.contract = json.loads(contract_path.read_text(encoding="utf-8"))

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)
        Store.create(root / "onceproof.sqlite3")
        self.service = OnceproofService(
            database_path=root / "onceproof.sqlite3",
            keyring=KeyRing.create(root / "keyring.json"),
        )
        self.client = self.service.create_client(
            name="checkout",
            allowed_audiences=("urn:onceproof:contract",),
        )
        self.app = create_app(service=self.service, max_request_bytes=2048)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def validator(self, schema_name: str) -> Draft202012Validator:
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": f"#/components/schemas/{schema_name}",
            "components": self.contract["components"],
        }
        Draft202012Validator.check_schema(schema)
        return Draft202012Validator(schema)

    def request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | bytes | None = None,
        secret: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, Any], dict[str, str]]:
        encoded = json.dumps(body).encode("utf-8") if isinstance(body, dict) else body or b""
        request_headers = dict(headers or {})
        if isinstance(body, dict):
            request_headers.setdefault("Content-Type", "application/json")
        if secret is not None:
            request_headers["Authorization"] = f"Bearer {secret}"
        parsed = urlsplit(path)

        async def exchange() -> tuple[int, dict[str, Any], dict[str, str]]:
            messages: list[dict[str, Any]] = []
            sent = False

            async def receive() -> dict[str, Any]:
                nonlocal sent
                if sent:
                    return {"type": "http.disconnect"}
                sent = True
                return {"type": "http.request", "body": encoded, "more_body": False}

            async def send(message: dict[str, Any]) -> None:
                messages.append(message)

            await self.app(
                {
                    "type": "http",
                    "http_version": "1.1",
                    "method": method,
                    "scheme": "http",
                    "path": parsed.path,
                    "raw_path": parsed.path.encode("ascii"),
                    "query_string": parsed.query.encode("ascii"),
                    "headers": [
                        (name.lower().encode("ascii"), value.encode("ascii"))
                        for name, value in request_headers.items()
                    ],
                },
                receive,
                send,
            )
            start = next(message for message in messages if message["type"] == "http.response.start")
            raw = b"".join(
                message.get("body", b"")
                for message in messages
                if message["type"] == "http.response.body"
            )
            response_headers = {
                name.decode("ascii").lower(): value.decode("ascii")
                for name, value in start["headers"]
            }
            return int(start["status"]), json.loads(raw), response_headers

        return asyncio.run(exchange())

    def validate_http_response(
        self,
        path: str,
        method: str,
        status: int,
        body: dict[str, Any],
        headers: dict[str, str],
    ) -> None:
        operation = self.contract["paths"][path][method.lower()]
        response = operation["responses"][str(status)]
        if "$ref" in response:
            response = self.contract["components"]["responses"][response["$ref"].rsplit("/", 1)[1]]
        schema = response["content"]["application/json"]["schema"]
        name = schema["$ref"].rsplit("/", 1)[1]
        self.validator(name).validate(body)
        for header_name, header_spec in response.get("headers", {}).items():
            actual = headers[header_name.lower()]
            header_schema = header_spec["schema"]
            value: object = int(actual) if header_schema.get("type") == "integer" else actual
            Draft202012Validator(header_schema).validate(value)

    def issue(self):
        return self.service.issue_proof(
            issuance_secret=self.client.issuance_secret,
            subject="user_123",
            purpose="checkout",
            audience="urn:onceproof:contract",
        )

    def verify(self, proof: str):
        return self.service.verify_proof(
            verification_secret=self.client.verification_secret,
            proof=proof,
            subject="user_123",
            purpose="checkout",
            audience="urn:onceproof:contract",
        )

    def test_real_issue_success_and_replay_match_the_published_contract(self) -> None:
        issue_status, issued, issue_headers = self.request(
            "POST",
            "/v1/proofs",
            secret=self.client.issuance_secret,
            body={
                "subject": "user_123",
                "purpose": "checkout",
                "audience": "urn:onceproof:contract",
            },
        )
        request = {
            "proof": issued["proof"],
            "subject": "user_123",
            "purpose": "checkout",
            "audience": "urn:onceproof:contract",
        }
        accepted_status, accepted, accepted_headers = self.request(
            "POST",
            "/v1/verifications",
            secret=self.client.verification_secret,
            body=request,
        )
        replay_status, replay, replay_headers = self.request(
            "POST",
            "/v1/verifications",
            secret=self.client.verification_secret,
            body=request,
        )

        self.validate_http_response("/v1/proofs", "post", issue_status, issued, issue_headers)
        self.validate_http_response(
            "/v1/verifications", "post", accepted_status, accepted, accepted_headers
        )
        self.validate_http_response(
            "/v1/verifications", "post", replay_status, replay, replay_headers
        )

    def test_http_response_matrix_and_security_headers_match_openapi(self) -> None:
        expected = {
            "/v1/proofs": {"201", "400", "401", "403", "408", "413", "415", "429", "500", "503"},
            "/v1/verifications": {"200", "400", "401", "408", "409", "413", "415", "429", "500", "503"},
        }
        for path, statuses in expected.items():
            with self.subTest(path=path):
                self.assertEqual(statuses, set(self.contract["paths"][path]["post"]["responses"]))

        status, body, headers = self.request(
            "POST",
            "/v1/proofs",
            secret="opi1.ic_unknown.not-a-secret",
            body=b"{",
            headers={"Content-Type": "application/json"},
        )
        self.validate_http_response("/v1/proofs", "post", status, body, headers)
        self.assertEqual(401, status)

        self.assertEqual(
            {"200", "400"},
            set(self.contract["paths"]["/healthz"]["get"]["responses"]),
        )
        self.assertEqual(
            {"200", "400", "503"},
            set(self.contract["paths"]["/readyz"]["get"]["responses"]),
        )

    def test_receipt_cannot_claim_verifier_acceptance(self) -> None:
        issued = self.issue().to_dict()
        issued["receipt"]["state"] = "verified_once"

        with self.assertRaises(ValidationError):
            self.validator("IssueResponse").validate(issued)

    def test_rejected_result_cannot_carry_claims_or_an_accepted_witness(self) -> None:
        issued = self.issue()
        rejected = self.service.verify_proof(
            verification_secret=self.client.verification_secret,
            proof=issued.proof,
            subject="user_123",
            purpose="different",
            audience="urn:onceproof:contract",
        ).to_dict()
        forged = copy.deepcopy(rejected)
        forged["verified"] = True
        forged["reason"] = None
        forged["witness"]["state"] = "verified_once"

        self.validator("VerificationResponse").validate(rejected)
        with self.assertRaises(ValidationError):
            self.validator("VerificationResponse").validate(forged)

    def test_replay_state_is_reserved_for_an_already_consumed_proof(self) -> None:
        issued = self.issue()
        self.verify(issued.proof)
        replay = self.verify(issued.proof).to_dict()
        replay["reason"] = "invalid"
        replay["witness"]["reason"] = "invalid"

        with self.assertRaises(ValidationError):
            self.validator("VerificationResponse").validate(replay)

    def test_contract_has_only_the_independent_onceproof_surface(self) -> None:
        self.assertEqual(
            {"/healthz", "/readyz", "/v1/proofs", "/v1/verifications"},
            set(self.contract["paths"]),
        )
        serialized = json.dumps(self.contract).lower()
        for borrowed_term in ("siteverify", "sitekey", "hcaptcha"):
            self.assertNotIn(borrowed_term, serialized)

    def test_unknown_request_fields_are_schema_errors(self) -> None:
        request: dict[str, Any] = {
            "subject": "user_123",
            "purpose": "checkout",
            "audience": "urn:onceproof:contract",
            "unknown": True,
        }

        with self.assertRaises(ValidationError):
            self.validator("IssueRequest").validate(request)

    def test_request_patterns_reject_trailing_controls_like_runtime(self) -> None:
        for schema_name, value in (
            ("Subject", "subject\n"),
            ("Purpose", "purpose\n"),
            ("Audience", "urn:onceproof:test\n"),
            ("Audience", "urn:onceproof:\x00test"),
        ):
            with self.subTest(schema=schema_name, value=repr(value)), self.assertRaises(
                ValidationError
            ):
                self.validator(schema_name).validate(value)


if __name__ == "__main__":
    unittest.main()
