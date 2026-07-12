"""HTTP tests prove that the public surface preserves core trust boundaries."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.parse import urlsplit

from onceproof.errors import StoreCorruptionError
from onceproof.http import create_app
from onceproof.keyring import KeyRing
from onceproof.service import OnceproofService
from onceproof.store import Store


class HttpSurfaceTests(unittest.TestCase):
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
            allowed_audiences=("https://api.example.test/checkout",),
        )
        self.app = create_app(
            service=self.service,
            max_request_bytes=2048,
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | bytes | None = None,
        secret: str | None = None,
        headers: dict[str, str] | None = None,
        extra_header_pairs: tuple[tuple[str, str], ...] = (),
    ) -> tuple[int, dict[str, Any], dict[str, str]]:
        encoded: bytes | None
        if isinstance(body, dict):
            encoded = json.dumps(body).encode("utf-8")
        else:
            encoded = body
        request_headers = dict(headers or {})
        if isinstance(body, dict):
            request_headers.setdefault("Content-Type", "application/json")
        if secret is not None:
            request_headers["Authorization"] = f"Bearer {secret}"

        parsed = urlsplit(path)

        async def exchange() -> tuple[int, dict[str, Any], dict[str, str]]:
            messages: list[dict[str, Any]] = []
            request_sent = False

            async def receive() -> dict[str, Any]:
                nonlocal request_sent
                if request_sent:
                    return {"type": "http.disconnect"}
                request_sent = True
                return {
                    "type": "http.request",
                    "body": encoded or b"",
                    "more_body": False,
                }

            async def send(message: dict[str, Any]) -> None:
                messages.append(message)

            scope = {
                "type": "http",
                "http_version": "1.1",
                "method": method,
                "scheme": "http",
                "path": parsed.path,
                "raw_path": parsed.path.encode("ascii"),
                "query_string": parsed.query.encode("ascii"),
                "headers": [
                    (key.lower().encode("ascii"), value.encode("ascii"))
                    for key, value in request_headers.items()
                ]
                + [
                    (key.lower().encode("ascii"), value.encode("ascii"))
                    for key, value in extra_header_pairs
                ],
            }
            await self.app(scope, receive, send)
            start = next(message for message in messages if message["type"] == "http.response.start")
            raw = b"".join(
                message.get("body", b"")
                for message in messages
                if message["type"] == "http.response.body"
            )
            response_headers = {
                key.decode("ascii").lower(): value.decode("ascii")
                for key, value in start["headers"]
            }
            return int(start["status"]), json.loads(raw) if raw else {}, response_headers

        return asyncio.run(exchange())

    def issue(self) -> tuple[int, dict[str, Any], dict[str, str]]:
        return self.request(
            "POST",
            "/v1/proofs",
            secret=self.client.issuance_secret,
            body={
                "subject": "user_123",
                "purpose": "checkout",
                "audience": "https://api.example.test/checkout",
            },
        )

    def test_issue_verify_and_replay_over_http(self) -> None:
        issue_status, issued, issue_headers = self.issue()

        verify_status, verified, verify_headers = self.request(
            "POST",
            "/v1/verifications",
            secret=self.client.verification_secret,
            body={
                "proof": issued["proof"],
                "subject": "user_123",
                "purpose": "checkout",
                "audience": "https://api.example.test/checkout",
            },
        )
        replay_status, replay, _ = self.request(
            "POST",
            "/v1/verifications",
            secret=self.client.verification_secret,
            body={
                "proof": issued["proof"],
                "subject": "user_123",
                "purpose": "checkout",
                "audience": "https://api.example.test/checkout",
            },
        )

        self.assertEqual(201, issue_status)
        self.assertEqual("issued", issued["receipt"]["state"])
        self.assertEqual("no-store", issue_headers["cache-control"])
        self.assertEqual(200, verify_status)
        self.assertTrue(verified["verified"])
        self.assertEqual("verified_once", verified["witness"]["state"])
        self.assertEqual("nosniff", verify_headers["x-content-type-options"])
        self.assertEqual(200, replay_status)
        self.assertFalse(replay["verified"])
        self.assertEqual("replay_rejected", replay["witness"]["state"])

    def test_issuer_and_verifier_credentials_are_not_interchangeable(self) -> None:
        issue_with_verifier, body, _ = self.request(
            "POST",
            "/v1/proofs",
            secret=self.client.verification_secret,
            body={
                "subject": "user_123",
                "purpose": "checkout",
                "audience": "https://api.example.test/checkout",
            },
        )

        self.assertEqual(401, issue_with_verifier)
        self.assertEqual({"error": "credential_rejected"}, body)

    def test_verification_requires_an_authenticated_verifier(self) -> None:
        _, issued, _ = self.issue()

        status, body, headers = self.request(
            "POST",
            "/v1/verifications",
            secret="opv1.vc_unknown.not-a-secret",
            body={
                "proof": issued["proof"],
                "subject": "user_123",
                "purpose": "checkout",
                "audience": "https://api.example.test/checkout",
            },
        )

        self.assertEqual(401, status)
        self.assertEqual({"error": "credential_rejected"}, body)
        self.assertEqual('Bearer realm="onceproof"', headers["www-authenticate"])

    def test_authentication_precedes_body_parsing_and_bearer_scheme_is_case_insensitive(self) -> None:
        rejected_status, rejected, rejected_headers = self.request(
            "POST",
            "/v1/proofs",
            secret="opi1.ic_unknown.not-a-secret",
            body=b"{",
            headers={"Content-Type": "application/json"},
        )
        accepted_status, _, _ = self.request(
            "POST",
            "/v1/proofs",
            headers={
                "Authorization": f"bEaReR {self.client.issuance_secret}",
                "Content-Type": "application/json",
            },
            body={
                "subject": "subject",
                "purpose": "checkout",
                "audience": "https://api.example.test/checkout",
            },
        )

        self.assertEqual((401, "credential_rejected"), (rejected_status, rejected["error"]))
        self.assertEqual('Bearer realm="onceproof"', rejected_headers["www-authenticate"])
        self.assertEqual(201, accepted_status)

        tab_status, _, _ = self.request(
            "POST",
            "/v1/proofs",
            headers={
                "Authorization": f"Bearer\t{self.client.issuance_secret}",
                "Content-Type": "application/json",
            },
            body={
                "subject": "subject",
                "purpose": "checkout",
                "audience": "https://api.example.test/checkout",
            },
        )
        spaces_status, _, _ = self.request(
            "POST",
            "/v1/proofs",
            headers={
                "Authorization": f"Bearer   {self.client.issuance_secret}",
                "Content-Type": "application/json",
            },
            body={
                "subject": "subject",
                "purpose": "checkout",
                "audience": "https://api.example.test/checkout",
            },
        )
        self.assertEqual(401, tab_status)
        self.assertEqual(201, spaces_status)

    def test_ttl_json_integer_semantics_and_client_policy_are_explicit(self) -> None:
        request = {
            "subject": "subject",
            "purpose": "checkout",
            "audience": "https://api.example.test/checkout",
        }
        null_status, null, _ = self.request(
            "POST",
            "/v1/proofs",
            secret=self.client.issuance_secret,
            body={**request, "ttl_seconds": None},
        )
        integral_status, integral, _ = self.request(
            "POST",
            "/v1/proofs",
            secret=self.client.issuance_secret,
            body={**request, "ttl_seconds": 1.0},
        )
        policy_status, policy, _ = self.request(
            "POST",
            "/v1/proofs",
            secret=self.client.issuance_secret,
            body={**request, "ttl_seconds": 121},
        )

        self.assertEqual((400, "invalid_ttl_seconds"), (null_status, null["error"]))
        self.assertEqual(201, integral_status)
        self.assertEqual(1, integral["receipt"]["expires_at"] - integral["receipt"]["issued_at"])
        self.assertEqual((400, "invalid_ttl_seconds"), (policy_status, policy["error"]))

    def test_idempotency_header_retries_exactly_and_conflicts_on_new_input(self) -> None:
        _, first_issue, _ = self.issue()
        _, second_issue, _ = self.issue()
        body = {
            "proof": first_issue["proof"],
            "subject": "user_123",
            "purpose": "checkout",
            "audience": "https://api.example.test/checkout",
        }

        first_status, first, _ = self.request(
            "POST",
            "/v1/verifications",
            secret=self.client.verification_secret,
            headers={"Idempotency-Key": "checkout-request-42"},
            body=body,
        )
        retry_status, retry, _ = self.request(
            "POST",
            "/v1/verifications",
            secret=self.client.verification_secret,
            headers={"Idempotency-Key": "checkout-request-42"},
            body=body,
        )
        conflict_status, conflict, _ = self.request(
            "POST",
            "/v1/verifications",
            secret=self.client.verification_secret,
            headers={"Idempotency-Key": "checkout-request-42"},
            body={**body, "proof": second_issue["proof"]},
        )

        self.assertEqual(200, first_status)
        self.assertEqual(200, retry_status)
        self.assertEqual(first, retry)
        self.assertEqual(409, conflict_status)
        self.assertEqual({"error": "idempotency_conflict"}, conflict)

    def test_unknown_json_fields_are_rejected(self) -> None:
        status, body, _ = self.request(
            "POST",
            "/v1/proofs",
            secret=self.client.issuance_secret,
            body={
                "subject": "user_123",
                "purpose": "checkout",
                "audience": "https://api.example.test/checkout",
                "sitekey": "not-our-protocol",
            },
        )

        self.assertEqual(400, status)
        self.assertEqual("unknown_fields", body["error"])

    def test_wrong_content_type_and_oversized_body_are_rejected(self) -> None:
        wrong_type, _, _ = self.request(
            "POST",
            "/v1/proofs",
            secret=self.client.issuance_secret,
            body=b"{}",
            headers={"Content-Type": "text/plain"},
        )
        oversized, body, _ = self.request(
            "POST",
            "/v1/proofs",
            secret=self.client.issuance_secret,
            body=b"{" + b" " * 3000 + b"}",
            headers={"Content-Type": "application/json"},
        )

        self.assertEqual(415, wrong_type)
        self.assertEqual(413, oversized)
        self.assertEqual("request_too_large", body["error"])

    def test_unlisted_audience_is_forbidden(self) -> None:
        status, body, _ = self.request(
            "POST",
            "/v1/proofs",
            secret=self.client.issuance_secret,
            body={
                "subject": "user_123",
                "purpose": "checkout",
                "audience": "https://attacker.example/",
            },
        )

        self.assertEqual(403, status)
        self.assertEqual("audience_not_allowed", body["error"])

    def test_durable_quota_returns_retry_after(self) -> None:
        limited = self.service.create_client(
            name="limited",
            allowed_audiences=("urn:onceproof:http-limit",),
            issue_limit_per_minute=1,
        )
        request = {
            "subject": "subject",
            "purpose": "quota",
            "audience": "urn:onceproof:http-limit",
        }
        first_status, _, _ = self.request(
            "POST",
            "/v1/proofs",
            secret=limited.issuance_secret,
            body=request,
        )
        blocked_status, blocked, headers = self.request(
            "POST",
            "/v1/proofs",
            secret=limited.issuance_secret,
            body=request,
        )

        self.assertEqual(201, first_status)
        self.assertEqual(429, blocked_status)
        self.assertEqual("rate_limited", blocked["error"])
        self.assertEqual(str(blocked["retry_after_seconds"]), headers["retry-after"])

    def test_health_and_readiness_are_distinct(self) -> None:
        health_status, health, _ = self.request("GET", "/healthz")
        ready_status, ready, _ = self.request("GET", "/readyz")

        self.assertEqual(200, health_status)
        self.assertEqual({"status": "ok"}, health)
        self.assertEqual(200, ready_status)
        self.assertEqual({"status": "ready"}, ready)

    def test_query_strings_are_rejected_to_keep_proofs_out_of_access_urls(self) -> None:
        status, body, _ = self.request("GET", "/healthz?proof=leak")

        self.assertEqual(400, status)
        self.assertEqual("query_not_allowed", body["error"])

    def test_malformed_empty_non_object_and_missing_json_are_rejected(self) -> None:
        cases = (
            (b"{", "invalid_json"),
            (b"", "empty_request"),
            (b"[]", "json_object_required"),
            (b'{"subject":"only"}', "missing_fields"),
        )

        for raw, expected in cases:
            status, body, _ = self.request(
                "POST",
                "/v1/proofs",
                secret=self.client.issuance_secret,
                body=raw,
                headers={"Content-Type": "application/json"},
            )
            with self.subTest(expected=expected):
                self.assertEqual(400, status)
                self.assertEqual(expected, body["error"])

        duplicate_status, duplicate, _ = self.request(
            "POST",
            "/v1/proofs",
            secret=self.client.issuance_secret,
            body=(
                b'{"subject":"one","subject":"two","purpose":"checkout",'
                b'"audience":"https://api.example.test/checkout"}'
            ),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(400, duplicate_status)
        self.assertEqual("duplicate_json_field", duplicate["error"])

    def test_duplicate_authorization_and_idempotency_headers_are_rejected(self) -> None:
        duplicate_auth, _, _ = self.request(
            "POST",
            "/v1/proofs",
            secret=self.client.issuance_secret,
            extra_header_pairs=(("Authorization", f"Bearer {self.client.issuance_secret}"),),
            body={
                "subject": "subject",
                "purpose": "checkout",
                "audience": "https://api.example.test/checkout",
            },
        )
        _, issued, _ = self.issue()
        duplicate_idempotency, body, _ = self.request(
            "POST",
            "/v1/verifications",
            secret=self.client.verification_secret,
            headers={"Idempotency-Key": "one"},
            extra_header_pairs=(("Idempotency-Key", "two"),),
            body={
                "proof": issued["proof"],
                "subject": "user_123",
                "purpose": "checkout",
                "audience": "https://api.example.test/checkout",
            },
        )

        self.assertEqual(401, duplicate_auth)
        self.assertEqual(400, duplicate_idempotency)
        self.assertEqual("duplicate_idempotency_key", body["error"])

    def test_known_wrong_method_unknown_path_and_store_failure_have_stable_errors(self) -> None:
        method_status, method, method_headers = self.request("PUT", "/v1/proofs")
        missing_status, missing, _ = self.request("GET", "/missing")
        with patch.object(self.service, "issue_proof", side_effect=sqlite3.OperationalError("closed")):
            store_status, store, _ = self.request(
                "POST",
                "/v1/proofs",
                secret=self.client.issuance_secret,
                body={
                    "subject": "subject",
                    "purpose": "checkout",
                    "audience": "https://api.example.test/checkout",
                },
            )
        with patch.object(self.service, "issue_proof", side_effect=RuntimeError("fault")):
            internal_status, internal, _ = self.request(
                "POST",
                "/v1/proofs",
                secret=self.client.issuance_secret,
                body={
                    "subject": "subject",
                    "purpose": "checkout",
                    "audience": "https://api.example.test/checkout",
                },
            )

        self.assertEqual((405, "method_not_allowed"), (method_status, method["error"]))
        self.assertEqual("POST", method_headers["allow"])
        self.assertEqual((404, "not_found"), (missing_status, missing["error"]))
        self.assertEqual((503, "store_unavailable"), (store_status, store["error"]))
        self.assertEqual((500, "internal_error"), (internal_status, internal["error"]))

    def test_persisted_store_corruption_is_not_reported_as_client_input(self) -> None:
        with patch.object(
            self.service,
            "verify_proof",
            side_effect=StoreCorruptionError(),
        ):
            status, body, _ = self.request(
                "POST",
                "/v1/verifications",
                secret=self.client.verification_secret,
                body={
                    "proof": "op1.hk_missing.opaque",
                    "subject": "subject",
                    "purpose": "checkout",
                    "audience": "https://api.example.test/checkout",
                },
            )

        self.assertEqual((503, "store_unavailable"), (status, body["error"]))

    def test_readiness_reports_unavailable_without_claiming_liveness_failed(self) -> None:
        with patch.object(self.service, "ready", return_value=False):
            ready_status, ready, _ = self.request("GET", "/readyz")
        health_status, health, _ = self.request("GET", "/healthz")

        self.assertEqual((503, "unavailable"), (ready_status, ready["status"]))
        self.assertEqual((200, "ok"), (health_status, health["status"]))
        for error in (sqlite3.OperationalError("closed"), RuntimeError("fault")):
            with self.subTest(error=type(error).__name__), patch.object(
                self.service,
                "ready",
                side_effect=error,
            ):
                status, body, _ = self.request("GET", "/readyz")
                self.assertEqual((503, "unavailable"), (status, body["status"]))

    def test_api_overload_is_a_contracted_json_failure_without_hiding_health(self) -> None:
        self.app._active_api_requests = 64
        api_status, api, _ = self.issue()
        health_status, health, _ = self.request("GET", "/healthz")

        self.assertEqual((503, "server_busy"), (api_status, api["error"]))
        self.assertEqual((200, "ok"), (health_status, health["status"]))

    def test_incomplete_body_times_out_and_releases_its_api_slot(self) -> None:
        async def exchange() -> tuple[int, dict[str, Any]]:
            messages: list[dict[str, Any]] = []
            first = True

            async def receive() -> dict[str, Any]:
                nonlocal first
                if first:
                    first = False
                    return {"type": "http.request", "body": b"{", "more_body": True}
                await asyncio.sleep(1)
                return {"type": "http.disconnect"}

            async def send(message: dict[str, Any]) -> None:
                messages.append(message)

            await self.app(
                {
                    "type": "http",
                    "http_version": "1.1",
                    "method": "POST",
                    "scheme": "http",
                    "path": "/v1/proofs",
                    "raw_path": b"/v1/proofs",
                    "query_string": b"",
                    "headers": [
                        (b"authorization", f"Bearer {self.client.issuance_secret}".encode("ascii")),
                        (b"content-type", b"application/json"),
                    ],
                },
                receive,
                send,
            )
            start = next(message for message in messages if message["type"] == "http.response.start")
            raw = next(message["body"] for message in messages if message["type"] == "http.response.body")
            return int(start["status"]), json.loads(raw)

        with patch("onceproof.http._REQUEST_BODY_TIMEOUT_SECONDS", 0.001):
            status, body = asyncio.run(exchange())

        self.assertEqual((408, "request_timeout"), (status, body["error"]))
        self.assertEqual(0, self.app._active_api_requests)

    def test_asgi_lifespan_checks_readiness_and_completes_shutdown(self) -> None:
        async def run_lifespan(ready: bool | Exception) -> list[str]:
            incoming = [{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}]
            outgoing: list[str] = []

            async def receive() -> dict[str, Any]:
                return incoming.pop(0)

            async def send(message: dict[str, Any]) -> None:
                outgoing.append(str(message["type"]))

            patcher = (
                patch.object(self.service, "ready", side_effect=ready)
                if isinstance(ready, Exception)
                else patch.object(self.service, "ready", return_value=ready)
            )
            with patcher:
                await self.app({"type": "lifespan"}, receive, send)
            return outgoing

        self.assertEqual(
            ["lifespan.startup.complete", "lifespan.shutdown.complete"],
            asyncio.run(run_lifespan(True)),
        )
        self.assertEqual(
            ["lifespan.startup.failed"],
            asyncio.run(run_lifespan(False)),
        )
        self.assertEqual(
            ["lifespan.startup.failed"],
            asyncio.run(run_lifespan(sqlite3.OperationalError("closed"))),
        )


if __name__ == "__main__":
    unittest.main()
