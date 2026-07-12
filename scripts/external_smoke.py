"""Probe a deployed Onceproof instance without exposing bearer material."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit


def _required_environment(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"missing_environment:{name}")
    return value


def _base_url() -> str:
    value = _required_environment("ONCEPROOF_EXTERNAL_URL").rstrip("/")
    parsed = urlsplit(value)
    loopback_http = (
        parsed.scheme == "http"
        and parsed.hostname in {"127.0.0.1", "::1", "localhost"}
        and os.environ.get("ONCEPROOF_EXTERNAL_ALLOW_HTTP_LOOPBACK") == "1"
    )
    if (
        (parsed.scheme != "https" and not loopback_http)
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError("invalid_external_url")
    return value


def _request(
    url: str,
    *,
    body: Mapping[str, Any] | None = None,
    secret: str | None = None,
    idempotency_key: str | None = None,
) -> tuple[int, dict[str, Any], Mapping[str, str]]:
    headers = {"Accept": "application/json"}
    data = None
    method = "GET"
    if body is not None:
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
        method = "POST"
    if secret is not None:
        headers["Authorization"] = f"Bearer {secret}"
    if idempotency_key is not None:
        headers["Idempotency-Key"] = idempotency_key
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        response = urllib.request.urlopen(request, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read()
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError("external_response_not_json") from error
        if not isinstance(payload, dict):
            raise RuntimeError("external_response_not_object")
        return int(response.status), payload, response.headers


def _require(condition: bool, failure: str) -> None:
    if not condition:
        raise RuntimeError(failure)


def _wait_ready(base_url: str) -> None:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            status, body, _ = _request(f"{base_url}/readyz")
        except (OSError, urllib.error.URLError):
            time.sleep(1)
            continue
        if status == 200 and body == {"status": "ready"}:
            return
        time.sleep(1)
    raise RuntimeError("external_not_ready")


def main() -> int:
    base_url = _base_url()
    issuance_secret = _required_environment("ONCEPROOF_EXTERNAL_ISSUANCE_SECRET")
    verification_secret = _required_environment("ONCEPROOF_EXTERNAL_VERIFICATION_SECRET")
    audience = _required_environment("ONCEPROOF_EXTERNAL_AUDIENCE")
    probe_id = uuid.uuid4().hex
    binding = {
        "subject": f"external-{probe_id}",
        "purpose": "external-smoke",
        "audience": audience,
    }

    _wait_ready(base_url)

    rejected_status, rejected, _ = _request(f"{base_url}/v1/proofs", body=binding)
    _require(
        rejected_status == 401 and rejected == {"error": "credential_rejected"},
        "external_unauthenticated_issue_accepted",
    )

    role_status, role_rejected, _ = _request(
        f"{base_url}/v1/proofs",
        body=binding,
        secret=verification_secret,
    )
    _require(
        role_status == 401 and role_rejected == {"error": "credential_rejected"},
        "external_role_separation_failed",
    )

    issue_status, issued, issue_headers = _request(
        f"{base_url}/v1/proofs",
        body=binding,
        secret=issuance_secret,
    )
    proof = issued.get("proof")
    receipt = issued.get("receipt")
    _require(
        issue_status == 201
        and isinstance(proof, str)
        and proof.startswith("op1.")
        and isinstance(receipt, dict)
        and receipt.get("state") == "issued"
        and issue_headers.get("Cache-Control") == "no-store",
        "external_issue_failed",
    )

    verify_body = {"proof": proof, **binding}
    mismatch_status, mismatch, _ = _request(
        f"{base_url}/v1/verifications",
        body={**verify_body, "purpose": "external-smoke-mismatch"},
        secret=verification_secret,
    )
    _require(
        mismatch_status == 200
        and mismatch.get("verified") is False
        and mismatch.get("reason") == "binding_mismatch",
        "external_binding_mismatch_failed",
    )

    idempotency_key = f"external-smoke-{probe_id}"
    verify_status, verified, verify_headers = _request(
        f"{base_url}/v1/verifications",
        body=verify_body,
        secret=verification_secret,
        idempotency_key=idempotency_key,
    )
    retry_status, retry, _ = _request(
        f"{base_url}/v1/verifications",
        body=verify_body,
        secret=verification_secret,
        idempotency_key=idempotency_key,
    )
    replay_status, replay, _ = _request(
        f"{base_url}/v1/verifications",
        body=verify_body,
        secret=verification_secret,
    )
    _require(
        verify_status == 200
        and verified.get("verified") is True
        and verified.get("witness", {}).get("state") == "verified_once"
        and verify_headers.get("X-Content-Type-Options") == "nosniff",
        "external_verify_failed",
    )
    _require(retry_status == 200 and retry == verified, "external_idempotent_retry_failed")
    _require(
        replay_status == 200
        and replay.get("verified") is False
        and replay.get("witness", {}).get("state") == "replay_rejected",
        "external_replay_rejection_failed",
    )

    print(
        json.dumps(
            {
                "binding_mismatch": "rejected_without_consume",
                "issue": "issued",
                "ready": "ready",
                "replay": "replay_rejected",
                "retry": "same_witness",
                "role_separation": "enforced",
                "tls": urlsplit(base_url).scheme == "https",
                "verify": "verified_once",
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
