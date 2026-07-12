"""Exercise the installed wheel through its CLI and real loopback HTTP server."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


def _run(*arguments: str) -> dict[str, Any]:
    completed = subprocess.run(
        [sys.executable, "-m", "onceproof", *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _request(
    url: str,
    *,
    body: dict[str, Any] | None = None,
    secret: str | None = None,
    idempotency_key: str | None = None,
) -> tuple[int, dict[str, Any]]:
    headers = {"Accept": "application/json"}
    data = None
    method = "GET"
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
        method = "POST"
    if secret is not None:
        headers["Authorization"] = f"Bearer {secret}"
    if idempotency_key is not None:
        headers["Idempotency-Key"] = idempotency_key
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=5) as response:
        return int(response.status), json.loads(response.read())


def _wait_ready(base_url: str, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"server_exited:{process.returncode}")
        try:
            status, body = _request(f"{base_url}/readyz")
        except (OSError, urllib.error.URLError):
            time.sleep(0.1)
            continue
        if status == 200 and body == {"status": "ready"}:
            return
        time.sleep(0.1)
    raise TimeoutError("server_not_ready")


def main() -> int:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        instance = root / "instance"
        config = instance / "onceproof.toml"
        credentials_path = root / "client.credentials.json"
        _run("init", str(instance))
        port = _free_loopback_port()
        config.write_text(
            config.read_text(encoding="utf-8").replace("port = 8787", f"port = {port}"),
            encoding="utf-8",
        )
        _run(
            "client",
            "create",
            "--config",
            str(config),
            "--name",
            "release-smoke",
            "--audience",
            "urn:onceproof:release-smoke",
            "--credentials-out",
            str(credentials_path),
        )
        credentials = json.loads(credentials_path.read_text(encoding="utf-8"))
        stdout_path = root / "server.stdout.log"
        stderr_path = root / "server.stderr.log"
        creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            process = subprocess.Popen(
                [sys.executable, "-m", "onceproof", "serve", "--config", str(config)],
                stdout=stdout,
                stderr=stderr,
                creationflags=creationflags,
            )
            try:
                base_url = f"http://127.0.0.1:{port}"
                _wait_ready(base_url, process)
                issue_status, issued = _request(
                    f"{base_url}/v1/proofs",
                    secret=credentials["issuance_secret"],
                    body={
                        "subject": "release-subject",
                        "purpose": "release-smoke",
                        "audience": "urn:onceproof:release-smoke",
                    },
                )
                verify_body = {
                    "proof": issued["proof"],
                    "subject": "release-subject",
                    "purpose": "release-smoke",
                    "audience": "urn:onceproof:release-smoke",
                }
                verify_status, verified = _request(
                    f"{base_url}/v1/verifications",
                    secret=credentials["verification_secret"],
                    idempotency_key="release-smoke-request",
                    body=verify_body,
                )
                retry_status, retry = _request(
                    f"{base_url}/v1/verifications",
                    secret=credentials["verification_secret"],
                    idempotency_key="release-smoke-request",
                    body=verify_body,
                )
                replay_status, replay = _request(
                    f"{base_url}/v1/verifications",
                    secret=credentials["verification_secret"],
                    body=verify_body,
                )
                if (
                    issue_status != 201
                    or issued["receipt"]["state"] != "issued"
                    or verify_status != 200
                    or not verified["verified"]
                    or retry_status != 200
                    or retry != verified
                    or replay_status != 200
                    or replay["witness"]["state"] != "replay_rejected"
                ):
                    raise RuntimeError("release_smoke_invariant_failed")
            finally:
                process.terminate()
                process.wait(timeout=10)

        logs = stdout_path.read_bytes() + stderr_path.read_bytes()
        for bearer in (
            credentials["issuance_secret"],
            credentials["verification_secret"],
            issued["proof"],
        ):
            if bearer.encode("utf-8") in logs:
                raise RuntimeError("release_smoke_bearer_logged")
        doctor = _run("doctor", "--config", str(config))
        if doctor["status"] != "healthy":
            raise RuntimeError("release_smoke_doctor_failed")
        print(
            json.dumps(
                {
                    "doctor": "healthy",
                    "issue": "issued",
                    "replay": "replay_rejected",
                    "retry": "same_witness",
                    "verify": "verified_once",
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
