"""The ASGI surface exposes two role-separated commands and no token-bearing URLs."""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import sqlite3
from collections.abc import Awaitable, Callable
from contextlib import nullcontext
from dataclasses import dataclass
from typing import Any

from .errors import RateLimitError, RestoreRequiredError, StoreCorruptionError
from .locking import instance_lock
from .service import OnceproofService

_ISSUE_FIELDS = frozenset({"subject", "purpose", "audience", "ttl_seconds"})
_ISSUE_REQUIRED = frozenset({"subject", "purpose", "audience"})
_VERIFY_FIELDS = frozenset({"proof", "subject", "purpose", "audience"})
_VERIFY_REQUIRED = frozenset({"proof", "subject", "purpose", "audience"})
_MAX_IN_FLIGHT_API_REQUESTS = 64
_REQUEST_BODY_TIMEOUT_SECONDS = 5.0

_Receive = Callable[[], Awaitable[dict[str, Any]]]
_Send = Callable[[dict[str, Any]], Awaitable[None]]


@dataclass(frozen=True)
class _RequestError(Exception):
    status: int
    code: str


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _RequestError(400, "duplicate_json_field")
        value[key] = item
    return value


def _header_values(scope: dict[str, Any], name: bytes) -> list[bytes]:
    return [value for key, value in scope.get("headers", []) if key.lower() == name]


def _bearer_secret(scope: dict[str, Any]) -> str:
    values = _header_values(scope, b"authorization")
    if len(values) != 1:
        raise _RequestError(401, "credential_rejected")
    try:
        value = values[0].decode("ascii")
    except UnicodeDecodeError as error:
        raise _RequestError(401, "credential_rejected") from error
    scheme, separator, remainder = value.partition(" ")
    if separator != " " or scheme.lower() != "bearer":
        raise _RequestError(401, "credential_rejected")
    secret = remainder.lstrip(" ")
    if not secret or any(character.isspace() for character in secret):
        raise _RequestError(401, "credential_rejected")
    return secret


def _idempotency_key(scope: dict[str, Any]) -> str | None:
    values = _header_values(scope, b"idempotency-key")
    if not values:
        return None
    if len(values) != 1:
        raise _RequestError(400, "duplicate_idempotency_key")
    try:
        return values[0].decode("ascii")
    except UnicodeDecodeError as error:
        raise _RequestError(400, "invalid_idempotency_key") from error


def _content_type_is_json(scope: dict[str, Any]) -> bool:
    values = _header_values(scope, b"content-type")
    if len(values) != 1:
        return False
    media_type = values[0].split(b";", 1)[0].strip().lower()
    return media_type == b"application/json"


def _strict_object(value: Any, allowed: frozenset[str], required: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise _RequestError(400, "json_object_required")
    unknown = set(value) - allowed
    missing = required - set(value)
    if unknown:
        raise _RequestError(400, "unknown_fields")
    if missing:
        raise _RequestError(400, "missing_fields")
    return value


async def _json_response(
    send: _Send,
    status: int,
    body: dict[str, Any],
    extra_headers: tuple[tuple[bytes, bytes], ...] = (),
) -> None:
    raw = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(raw)).encode("ascii")),
        (b"cache-control", b"no-store"),
        (b"pragma", b"no-cache"),
        (b"x-content-type-options", b"nosniff"),
        (b"x-request-id", f"rq_{secrets.token_hex(12)}".encode("ascii")),
        *extra_headers,
    ]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": raw, "more_body": False})


class OnceproofApp:
    """Translate strict ASGI requests into synchronous, transactional service calls."""

    def __init__(self, service: OnceproofService, max_request_bytes: int) -> None:
        self.service = service
        self.max_request_bytes = max_request_bytes
        self._active_api_requests = 0

    async def __call__(self, scope: dict[str, Any], receive: _Receive, send: _Send) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
            return
        if scope["type"] != "http":
            return
        if str(scope.get("path", "")).startswith("/v1/"):
            if self._active_api_requests >= _MAX_IN_FLIGHT_API_REQUESTS:
                await _json_response(send, 503, {"error": "server_busy"})
                return
            self._active_api_requests += 1
            try:
                await self._http(scope, receive, send)
            finally:
                self._active_api_requests -= 1
            return
        await self._http(scope, receive, send)

    async def _lifespan(self, receive: _Receive, send: _Send) -> None:
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                try:
                    ready = await asyncio.to_thread(self.service.ready)
                except Exception as error:
                    logging.getLogger("onceproof").error(
                        "readiness failed during startup: %s",
                        type(error).__name__,
                    )
                    ready = False
                if not ready:
                    await send({"type": "lifespan.startup.failed", "message": "instance_not_ready"})
                    return
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return

    async def _http(self, scope: dict[str, Any], receive: _Receive, send: _Send) -> None:
        if scope.get("query_string", b""):
            await _json_response(send, 400, {"error": "query_not_allowed"})
            return
        method = str(scope.get("method", "")).upper()
        path = str(scope.get("path", ""))
        try:
            if method == "GET" and path == "/healthz":
                await _json_response(send, 200, {"status": "ok"})
                return
            if method == "GET" and path == "/readyz":
                try:
                    ready = await asyncio.to_thread(self.service.ready)
                except Exception as error:
                    logging.getLogger("onceproof").error(
                        "readiness probe failed: %s",
                        type(error).__name__,
                    )
                    ready = False
                await _json_response(
                    send,
                    200 if ready else 503,
                    {"status": "ready" if ready else "unavailable"},
                )
                return
            if method == "POST" and path == "/v1/proofs":
                await self._issue(scope, receive, send)
                return
            if method == "POST" and path == "/v1/verifications":
                await self._verify(scope, receive, send)
                return
            if path in ("/healthz", "/readyz", "/v1/proofs", "/v1/verifications"):
                allowed = b"GET" if path in ("/healthz", "/readyz") else b"POST"
                await _json_response(
                    send,
                    405,
                    {"error": "method_not_allowed"},
                    ((b"allow", allowed),),
                )
                return
            await _json_response(send, 404, {"error": "not_found"})
        except _RequestError as error:
            headers = (
                ((b"www-authenticate", b'Bearer realm="onceproof"'),)
                if error.status == 401
                else ()
            )
            await _json_response(send, error.status, {"error": error.code}, headers)
        except PermissionError:
            await _json_response(
                send,
                401,
                {"error": "credential_rejected"},
                ((b"www-authenticate", b'Bearer realm="onceproof"'),),
            )
        except RateLimitError as error:
            retry_after = str(error.retry_after_seconds).encode("ascii")
            await _json_response(
                send,
                429,
                {
                    "error": "rate_limited",
                    "retry_after_seconds": error.retry_after_seconds,
                },
                ((b"retry-after", retry_after),),
            )
        except ValueError as error:
            code = str(error)
            if code == "audience_not_allowed":
                await _json_response(send, 403, {"error": code})
            elif code == "idempotency_conflict":
                await _json_response(send, 409, {"error": code})
            else:
                await _json_response(
                    send,
                    400,
                    {"error": code if code.startswith("invalid_") else "invalid_request"},
                )
        except (sqlite3.Error, RestoreRequiredError, StoreCorruptionError):
            await _json_response(send, 503, {"error": "store_unavailable"})
        except Exception as error:
            logging.getLogger("onceproof").error("request failed: %s", type(error).__name__)
            await _json_response(send, 500, {"error": "internal_error"})

    async def _issue(self, scope: dict[str, Any], receive: _Receive, send: _Send) -> None:
        secret = _bearer_secret(scope)
        authenticated = await asyncio.to_thread(
            self.service.credential_is_accepted,
            secret,
            "issuance",
        )
        if not authenticated:
            raise PermissionError("credential_rejected")
        payload = await self._read_json(scope, receive, _ISSUE_FIELDS, _ISSUE_REQUIRED)
        ttl_seconds = payload.get("ttl_seconds")
        if "ttl_seconds" in payload:
            if isinstance(ttl_seconds, float) and ttl_seconds.is_integer():
                ttl_seconds = int(ttl_seconds)
            if (
                isinstance(ttl_seconds, bool)
                or not isinstance(ttl_seconds, int)
                or not 1 <= ttl_seconds <= 3600
            ):
                raise _RequestError(400, "invalid_ttl_seconds")
        issued = await asyncio.to_thread(
            self.service.issue_proof,
            issuance_secret=secret,
            subject=payload["subject"],
            purpose=payload["purpose"],
            audience=payload["audience"],
            ttl_seconds=ttl_seconds,
        )
        await _json_response(send, 201, issued.to_dict())

    async def _verify(self, scope: dict[str, Any], receive: _Receive, send: _Send) -> None:
        secret = _bearer_secret(scope)
        authenticated = await asyncio.to_thread(
            self.service.credential_is_accepted,
            secret,
            "verification",
        )
        if not authenticated:
            raise PermissionError("credential_rejected")
        idempotency_key = _idempotency_key(scope)
        payload = await self._read_json(scope, receive, _VERIFY_FIELDS, _VERIFY_REQUIRED)
        result = await asyncio.to_thread(
            self.service.verify_proof,
            verification_secret=secret,
            proof=payload["proof"],
            subject=payload["subject"],
            purpose=payload["purpose"],
            audience=payload["audience"],
            idempotency_key=idempotency_key,
        )
        if result.reason == "credential_rejected":
            raise PermissionError("credential_rejected")
        await _json_response(send, 200, result.to_dict())

    async def _read_json(
        self,
        scope: dict[str, Any],
        receive: _Receive,
        allowed: frozenset[str],
        required: frozenset[str],
    ) -> dict[str, Any]:
        if not _content_type_is_json(scope):
            raise _RequestError(415, "content_type_must_be_json")
        body = bytearray()
        try:
            async with asyncio.timeout(_REQUEST_BODY_TIMEOUT_SECONDS):
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        raise _RequestError(400, "incomplete_request")
                    if message["type"] != "http.request":
                        continue
                    body.extend(message.get("body", b""))
                    if len(body) > self.max_request_bytes:
                        raise _RequestError(413, "request_too_large")
                    if not message.get("more_body", False):
                        break
        except TimeoutError as error:
            raise _RequestError(408, "request_timeout") from error
        if not body:
            raise _RequestError(400, "empty_request")
        try:
            value = json.loads(body, object_pairs_hook=_object_without_duplicates)
        except _RequestError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise _RequestError(400, "invalid_json") from error
        return _strict_object(value, allowed, required)


def create_app(*, service: OnceproofService, max_request_bytes: int) -> OnceproofApp:
    return OnceproofApp(service, max_request_bytes)


def serve(
    *,
    service: OnceproofService,
    host: str,
    port: int,
    max_request_bytes: int,
    instance_lock_held: bool = False,
) -> None:
    import uvicorn

    app = create_app(service=service, max_request_bytes=max_request_bytes)
    lock = nullcontext() if instance_lock_held else instance_lock(service.store.path)
    with lock:
        uvicorn.run(
            app,
            host=host,
            port=port,
            workers=1,
            ws="none",
            proxy_headers=False,
            server_header=False,
            access_log=False,
        backlog=128,
            timeout_keep_alive=5,
            timeout_graceful_shutdown=15,
        )


__all__ = ["OnceproofApp", "create_app", "serve"]
