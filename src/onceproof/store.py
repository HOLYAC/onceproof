"""SQLite owns the atomic transition from an active proof to one witness."""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .errors import RateLimitError, RestoreRequiredError, StoreCorruptionError
from .model import ProofClaims, VerificationResult, VerificationWitness

_SCHEMA_VERSION = 1
IDEMPOTENCY_RETENTION_SECONDS = 86_400
PROOF_RETENTION_SECONDS = 3_600
_REQUIRED_TABLES = frozenset(
    {
        "audit_events",
        "clients",
        "credentials",
        "hash_keys",
        "maintenance",
        "proofs",
        "rate_events",
        "verifications",
    }
)
_REQUIRED_INDEXES = frozenset(
    {
        "audit_events_created",
        "one_current_credential_per_role",
        "proofs_expiry",
        "proofs_hash_kid",
        "rate_events_expiry",
        "rate_events_window",
        "verification_idempotency",
        "verifications_created",
    }
)


@dataclass(frozen=True)
class ClientRecord:
    """Read client policy from the durable registration row."""

    client_id: str
    name: str
    status: str
    allowed_audiences: tuple[str, ...]
    proof_ttl_seconds: int
    issue_limit_per_minute: int
    verify_limit_per_minute: int


@dataclass(frozen=True)
class CredentialRecord:
    """Read only the digest metadata needed to authenticate one role."""

    credential_id: str
    client_id: str
    role: str
    hash_kid: str
    secret_digest: str
    status: str
    valid_until: int | None


@dataclass(frozen=True)
class ProofRecord:
    """Read proof claims from their keyed digest, never from bearer bytes."""

    token_digest: str
    proof_tag: str
    hash_kid: str
    client_id: str
    issue_credential_id: str
    subject: str
    purpose: str
    audience: str
    issued_at: int
    expires_at: int
    consumed_at: int | None


def _credential_is_accepted(record: sqlite3.Row, now: int) -> bool:
    if record["status"] == "current":
        return True
    valid_until = record["valid_until"]
    return record["status"] == "previous" and valid_until is not None and now < int(valid_until)


def _client_from_row(row: sqlite3.Row) -> ClientRecord:
    try:
        audiences = json.loads(row["allowed_audiences_json"])
    except (TypeError, json.JSONDecodeError) as error:
        raise StoreCorruptionError from error
    if not isinstance(audiences, list) or not audiences or any(
        not isinstance(value, str) or not value for value in audiences
    ):
        raise StoreCorruptionError
    return ClientRecord(
        client_id=row["client_id"],
        name=row["name"],
        status=row["status"],
        allowed_audiences=tuple(str(value) for value in audiences),
        proof_ttl_seconds=int(row["proof_ttl_seconds"]),
        issue_limit_per_minute=int(row["issue_limit_per_minute"]),
        verify_limit_per_minute=int(row["verify_limit_per_minute"]),
    )


def _credential_from_row(row: sqlite3.Row) -> CredentialRecord:
    valid_until = row["valid_until"]
    return CredentialRecord(
        credential_id=row["credential_id"],
        client_id=row["client_id"],
        role=row["role"],
        hash_kid=row["hash_kid"],
        secret_digest=row["secret_digest"],
        status=row["status"],
        valid_until=int(valid_until) if valid_until is not None else None,
    )


def _proof_from_row(row: sqlite3.Row) -> ProofRecord:
    consumed_at = row["consumed_at"]
    return ProofRecord(
        token_digest=row["token_digest"],
        proof_tag=row["proof_tag"],
        hash_kid=row["hash_kid"],
        client_id=row["client_id"],
        issue_credential_id=row["issue_credential_id"],
        subject=row["subject"],
        purpose=row["purpose"],
        audience=row["audience"],
        issued_at=int(row["issued_at"]),
        expires_at=int(row["expires_at"]),
        consumed_at=int(consumed_at) if consumed_at is not None else None,
    )


def _result_json(result: VerificationResult) -> str:
    return json.dumps(result.to_dict(), separators=(",", ":"), sort_keys=True)


def _result_from_json(value: str) -> VerificationResult:
    try:
        decoded = json.loads(value)
        return VerificationResult.from_dict(decoded)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise StoreCorruptionError from error


def _rejected_result(
    *,
    reason: str,
    verification_id: str,
    proof_tag: str | None,
    client_id: str | None,
    now: int,
) -> VerificationResult:
    state = "replay_rejected" if reason == "already_consumed" else "rejected"
    return VerificationResult(
        verified=False,
        reason=reason,
        witness=VerificationWitness(
            state=state,
            verification_id=verification_id,
            proof_tag=proof_tag,
            client_id=client_id,
            decided_at=now,
            reason=reason,
        ),
    )


def _accepted_result(record: ProofRecord, verification_id: str, now: int) -> VerificationResult:
    claims = ProofClaims(
        client_id=record.client_id,
        subject=record.subject,
        purpose=record.purpose,
        audience=record.audience,
        issued_at=record.issued_at,
        expires_at=record.expires_at,
    )
    return VerificationResult(
        verified=True,
        reason=None,
        witness=VerificationWitness(
            state="verified_once",
            verification_id=verification_id,
            proof_tag=record.proof_tag,
            client_id=record.client_id,
            decided_at=now,
        ),
        claims=claims,
    )


def _create_schema(database: sqlite3.Connection) -> None:
    database.execute(
        """
        CREATE TABLE clients (
            client_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
            allowed_audiences_json TEXT NOT NULL,
            proof_ttl_seconds INTEGER NOT NULL CHECK (proof_ttl_seconds BETWEEN 1 AND 3600),
            issue_limit_per_minute INTEGER NOT NULL CHECK (issue_limit_per_minute BETWEEN 1 AND 100000),
            verify_limit_per_minute INTEGER NOT NULL CHECK (verify_limit_per_minute BETWEEN 1 AND 100000),
            created_at INTEGER NOT NULL,
            revoked_at INTEGER
        ) STRICT
        """
    )
    database.execute(
        """
        CREATE TABLE credentials (
            credential_id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL REFERENCES clients(client_id) ON DELETE RESTRICT,
            role TEXT NOT NULL CHECK (role IN ('issuance', 'verification')),
            hash_kid TEXT NOT NULL,
            secret_digest TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('current', 'previous', 'revoked')),
            created_at INTEGER NOT NULL,
            valid_until INTEGER,
            revoked_at INTEGER
        ) STRICT
        """
    )
    database.execute(
        """
        CREATE UNIQUE INDEX one_current_credential_per_role
        ON credentials(client_id, role)
        WHERE status = 'current'
        """
    )
    database.execute(
        """
        CREATE TABLE proofs (
            token_digest TEXT PRIMARY KEY,
            proof_tag TEXT NOT NULL UNIQUE,
            hash_kid TEXT NOT NULL,
            client_id TEXT NOT NULL REFERENCES clients(client_id) ON DELETE RESTRICT,
            issue_credential_id TEXT NOT NULL REFERENCES credentials(credential_id) ON DELETE RESTRICT,
            subject TEXT NOT NULL,
            purpose TEXT NOT NULL,
            audience TEXT NOT NULL,
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            consumed_at INTEGER,
            consume_verification_id TEXT
        ) STRICT
        """
    )
    database.execute("CREATE INDEX proofs_expiry ON proofs(expires_at)")
    database.execute("CREATE INDEX proofs_hash_kid ON proofs(hash_kid)")
    database.execute(
        """
        CREATE TABLE verifications (
            verification_id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            credential_id TEXT NOT NULL,
            proof_tag TEXT,
            request_fingerprint TEXT NOT NULL,
            idempotency_key TEXT,
            result_json TEXT NOT NULL,
            created_at INTEGER NOT NULL
        ) STRICT
        """
    )
    database.execute(
        """
        CREATE UNIQUE INDEX verification_idempotency
        ON verifications(client_id, idempotency_key)
        WHERE idempotency_key IS NOT NULL
        """
    )
    database.execute("CREATE INDEX verifications_created ON verifications(created_at)")
    database.execute(
        """
        CREATE TABLE audit_events (
            event_id TEXT PRIMARY KEY,
            created_at INTEGER NOT NULL,
            kind TEXT NOT NULL,
            client_id TEXT,
            credential_id TEXT,
            proof_tag TEXT,
            outcome TEXT NOT NULL,
            reason TEXT
        ) STRICT
        """
    )
    database.execute("CREATE INDEX audit_events_created ON audit_events(created_at)")
    database.execute(
        """
        CREATE TABLE rate_events (
            event_id INTEGER PRIMARY KEY,
            client_id TEXT NOT NULL,
            operation TEXT NOT NULL CHECK (operation IN ('issue', 'verify')),
            occurred_at INTEGER NOT NULL
        ) STRICT
        """
    )
    database.execute(
        "CREATE INDEX rate_events_window ON rate_events(client_id, operation, occurred_at)"
    )
    database.execute("CREATE INDEX rate_events_expiry ON rate_events(occurred_at)")
    database.execute(
        """
        CREATE TABLE hash_keys (
            hash_kid TEXT PRIMARY KEY,
            key_check TEXT NOT NULL
        ) STRICT
        """
    )
    database.execute(
        """
        CREATE TABLE maintenance (
            name TEXT PRIMARY KEY,
            value_integer INTEGER NOT NULL
        ) STRICT
        """
    )
    database.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")


def _assert_complete_schema(database: sqlite3.Connection) -> None:
    rows = database.execute(
        "SELECT type, name FROM sqlite_schema WHERE type IN ('table', 'index')"
    ).fetchall()
    tables = {str(row["name"]) for row in rows if row["type"] == "table"}
    indexes = {str(row["name"]) for row in rows if row["type"] == "index"}
    missing_tables = sorted(_REQUIRED_TABLES - tables)
    missing_indexes = sorted(_REQUIRED_INDEXES - indexes)
    if missing_tables or missing_indexes:
        missing = ",".join([*(f"table:{name}" for name in missing_tables), *(f"index:{name}" for name in missing_indexes)])
        raise ValueError(f"incomplete_schema:{missing}")


def _fsync_parent(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class Store:
    """Keep every replay-sensitive state transition in a SQLite write lock."""

    def __init__(self, path: str | Path, *, _initialize: bool = False) -> None:
        declared = Path(path).absolute()
        if not declared.exists():
            raise ValueError("database_missing")
        if declared.is_symlink() or not declared.is_file():
            raise ValueError("database_not_regular")
        if os.name != "nt":
            mode = stat.S_IMODE(declared.stat().st_mode)
            parent_mode = stat.S_IMODE(declared.parent.stat().st_mode)
            if mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise ValueError("database_permissions_too_open")
            if parent_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise ValueError("database_parent_permissions_too_open")
        self.path = declared.resolve()
        self._initialize(allow_schema_creation=_initialize)

    @classmethod
    def create(cls, path: str | Path) -> Store:
        target = Path(path).resolve()
        if not target.parent.is_dir():
            raise ValueError("database_parent_missing")
        descriptor = os.open(target, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        try:
            os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)
            return cls(target, _initialize=True)
        except BaseException:
            for suffix in ("", "-journal", "-shm", "-wal"):
                target.with_name(target.name + suffix).unlink(missing_ok=True)
            raise

    def _connect(self) -> sqlite3.Connection:
        database = sqlite3.connect(
            f"{self.path.as_uri()}?mode=rw",
            timeout=10,
            isolation_level=None,
            uri=True,
        )
        database.row_factory = sqlite3.Row
        database.execute("PRAGMA foreign_keys = ON")
        database.execute("PRAGMA busy_timeout = 10000")
        database.execute("PRAGMA trusted_schema = OFF")
        database.execute("PRAGMA synchronous = EXTRA")
        database.execute("PRAGMA secure_delete = ON")
        return database

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        database = self._connect()
        try:
            yield database
        finally:
            database.close()

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        database = self._connect()
        try:
            database.execute("BEGIN IMMEDIATE")
            yield database
            database.execute("COMMIT")
        except BaseException:
            if database.in_transaction:
                database.execute("ROLLBACK")
            raise
        finally:
            database.close()

    def _initialize(self, *, allow_schema_creation: bool) -> None:
        with self._read() as database:
            database.execute("PRAGMA journal_mode = DELETE")
            database.execute("BEGIN IMMEDIATE")
            try:
                version = int(database.execute("PRAGMA user_version").fetchone()[0])
                if version not in (0, _SCHEMA_VERSION):
                    raise ValueError(f"unsupported_schema_version:{version}")
                if version == 0:
                    if not allow_schema_creation:
                        raise ValueError("uninitialized_database")
                    _create_schema(database)
                _assert_complete_schema(database)
                database.execute("COMMIT")
            except BaseException:
                if database.in_transaction:
                    database.execute("ROLLBACK")
                raise

    def create_client(
        self,
        *,
        client_id: str,
        name: str,
        allowed_audiences: tuple[str, ...],
        proof_ttl_seconds: int,
        issue_limit_per_minute: int,
        verify_limit_per_minute: int,
        issuance_credential: CredentialRecord,
        verification_credential: CredentialRecord,
        hash_key_check: str,
        now: int,
    ) -> None:
        with self._write() as database:
            self._require_operational(database)
            hash_kids = {issuance_credential.hash_kid, verification_credential.hash_kid}
            if len(hash_kids) != 1:
                raise ValueError("client_credential_key_mismatch")
            self._register_hash_key(database, hash_kids.pop(), hash_key_check)
            database.execute(
                """
                INSERT INTO clients (
                    client_id, name, status, allowed_audiences_json,
                    proof_ttl_seconds, issue_limit_per_minute,
                    verify_limit_per_minute, created_at
                ) VALUES (?, ?, 'active', ?, ?, ?, ?, ?)
                """,
                (
                    client_id,
                    name,
                    json.dumps(allowed_audiences, separators=(",", ":")),
                    proof_ttl_seconds,
                    issue_limit_per_minute,
                    verify_limit_per_minute,
                    now,
                ),
            )
            for credential in (issuance_credential, verification_credential):
                database.execute(
                    """
                    INSERT INTO credentials (
                        credential_id, client_id, role, hash_kid,
                        secret_digest, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, 'current', ?)
                    """,
                    (
                        credential.credential_id,
                        credential.client_id,
                        credential.role,
                        credential.hash_kid,
                        credential.secret_digest,
                        now,
                    ),
                )
            self._insert_audit(
                database,
                now=now,
                kind="client_created",
                client_id=client_id,
                outcome="created",
            )

    def client(self, client_id: str) -> ClientRecord | None:
        with self._read() as database:
            row = database.execute(
                "SELECT * FROM clients WHERE client_id = ?",
                (client_id,),
            ).fetchone()
        return _client_from_row(row) if row is not None else None

    def credential(self, credential_id: str) -> CredentialRecord | None:
        with self._read() as database:
            row = database.execute(
                "SELECT * FROM credentials WHERE credential_id = ?",
                (credential_id,),
            ).fetchone()
        return _credential_from_row(row) if row is not None else None

    def credentials_for_client(self, client_id: str) -> tuple[CredentialRecord, ...]:
        with self._read() as database:
            rows = database.execute(
                """
                SELECT * FROM credentials
                WHERE client_id = ?
                ORDER BY role, created_at, credential_id
                """,
                (client_id,),
            ).fetchall()
        return tuple(_credential_from_row(row) for row in rows)

    def issue_proof(
        self,
        record: ProofRecord,
        *,
        hash_key_check: str,
        clock: Callable[[], int],
    ) -> ProofRecord:
        with self._write() as database:
            self._require_operational(database)
            self._register_hash_key(database, record.hash_kid, hash_key_check)
            now = clock()
            ttl_seconds = record.expires_at - record.issued_at
            committed = replace(record, issued_at=now, expires_at=now + ttl_seconds)
            credential = database.execute(
                """
                SELECT credentials.*, clients.status AS client_status
                    , clients.issue_limit_per_minute AS operation_limit
                FROM credentials
                JOIN clients USING (client_id)
                WHERE credential_id = ? AND role = 'issuance'
                """,
                (committed.issue_credential_id,),
            ).fetchone()
            if credential is None or credential["client_status"] != "active":
                raise PermissionError("credential_rejected")
            if credential["client_id"] != committed.client_id or not _credential_is_accepted(credential, now):
                raise PermissionError("credential_rejected")
            self._consume_rate_slot(
                database,
                client_id=committed.client_id,
                operation="issue",
                limit=int(credential["operation_limit"]),
                now=now,
            )
            database.execute(
                """
                INSERT INTO proofs (
                    token_digest, proof_tag, hash_kid, client_id,
                    issue_credential_id, subject, purpose, audience,
                    issued_at, expires_at, consumed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    committed.token_digest,
                    committed.proof_tag,
                    committed.hash_kid,
                    committed.client_id,
                    committed.issue_credential_id,
                    committed.subject,
                    committed.purpose,
                    committed.audience,
                    committed.issued_at,
                    committed.expires_at,
                ),
            )
            self._insert_audit(
                database,
                now=now,
                kind="proof_issued",
                client_id=committed.client_id,
                credential_id=committed.issue_credential_id,
                proof_tag=committed.proof_tag,
                outcome="issued",
            )
        return committed

    def consume_proof(
        self,
        *,
        credential_id: str,
        client_id: str,
        token_digest: str,
        subject: str,
        purpose: str,
        audience: str,
        request_fingerprint: str,
        idempotency_key: str | None,
        clock: Callable[[], int],
    ) -> VerificationResult:
        with self._write() as database:
            self._require_operational(database)
            now = clock()
            credential = database.execute(
                """
                SELECT credentials.*, clients.status AS client_status
                    , clients.verify_limit_per_minute AS operation_limit
                FROM credentials
                JOIN clients USING (client_id)
                WHERE credential_id = ? AND role = 'verification'
                """,
                (credential_id,),
            ).fetchone()
            if (
                credential is None
                or credential["client_id"] != client_id
                or credential["client_status"] != "active"
                or not _credential_is_accepted(credential, now)
            ):
                return _rejected_result(
                    reason="credential_rejected",
                    verification_id=f"vr_{secrets.token_hex(16)}",
                    proof_tag=None,
                    client_id=None,
                    now=now,
                )

            cached = self._idempotent_result(
                database,
                client_id=client_id,
                idempotency_key=idempotency_key,
                request_fingerprint=request_fingerprint,
            )
            if cached is not None:
                return cached

            self._consume_rate_slot(
                database,
                client_id=client_id,
                operation="verify",
                limit=int(credential["operation_limit"]),
                now=now,
            )

            verification_id = f"vr_{secrets.token_hex(16)}"
            row = database.execute(
                "SELECT * FROM proofs WHERE token_digest = ?",
                (token_digest,),
            ).fetchone()
            record = _proof_from_row(row) if row is not None and row["client_id"] == client_id else None

            if record is None:
                result = _rejected_result(
                    reason="invalid",
                    verification_id=verification_id,
                    proof_tag=None,
                    client_id=client_id,
                    now=now,
                )
            elif record.consumed_at is not None:
                result = _rejected_result(
                    reason="already_consumed",
                    verification_id=verification_id,
                    proof_tag=record.proof_tag,
                    client_id=client_id,
                    now=now,
                )
            elif now >= record.expires_at:
                result = _rejected_result(
                    reason="expired",
                    verification_id=verification_id,
                    proof_tag=record.proof_tag,
                    client_id=client_id,
                    now=now,
                )
            elif (
                record.purpose != purpose
                or record.audience != audience
                or record.subject != subject
            ):
                result = _rejected_result(
                    reason="binding_mismatch",
                    verification_id=verification_id,
                    proof_tag=record.proof_tag,
                    client_id=client_id,
                    now=now,
                )
            else:
                updated = database.execute(
                    """
                    UPDATE proofs
                    SET consumed_at = ?, consume_verification_id = ?
                    WHERE token_digest = ? AND consumed_at IS NULL AND expires_at > ?
                    """,
                    (now, verification_id, token_digest, now),
                )
                if updated.rowcount == 1:
                    result = _accepted_result(record, verification_id, now)
                else:
                    result = _rejected_result(
                        reason="already_consumed",
                        verification_id=verification_id,
                        proof_tag=record.proof_tag,
                        client_id=client_id,
                        now=now,
                    )

            self._insert_verification(
                database,
                result=result,
                credential_id=credential_id,
                client_id=client_id,
                request_fingerprint=request_fingerprint,
                idempotency_key=idempotency_key,
                now=now,
            )
            self._insert_audit(
                database,
                now=now,
                kind="proof_verified" if result.verified else "proof_rejected",
                client_id=client_id,
                credential_id=credential_id,
                proof_tag=result.witness.proof_tag,
                outcome="verified" if result.verified else "rejected",
                reason=result.reason,
            )
            return result

    def rotate_credential(
        self,
        *,
        client_id: str,
        role: str,
        replacement: CredentialRecord,
        hash_key_check: str,
        grace_seconds: int,
        now: int,
    ) -> tuple[str, int]:
        previous_valid_until = now + grace_seconds
        with self._write() as database:
            self._require_operational(database)
            self._register_hash_key(database, replacement.hash_kid, hash_key_check)
            client = database.execute(
                "SELECT status FROM clients WHERE client_id = ?",
                (client_id,),
            ).fetchone()
            if client is None:
                raise KeyError(client_id)
            if client["status"] != "active":
                raise ValueError("client_revoked")
            current = database.execute(
                """
                SELECT credential_id FROM credentials
                WHERE client_id = ? AND role = ? AND status = 'current'
                """,
                (client_id, role),
            ).fetchone()
            if current is None:
                raise ValueError("current_credential_missing")
            previous_id = str(current["credential_id"])
            database.execute(
                """
                UPDATE credentials
                SET status = 'previous', valid_until = ?
                WHERE credential_id = ?
                """,
                (previous_valid_until, previous_id),
            )
            database.execute(
                """
                INSERT INTO credentials (
                    credential_id, client_id, role, hash_kid,
                    secret_digest, status, created_at
                ) VALUES (?, ?, ?, ?, ?, 'current', ?)
                """,
                (
                    replacement.credential_id,
                    replacement.client_id,
                    replacement.role,
                    replacement.hash_kid,
                    replacement.secret_digest,
                    now,
                ),
            )
            self._insert_audit(
                database,
                now=now,
                kind="credential_rotated",
                client_id=client_id,
                credential_id=replacement.credential_id,
                outcome="rotated",
            )
        return previous_id, previous_valid_until

    def revoke_client(self, client_id: str, *, now: int) -> bool:
        with self._write() as database:
            self._require_operational(database)
            client = database.execute(
                "SELECT status FROM clients WHERE client_id = ?",
                (client_id,),
            ).fetchone()
            if client is None:
                raise KeyError(client_id)
            if client["status"] == "revoked":
                return False
            database.execute(
                "UPDATE clients SET status = 'revoked', revoked_at = ? WHERE client_id = ?",
                (now, client_id),
            )
            database.execute(
                """
                UPDATE credentials
                SET status = 'revoked', valid_until = ?, revoked_at = ?
                WHERE client_id = ? AND status != 'revoked'
                """,
                (now, now, client_id),
            )
            database.execute(
                """
                UPDATE proofs
                SET expires_at = CASE WHEN expires_at < ? THEN expires_at ELSE ? END
                WHERE client_id = ? AND consumed_at IS NULL
                """,
                (now, now, client_id),
            )
            self._insert_audit(
                database,
                now=now,
                kind="client_revoked",
                client_id=client_id,
                outcome="revoked",
            )
            return True

    def cleanup(
        self,
        now: int,
        *,
        proof_retention_seconds: int = PROOF_RETENTION_SECONDS,
        verification_retention_seconds: int = IDEMPOTENCY_RETENTION_SECONDS,
        audit_retention_seconds: int = 604_800,
    ) -> dict[str, int]:
        with self._write() as database:
            proofs = database.execute(
                "DELETE FROM proofs WHERE expires_at < ?",
                (now - proof_retention_seconds,),
            ).rowcount
            credentials = database.execute(
                """
                DELETE FROM credentials
                WHERE status != 'current'
                  AND COALESCE(valid_until, revoked_at, created_at) < ?
                  AND NOT EXISTS (
                      SELECT 1 FROM proofs
                      WHERE proofs.issue_credential_id = credentials.credential_id
                  )
                """,
                (now,),
            ).rowcount
            verifications = database.execute(
                "DELETE FROM verifications WHERE created_at < ?",
                (now - verification_retention_seconds,),
            ).rowcount
            audit_events = database.execute(
                "DELETE FROM audit_events WHERE created_at < ?",
                (now - audit_retention_seconds,),
            ).rowcount
            rate_events = database.execute(
                "DELETE FROM rate_events WHERE occurred_at <= ?",
                (now - 60,),
            ).rowcount
            database.execute(
                """
                INSERT INTO maintenance (name, value_integer)
                VALUES ('last_cleanup_at', ?)
                ON CONFLICT(name) DO UPDATE SET value_integer = excluded.value_integer
                """,
                (now,),
            )
        return {
            "proofs": proofs,
            "credentials": credentials,
            "verifications": verifications,
            "audit_events": audit_events,
            "rate_events": rate_events,
        }

    def hash_key_is_in_use(self, kid: str) -> bool:
        with self._read() as database:
            credential = database.execute(
                "SELECT 1 FROM credentials WHERE hash_kid = ? LIMIT 1",
                (kid,),
            ).fetchone()
            proof = database.execute(
                "SELECT 1 FROM proofs WHERE hash_kid = ? LIMIT 1",
                (kid,),
            ).fetchone()
        return credential is not None or proof is not None

    def ready(self) -> bool:
        try:
            with self._read() as database:
                version = int(database.execute("PRAGMA user_version").fetchone()[0])
                foreign_keys = int(database.execute("PRAGMA foreign_keys").fetchone()[0])
                synchronous = int(database.execute("PRAGMA synchronous").fetchone()[0])
                journal_mode = str(database.execute("PRAGMA journal_mode").fetchone()[0]).lower()
                restore_required = self._restore_required(database)
                _assert_complete_schema(database)
                database.execute("BEGIN IMMEDIATE")
                database.execute("ROLLBACK")
        except (sqlite3.Error, ValueError):
            return False
        return (
            version == _SCHEMA_VERSION
            and foreign_keys == 1
            and synchronous == 3
            and journal_mode == "delete"
            and not restore_required
        )

    def referenced_hash_kids(self) -> tuple[str, ...]:
        with self._read() as database:
            rows = database.execute(
                """
                SELECT hash_kid FROM credentials
                UNION
                SELECT hash_kid FROM proofs
                ORDER BY hash_kid
                """
            ).fetchall()
        return tuple(str(row["hash_kid"]) for row in rows)

    def referenced_hash_key_checks(self) -> dict[str, str]:
        kids = self.referenced_hash_kids()
        if not kids:
            return {}
        placeholders = ",".join("?" for _ in kids)
        with self._read() as database:
            rows = database.execute(
                f"SELECT hash_kid, key_check FROM hash_keys WHERE hash_kid IN ({placeholders})",
                kids,
            ).fetchall()
        checks = {str(row["hash_kid"]): str(row["key_check"]) for row in rows}
        if set(checks) != set(kids):
            raise StoreCorruptionError
        return checks

    def integrity_check(self) -> str:
        with self._read() as database:
            rows = database.execute("PRAGMA integrity_check").fetchall()
        return "\n".join(str(row[0]) for row in rows)

    def status(self) -> dict[str, Any]:
        with self._read() as database:
            cleanup = database.execute(
                "SELECT value_integer FROM maintenance WHERE name = 'last_cleanup_at'"
            ).fetchone()
            return {
                "sqlite_version": sqlite3.sqlite_version,
                "schema_version": int(database.execute("PRAGMA user_version").fetchone()[0]),
                "journal_mode": str(database.execute("PRAGMA journal_mode").fetchone()[0]).lower(),
                "synchronous": int(database.execute("PRAGMA synchronous").fetchone()[0]),
                "foreign_keys": bool(database.execute("PRAGMA foreign_keys").fetchone()[0]),
                "secure_delete": bool(database.execute("PRAGMA secure_delete").fetchone()[0]),
                "last_cleanup_at": int(cleanup[0]) if cleanup is not None else None,
                "restore_required": self._restore_required(database),
            }

    def backup(self, destination: str | Path) -> Path:
        target = Path(destination).resolve()
        if target == self.path:
            raise ValueError("backup_path_collision")
        if target.exists():
            raise FileExistsError(target)
        if not target.parent.is_dir():
            raise ValueError("backup_parent_missing")

        descriptor = os.open(target, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        source: sqlite3.Connection | None = None
        backup: sqlite3.Connection | None = None
        try:
            source = self._connect()
            backup = sqlite3.connect(f"{target.as_uri()}?mode=rw", uri=True)
            source.backup(backup)
            backup.execute(
                """
                INSERT INTO maintenance (name, value_integer)
                VALUES ('restore_required', 1)
                ON CONFLICT(name) DO UPDATE SET value_integer = 1
                """
            )
            result = str(backup.execute("PRAGMA integrity_check").fetchone()[0])
            if result != "ok":
                raise sqlite3.DatabaseError(f"backup_integrity_failed:{result}")
            backup.commit()
            backup.close()
            backup = None
            source.close()
            source = None
            os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)
            descriptor = os.open(target, os.O_RDWR)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            _fsync_parent(target)
        except BaseException:
            if backup is not None:
                backup.close()
            if source is not None:
                source.close()
            target.unlink(missing_ok=True)
            raise
        return target

    def _idempotent_result(
        self,
        database: sqlite3.Connection,
        *,
        client_id: str,
        idempotency_key: str | None,
        request_fingerprint: str,
    ) -> VerificationResult | None:
        if idempotency_key is None:
            return None
        row = database.execute(
            """
            SELECT request_fingerprint, result_json
            FROM verifications
            WHERE client_id = ? AND idempotency_key = ?
            """,
            (client_id, idempotency_key),
        ).fetchone()
        if row is None:
            return None
        if row["request_fingerprint"] != request_fingerprint:
            raise ValueError("idempotency_conflict")
        return _result_from_json(row["result_json"])

    def cached_verification(
        self,
        *,
        credential_id: str,
        client_id: str,
        idempotency_key: str | None,
        request_fingerprint: str,
        clock: Callable[[], int],
    ) -> VerificationResult | None:
        if idempotency_key is None:
            return None
        with self._read() as database:
            self._require_operational(database)
            now = clock()
            credential = database.execute(
                """
                SELECT credentials.*, clients.status AS client_status
                FROM credentials
                JOIN clients USING (client_id)
                WHERE credential_id = ? AND role = 'verification'
                """,
                (credential_id,),
            ).fetchone()
            if (
                credential is None
                or credential["client_id"] != client_id
                or credential["client_status"] != "active"
                or not _credential_is_accepted(credential, now)
            ):
                return None
            return self._idempotent_result(
                database,
                client_id=client_id,
                idempotency_key=idempotency_key,
                request_fingerprint=request_fingerprint,
            )

    def activate_restored_backup(self, *, now: int) -> None:
        with self._write() as database:
            if not self._restore_required(database):
                raise ValueError("restore_activation_not_required")
            database.execute(
                "UPDATE clients SET status = 'revoked', revoked_at = COALESCE(revoked_at, ?)",
                (now,),
            )
            database.execute(
                """
                UPDATE credentials
                SET status = 'revoked', valid_until = ?, revoked_at = COALESCE(revoked_at, ?)
                """,
                (now, now),
            )
            database.execute(
                """
                UPDATE proofs
                SET expires_at = CASE WHEN expires_at < ? THEN expires_at ELSE ? END
                WHERE consumed_at IS NULL
                """,
                (now, now),
            )
            database.execute("DELETE FROM rate_events")
            self._insert_audit(
                database,
                now=now,
                kind="restore_activated",
                outcome="all_prior_authority_revoked",
            )
            database.execute(
                "UPDATE maintenance SET value_integer = 0 WHERE name = 'restore_required'"
            )

    @staticmethod
    def _restore_required(database: sqlite3.Connection) -> bool:
        row = database.execute(
            "SELECT value_integer FROM maintenance WHERE name = 'restore_required'"
        ).fetchone()
        return row is not None and int(row[0]) != 0

    @classmethod
    def _require_operational(cls, database: sqlite3.Connection) -> None:
        if cls._restore_required(database):
            raise RestoreRequiredError

    @staticmethod
    def _register_hash_key(
        database: sqlite3.Connection,
        kid: str,
        expected_check: str,
    ) -> None:
        row = database.execute(
            "SELECT key_check FROM hash_keys WHERE hash_kid = ?",
            (kid,),
        ).fetchone()
        if row is None:
            database.execute(
                "INSERT INTO hash_keys (hash_kid, key_check) VALUES (?, ?)",
                (kid, expected_check),
            )
            return
        if row["key_check"] != expected_check:
            raise StoreCorruptionError

    def _consume_rate_slot(
        self,
        database: sqlite3.Connection,
        *,
        client_id: str,
        operation: str,
        limit: int,
        now: int,
    ) -> None:
        cutoff = now - 60
        database.execute(
            "DELETE FROM rate_events WHERE occurred_at <= ?",
            (cutoff,),
        )
        row = database.execute(
            """
            SELECT COUNT(*) AS count, MIN(occurred_at) AS oldest
            FROM rate_events
            WHERE client_id = ? AND operation = ? AND occurred_at > ?
            """,
            (client_id, operation, cutoff),
        ).fetchone()
        count = int(row["count"])
        if count >= limit:
            oldest = int(row["oldest"])
            raise RateLimitError(min(60, max(1, oldest + 60 - now)))
        database.execute(
            "INSERT INTO rate_events (client_id, operation, occurred_at) VALUES (?, ?, ?)",
            (client_id, operation, now),
        )

    def _insert_verification(
        self,
        database: sqlite3.Connection,
        *,
        result: VerificationResult,
        credential_id: str,
        client_id: str,
        request_fingerprint: str,
        idempotency_key: str | None,
        now: int,
    ) -> None:
        database.execute(
            """
            INSERT INTO verifications (
                verification_id, client_id, credential_id, proof_tag,
                request_fingerprint, idempotency_key, result_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.witness.verification_id,
                client_id,
                credential_id,
                result.witness.proof_tag,
                request_fingerprint,
                idempotency_key,
                _result_json(result),
                now,
            ),
        )

    def _insert_audit(
        self,
        database: sqlite3.Connection,
        *,
        now: int,
        kind: str,
        outcome: str,
        client_id: str | None = None,
        credential_id: str | None = None,
        proof_tag: str | None = None,
        reason: str | None = None,
    ) -> None:
        database.execute(
            """
            INSERT INTO audit_events (
                event_id, created_at, kind, client_id, credential_id,
                proof_tag, outcome, reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"ae_{secrets.token_hex(16)}",
                now,
                kind,
                client_id,
                credential_id,
                proof_tag,
                outcome,
                reason,
            ),
        )


__all__ = ["ClientRecord", "CredentialRecord", "ProofRecord", "Store"]
