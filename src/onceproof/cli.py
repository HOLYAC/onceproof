"""The CLI keeps administrative mutation local and credentials one-time."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import stat
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import __version__
from .config import InstanceConfig, initialize_instance, load_config
from .crypto import key_check
from .errors import KeyringCommitUncertain, RestoreRequiredError, StoreCorruptionError
from .http import serve
from .keyring import KeyRing
from .locking import instance_lock
from .model import ClientCredentials, PreparedCredential
from .service import OnceproofService

_BACKUP_DATABASE_NAME = "onceproof.sqlite3"
_BACKUP_KEYRING_NAME = "keyring.json"
_BACKUP_MANIFEST_NAME = "manifest.json"
_BACKUP_INCOMPLETE_NAME = ".onceproof-incomplete"


def _json_line(value: dict[str, Any]) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def _fsync_parent(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_secret_json(path: Path, value: dict[str, Any]) -> None:
    payload = (_json_line(value) + "\n").encode("utf-8")
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.pending")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR)
        os.link(temporary, path)
        _fsync_parent(path)
    finally:
        temporary.unlink(missing_ok=True)


def _client_credentials_payload(credentials: ClientCredentials) -> dict[str, Any]:
    return {
        "client_id": credentials.client_id,
        "issuance_credential_id": credentials.issuance_credential_id,
        "issuance_secret": credentials.issuance_secret,
        "verification_credential_id": credentials.verification_credential_id,
        "verification_secret": credentials.verification_secret,
    }


def _rotated_credential_payload(rotated: PreparedCredential) -> dict[str, Any]:
    return {
        "client_id": rotated.client_id,
        "credential_id": rotated.credential_id,
        "role": rotated.role,
        "secret": rotated.secret,
    }


def _credentials_target(value: str) -> Path:
    if value == "-":
        raise ValueError("credentials_output_must_be_file")
    path = Path(value).resolve()
    if path.exists():
        raise ValueError("credentials_output_exists")
    if not path.parent.is_dir():
        raise ValueError("credentials_output_parent_missing")
    return path


def _service(config: InstanceConfig) -> OnceproofService:
    return OnceproofService(
        database_path=config.database_path,
        keyring=KeyRing.load(config.keyring_path),
    )


def _init(args: argparse.Namespace) -> dict[str, Any]:
    initialized = initialize_instance(
        args.directory,
        host=args.host,
        port=args.port,
        allow_public_bind=args.allow_public_bind,
    )
    return {
        "status": "initialized",
        "config_path": str(initialized.config_path),
        "database_path": str(initialized.database_path),
        "keyring_path": str(initialized.keyring_path),
    }


def _check(args: argparse.Namespace) -> dict[str, Any]:
    config = load_config(args.config)
    instance = _service(config)
    if not instance.ready():
        raise ValueError("instance_not_ready")
    return {
        "status": "ready",
        "database_path": str(config.database_path),
        "current_hash_kid": instance.keyring.current_kid,
    }


def _serve(args: argparse.Namespace) -> dict[str, Any]:
    config = load_config(args.config)
    with instance_lock(config.database_path):
        instance = _service(config)
        serve(
            service=instance,
            host=config.host,
            port=config.port,
            max_request_bytes=config.max_request_bytes,
            instance_lock_held=True,
        )
    return {"status": "stopped"}


def _client_create(args: argparse.Namespace) -> dict[str, Any]:
    target = _credentials_target(args.credentials_out)
    config = load_config(args.config)
    credentials = _service(config).create_client(
        name=args.name,
        allowed_audiences=tuple(args.audience),
        proof_ttl_seconds=args.ttl_seconds,
        issue_limit_per_minute=args.issue_limit_per_minute,
        verify_limit_per_minute=args.verify_limit_per_minute,
        credential_sink=lambda prepared: _write_secret_json(
            target,
            _client_credentials_payload(prepared),
        ),
    )
    return {
        "status": "created",
        "client_id": credentials.client_id,
        "credentials_path": str(target),
    }


def _client_rotate(args: argparse.Namespace) -> dict[str, Any]:
    target = _credentials_target(args.credentials_out)
    config = load_config(args.config)
    rotated = _service(config).rotate_credential(
        client_id=args.client_id,
        role=args.role,
        grace_seconds=args.grace_seconds,
        credential_sink=lambda prepared: _write_secret_json(
            target,
            _rotated_credential_payload(prepared),
        ),
    )
    return {
        "status": "rotated",
        "client_id": rotated.client_id,
        "credential_id": rotated.credential_id,
        "role": rotated.role,
        "credentials_path": str(target),
    }


def _client_revoke(args: argparse.Namespace) -> dict[str, Any]:
    if not args.yes_revoke:
        raise ValueError("revocation_confirmation_required")
    config = load_config(args.config)
    changed = _service(config).revoke_client(args.client_id)
    return {
        "status": "revoked" if changed else "already_revoked",
        "client_id": args.client_id,
    }


def _client_inspect(args: argparse.Namespace) -> dict[str, Any]:
    config = load_config(args.config)
    instance = _service(config)
    client = instance.store.client(args.client_id)
    if client is None:
        raise KeyError(args.client_id)
    credentials = instance.store.credentials_for_client(client.client_id)
    return {
        "status": "ok",
        "client": {
            "client_id": client.client_id,
            "name": client.name,
            "status": client.status,
            "allowed_audiences": list(client.allowed_audiences),
            "proof_ttl_seconds": client.proof_ttl_seconds,
            "issue_limit_per_minute": client.issue_limit_per_minute,
            "verify_limit_per_minute": client.verify_limit_per_minute,
        },
        "credentials": [
            {
                "credential_id": credential.credential_id,
                "role": credential.role,
                "status": credential.status,
                "hash_kid": credential.hash_kid,
                "valid_until": credential.valid_until,
            }
            for credential in credentials
        ],
    }


def _key_rotate(args: argparse.Namespace) -> dict[str, Any]:
    config = load_config(args.config)
    with instance_lock(config.database_path):
        keyring = KeyRing.load(config.keyring_path)
        kid = keyring.rotate()
    return {"status": "rotated", "current_hash_kid": kid}


def _key_retire(args: argparse.Namespace) -> dict[str, Any]:
    config = load_config(args.config)
    with instance_lock(config.database_path):
        instance = _service(config)
        instance.retire_hash_key(args.kid)
    return {"status": "retired", "hash_kid": args.kid}


def _cleanup(args: argparse.Namespace) -> dict[str, Any]:
    config = load_config(args.config)
    removed = _service(config).cleanup()
    return {"status": "cleaned", "removed": removed}


def _doctor(args: argparse.Namespace) -> dict[str, Any]:
    config = load_config(args.config)
    instance = _service(config)
    integrity = instance.store.integrity_check()
    referenced = instance.store.referenced_hash_kids()
    available = instance.keyring.key_ids
    ready = instance.ready() and integrity == "ok"
    return {
        "status": "healthy" if ready else "unhealthy",
        "ready": ready,
        "integrity": integrity,
        "database": instance.store.status(),
        "current_hash_kid": instance.keyring.current_kid,
        "available_hash_kids": list(available),
        "referenced_hash_kids": list(referenced),
        "missing_hash_kids": sorted(set(referenced) - set(available)),
    }


def _key_inspect(args: argparse.Namespace) -> dict[str, Any]:
    config = load_config(args.config)
    keyring = KeyRing.load(config.keyring_path)
    return {
        "status": "ok",
        "current_hash_kid": keyring.current_kid,
        "hash_kids": list(keyring.key_ids),
    }


def _db_integrity(args: argparse.Namespace) -> dict[str, Any]:
    config = load_config(args.config)
    result = _service(config).store.integrity_check()
    return {"status": "ok" if result == "ok" else "failed", "integrity": result}


def _prepare_backup_directory(path: Path) -> None:
    marker = path / _BACKUP_INCOMPLETE_NAME
    if path.exists():
        if not path.is_dir():
            raise ValueError("backup_output_exists")
        if (path / _BACKUP_MANIFEST_NAME).is_file():
            raise ValueError("backup_output_exists")
        entries = tuple(path.iterdir())
        allowed = {
            _BACKUP_DATABASE_NAME,
            _BACKUP_KEYRING_NAME,
            _BACKUP_INCOMPLETE_NAME,
        }
        temporary_prefixes = (
            f".{_BACKUP_INCOMPLETE_NAME}.",
            f".{_BACKUP_MANIFEST_NAME}.",
        )
        if entries and (
            not marker.is_file()
            and not all(
                entry.name.startswith(temporary_prefixes) and entry.name.endswith(".pending")
                for entry in entries
            )
        ):
            raise ValueError("incomplete_backup_not_reconcilable")
        if any(
            entry.name not in allowed
            and not (
                entry.name.startswith(temporary_prefixes)
                and entry.name.endswith(".pending")
            )
            for entry in entries
        ):
            raise ValueError("incomplete_backup_not_reconcilable")
        for entry in entries:
            if not entry.is_file() or entry.is_symlink():
                raise ValueError("incomplete_backup_not_reconcilable")
            entry.unlink()
        path.rmdir()
    path.mkdir(mode=0o700)
    os.chmod(path, stat.S_IRWXU)
    try:
        _write_secret_json(marker, {"format": 1, "state": "incomplete"})
    except BaseException:
        path.rmdir()
        raise


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate_backup_manifest_field:{key}")
        value[key] = item
    return value


def _verify_backup_directory(path: Path) -> dict[str, Path]:
    if path.is_symlink() or not path.is_dir():
        raise ValueError("backup_directory_not_regular")
    manifest_path = path / _BACKUP_MANIFEST_NAME
    database_path = path / _BACKUP_DATABASE_NAME
    keyring_path = path / _BACKUP_KEYRING_NAME
    try:
        manifest = json.loads(
            manifest_path.read_text(encoding="utf-8"),
            object_pairs_hook=_manifest_without_duplicates,
        )
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("backup_manifest_unreadable") from error
    expected_shape = {"format", "database", "keyring"}
    if not isinstance(manifest, dict) or set(manifest) != expected_shape or manifest["format"] != 1:
        raise ValueError("backup_manifest_invalid")
    for field, expected_name, target in (
        ("database", _BACKUP_DATABASE_NAME, database_path),
        ("keyring", _BACKUP_KEYRING_NAME, keyring_path),
    ):
        record = manifest[field]
        if (
            not isinstance(record, dict)
            or set(record) != {"name", "sha256"}
            or record["name"] != expected_name
            or not isinstance(record["sha256"], str)
            or len(record["sha256"]) != 64
            or target.is_symlink()
            or not target.is_file()
        ):
            raise ValueError("backup_manifest_invalid")
        if not hmac.compare_digest(_sha256(target), record["sha256"]):
            raise ValueError(f"backup_checksum_mismatch:{field}")

    store = OnceproofService(
        database_path=database_path,
        keyring=KeyRing.load(keyring_path),
    ).store
    if store.integrity_check() != "ok" or not store.status()["restore_required"]:
        raise ValueError("backup_not_recovery_sealed")
    checks = store.referenced_hash_key_checks()
    keyring = KeyRing.load(keyring_path)
    for kid, expected_check in checks.items():
        key = keyring.key_for(kid)
        if key is None or not hmac.compare_digest(key_check(key), expected_check):
            raise ValueError("backup_keyring_mismatch")
    return {
        "database": database_path,
        "keyring": keyring_path,
        "manifest": manifest_path,
    }


def _db_backup(args: argparse.Namespace) -> dict[str, Any]:
    backup_directory = Path(args.output).resolve()
    _prepare_backup_directory(backup_directory)
    database_target = backup_directory / _BACKUP_DATABASE_NAME
    keyring_target = backup_directory / _BACKUP_KEYRING_NAME
    manifest_target = backup_directory / _BACKUP_MANIFEST_NAME
    config = load_config(args.config)
    instance = _service(config)
    keyring_backup = instance.keyring.backup_with(
        keyring_target,
        lambda: instance.store.backup(database_target),
    )
    _write_secret_json(
        manifest_target,
        {
            "format": 1,
            "database": {
                "name": _BACKUP_DATABASE_NAME,
                "sha256": _sha256(database_target),
            },
            "keyring": {
                "name": _BACKUP_KEYRING_NAME,
                "sha256": _sha256(keyring_target),
            },
        },
    )
    (backup_directory / _BACKUP_INCOMPLETE_NAME).unlink()
    _fsync_parent(manifest_target)
    _verify_backup_directory(backup_directory)
    return {
        "status": "backed_up",
        "backup_directory": str(backup_directory),
        "database_backup_path": str(database_target),
        "keyring_backup_path": str(keyring_backup),
        "manifest_path": str(manifest_target),
    }


def _db_verify_backup(args: argparse.Namespace) -> dict[str, Any]:
    paths = _verify_backup_directory(Path(args.input).resolve())
    return {
        "status": "valid",
        "database_backup_path": str(paths["database"]),
        "keyring_backup_path": str(paths["keyring"]),
        "manifest_path": str(paths["manifest"]),
    }


def _db_activate_restore(args: argparse.Namespace) -> dict[str, Any]:
    if not args.yes_invalidate_prior_authority:
        raise ValueError("restore_activation_confirmation_required")
    config = load_config(args.config)
    with instance_lock(config.database_path):
        instance = _service(config)
        instance.activate_restored_backup()
    return {"status": "activated", "prior_authority": "revoked"}


def _add_config_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", required=True, help="Path to onceproof.toml")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="onceproof",
        description="Issue and atomically verify opaque one-time application proofs.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    init_parser = commands.add_parser("init", help="Create a local-only instance")
    init_parser.add_argument("directory", help="New instance directory")
    init_parser.add_argument("--host", default="127.0.0.1")
    init_parser.add_argument("--port", type=int, default=8787)
    init_parser.add_argument("--allow-public-bind", action="store_true")
    init_parser.set_defaults(handler=_init)

    check_parser = commands.add_parser("check", help="Validate configuration, keyring, and database")
    _add_config_argument(check_parser)
    check_parser.set_defaults(handler=_check)

    doctor_parser = commands.add_parser("doctor", help="Inspect schema, pragmas, key references, and integrity")
    _add_config_argument(doctor_parser)
    doctor_parser.set_defaults(handler=_doctor)

    serve_parser = commands.add_parser("serve", help="Run the HTTP issuer and verifier")
    _add_config_argument(serve_parser)
    serve_parser.set_defaults(handler=_serve)

    client_parser = commands.add_parser("client", help="Manage role-separated client credentials")
    client_commands = client_parser.add_subparsers(dest="client_command", required=True)

    create_parser = client_commands.add_parser("create", help="Create a client")
    _add_config_argument(create_parser)
    create_parser.add_argument("--name", required=True)
    create_parser.add_argument("--audience", required=True, action="append")
    create_parser.add_argument("--ttl-seconds", type=int, default=120)
    create_parser.add_argument("--issue-limit-per-minute", type=int, default=120)
    create_parser.add_argument("--verify-limit-per-minute", type=int, default=600)
    create_parser.add_argument(
        "--credentials-out",
        required=True,
        help="New 0600 JSON path; stdout delivery is refused",
    )
    create_parser.set_defaults(handler=_client_create)

    rotate_parser = client_commands.add_parser("rotate", help="Rotate one client role")
    _add_config_argument(rotate_parser)
    rotate_parser.add_argument("--client-id", required=True)
    rotate_parser.add_argument("--role", choices=("issuance", "verification"), required=True)
    rotate_parser.add_argument("--grace-seconds", type=int, default=300)
    rotate_parser.add_argument(
        "--credentials-out",
        required=True,
        help="New 0600 JSON path; stdout delivery is refused",
    )
    rotate_parser.set_defaults(handler=_client_rotate)

    revoke_parser = client_commands.add_parser("revoke", help="Revoke a client and both roles")
    _add_config_argument(revoke_parser)
    revoke_parser.add_argument("--client-id", required=True)
    revoke_parser.add_argument(
        "--yes-revoke",
        action="store_true",
        help="Confirm that outstanding proofs and both credentials stop working",
    )
    revoke_parser.set_defaults(handler=_client_revoke)

    inspect_parser = client_commands.add_parser("inspect", help="Inspect non-secret client state")
    _add_config_argument(inspect_parser)
    inspect_parser.add_argument("--client-id", required=True)
    inspect_parser.set_defaults(handler=_client_inspect)

    key_parser = commands.add_parser("key", help="Manage the keyed-digest root keyring")
    key_commands = key_parser.add_subparsers(dest="key_command", required=True)
    key_inspect_parser = key_commands.add_parser("inspect", help="List non-secret hash key identifiers")
    _add_config_argument(key_inspect_parser)
    key_inspect_parser.set_defaults(handler=_key_inspect)
    key_rotate_parser = key_commands.add_parser("rotate", help="Add a new current hash key")
    _add_config_argument(key_rotate_parser)
    key_rotate_parser.set_defaults(handler=_key_rotate)
    key_retire_parser = key_commands.add_parser("retire", help="Remove an unused previous hash key")
    _add_config_argument(key_retire_parser)
    key_retire_parser.add_argument("--kid", required=True)
    key_retire_parser.set_defaults(handler=_key_retire)

    cleanup_parser = commands.add_parser("cleanup", help="Remove expired retained state")
    _add_config_argument(cleanup_parser)
    cleanup_parser.set_defaults(handler=_cleanup)

    database_parser = commands.add_parser("db", help="Inspect and back up the SQLite ledger")
    database_commands = database_parser.add_subparsers(dest="database_command", required=True)
    integrity_parser = database_commands.add_parser("integrity-check", help="Run SQLite integrity_check")
    _add_config_argument(integrity_parser)
    integrity_parser.set_defaults(handler=_db_integrity)
    backup_parser = database_commands.add_parser("backup", help="Create a consistent SQLite backup")
    _add_config_argument(backup_parser)
    backup_parser.add_argument("--output", required=True, help="New or recoverable backup directory")
    backup_parser.set_defaults(handler=_db_backup)
    verify_backup_parser = database_commands.add_parser(
        "verify-backup",
        help="Verify a sealed database/keyring backup directory",
    )
    verify_backup_parser.add_argument("--input", required=True)
    verify_backup_parser.set_defaults(handler=_db_verify_backup)
    activate_parser = database_commands.add_parser(
        "activate-restore",
        help="Revoke prior authority before opening a restored backup",
    )
    _add_config_argument(activate_parser)
    activate_parser.add_argument("--yes-invalidate-prior-authority", action="store_true")
    activate_parser.set_defaults(handler=_db_activate_restore)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    handler: Callable[[argparse.Namespace], dict[str, Any]] = args.handler
    try:
        result = handler(args)
    except FileExistsError:
        print(_json_line({"error": "instance_exists"}))
        return 2
    except KeyError as error:
        print(_json_line({"error": "not_found", "id": str(error.args[0])}))
        return 2
    except (
        KeyringCommitUncertain,
        OSError,
        PermissionError,
        RestoreRequiredError,
        StoreCorruptionError,
        ValueError,
    ) as error:
        code = str(error) or error.__class__.__name__.lower()
        print(_json_line({"error": code}))
        return 2
    print(_json_line(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())


__all__ = ["main"]
