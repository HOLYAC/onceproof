"""Configuration makes every network and secret-storage decision explicit."""

from __future__ import annotations

import ipaddress
import json
import os
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .keyring import KeyRing
from .store import Store

_CONFIG_VERSION = 1
_CONFIG_FIELDS = frozenset(
    {
        "version",
        "database",
        "keyring",
        "host",
        "port",
        "max_request_bytes",
        "allow_public_bind",
    }
)
_DEFAULT_MAX_REQUEST_BYTES = 16_384


@dataclass(frozen=True)
class InstanceConfig:
    """Carry values read from one validated TOML instance file."""

    config_path: Path
    database_path: Path
    keyring_path: Path
    host: str
    port: int
    max_request_bytes: int
    allow_public_bind: bool


@dataclass(frozen=True)
class InitializedInstance:
    """Return paths created by an all-or-nothing local initialization."""

    root: Path
    config_path: Path
    database_path: Path
    keyring_path: Path


def _write_exclusive(path: Path, text: str, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    os.chmod(path, mode)


def _strict_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"invalid_{field}")
    return value


def _strict_bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"invalid_{field}")
    return value


def _strict_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"invalid_{field}")
    return value


def _resolved_child(base: Path, value: Any, field: str) -> Path:
    text = _strict_text(value, field)
    path = Path(text)
    return (path if path.is_absolute() else base / path).absolute()


def _is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _render_config(host: str, port: int, allow_public_bind: bool) -> str:
    return (
        "version = 1\n"
        'database = "onceproof.sqlite3"\n'
        'keyring = "keyring.json"\n'
        f"host = {json.dumps(host)}\n"
        f"port = {port}\n"
        f"max_request_bytes = {_DEFAULT_MAX_REQUEST_BYTES}\n"
        f"allow_public_bind = {str(allow_public_bind).lower()}\n"
    )


def _validate_keyring_file(path: Path) -> None:
    if not path.exists():
        raise ValueError("keyring_missing")
    if path.is_symlink() or not path.is_file():
        raise ValueError("keyring_not_regular")
    if os.name != "nt":
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise ValueError("keyring_permissions_too_open")
    KeyRing.load(path)


def _validate_config_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError("config_not_regular")
    if os.name != "nt":
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ValueError("config_permissions_too_open")


def _validate_parent_integrity(path: Path, field: str) -> None:
    if os.name == "nt":
        return
    mode = stat.S_IMODE(path.parent.stat().st_mode)
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError(f"{field}_parent_permissions_too_open")


def initialize_instance(
    root: str | Path,
    *,
    host: str = "127.0.0.1",
    port: int = 8787,
    allow_public_bind: bool = False,
) -> InitializedInstance:
    accepted_host = _strict_text(host, "host")
    accepted_port = _strict_int(port, "port", 1, 65_535)
    accepted_public_bind = _strict_bool(allow_public_bind, "allow_public_bind")
    if not _is_loopback_host(accepted_host) and not accepted_public_bind:
        raise ValueError("public_bind_not_allowed")
    target = Path(root).resolve()
    target.mkdir(parents=True, exist_ok=False, mode=0o700)
    os.chmod(target, stat.S_IRWXU)
    config_path = target / "onceproof.toml"
    keyring_path = target / "keyring.json"
    database_path = target / "onceproof.sqlite3"
    try:
        KeyRing.create(keyring_path)
        Store.create(database_path)
        _write_exclusive(
            config_path,
            _render_config(accepted_host, accepted_port, accepted_public_bind),
            0o600,
        )
    except BaseException:
        config_path.unlink(missing_ok=True)
        keyring_path.unlink(missing_ok=True)
        for suffix in ("", "-journal", "-shm", "-wal"):
            database_path.with_name(database_path.name + suffix).unlink(missing_ok=True)
        target.rmdir()
        raise
    return InitializedInstance(
        root=target,
        config_path=config_path,
        database_path=database_path,
        keyring_path=keyring_path,
    )


def load_config(path: str | Path) -> InstanceConfig:
    declared_config_path = Path(path).absolute()
    if declared_config_path.exists():
        _validate_config_file(declared_config_path)
        _validate_parent_integrity(declared_config_path, "config")
    config_path = declared_config_path.resolve()
    try:
        with config_path.open("rb") as handle:
            raw = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ValueError("unreadable_config") from error
    if not isinstance(raw, dict):
        raise ValueError("invalid_config")
    unknown = set(raw) - _CONFIG_FIELDS
    missing = _CONFIG_FIELDS - set(raw)
    if unknown:
        raise ValueError(f"unknown_config_fields:{','.join(sorted(unknown))}")
    if missing:
        raise ValueError(f"missing_config_fields:{','.join(sorted(missing))}")
    if raw["version"] != _CONFIG_VERSION:
        raise ValueError("unsupported_config_version")

    base = config_path.parent
    database_path = _resolved_child(base, raw["database"], "database")
    keyring_path = _resolved_child(base, raw["keyring"], "keyring")
    host = _strict_text(raw["host"], "host")
    port = _strict_int(raw["port"], "port", 1, 65_535)
    max_request_bytes = _strict_int(raw["max_request_bytes"], "max_request_bytes", 1_024, 1_048_576)
    allow_public_bind = _strict_bool(raw["allow_public_bind"], "allow_public_bind")

    if len({config_path, database_path.resolve(), keyring_path.resolve()}) != 3:
        raise ValueError("config_path_collision")
    if not _is_loopback_host(host) and not allow_public_bind:
        raise ValueError("public_bind_not_allowed")
    _validate_parent_integrity(database_path, "database")
    _validate_parent_integrity(keyring_path, "keyring")
    _validate_keyring_file(keyring_path)
    return InstanceConfig(
        config_path=config_path,
        database_path=database_path,
        keyring_path=keyring_path,
        host=host,
        port=port,
        max_request_bytes=max_request_bytes,
        allow_public_bind=allow_public_bind,
    )


__all__ = ["InitializedInstance", "InstanceConfig", "initialize_instance", "load_config"]
