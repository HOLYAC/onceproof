"""A small file-backed keyring removes root secrets from source and SQLite."""

from __future__ import annotations

import base64
import json
import os
import secrets
import stat
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .errors import KeyringCommitUncertain

_KEY_BYTES = 32
_KEYRING_VERSION = 1
_TOP_LEVEL_FIELDS = frozenset({"version", "current_kid", "keys"})


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate_keyring_field:{key}")
        value[key] = item
    return value


def _encode_key(key: bytes) -> str:
    return base64.urlsafe_b64encode(key).decode("ascii").rstrip("=")


def _decode_key(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        key = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("invalid_key_encoding") from error
    if len(key) != _KEY_BYTES:
        raise ValueError("invalid_key_length")
    return key


def _new_kid(existing: set[str]) -> str:
    while True:
        kid = f"hk_{secrets.token_hex(8)}"
        if kid not in existing:
            return kid


def _serialized_payload(current_kid: str, keys: dict[str, bytes]) -> bytes:
    payload = {
        "version": _KEYRING_VERSION,
        "current_kid": current_kid,
        "keys": {kid: _encode_key(key) for kid, key in sorted(keys.items())},
    }
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _fsync_parent(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDWR)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_exclusive(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        _fsync_parent(path)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _replace_atomically(path: Path, payload: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    _write_exclusive(temporary, payload)
    try:
        os.replace(temporary, path)
        try:
            _fsync_file(path)
            _fsync_parent(path)
        except OSError as error:
            raise KeyringCommitUncertain from error
    finally:
        temporary.unlink(missing_ok=True)


def _parse_payload(value: Any) -> tuple[str, dict[str, bytes]]:
    if not isinstance(value, dict) or set(value) != _TOP_LEVEL_FIELDS:
        raise ValueError("invalid_keyring_shape")
    if value["version"] != _KEYRING_VERSION:
        raise ValueError("unsupported_keyring_version")
    current_kid = value["current_kid"]
    encoded_keys = value["keys"]
    if not isinstance(current_kid, str) or not current_kid.startswith("hk_"):
        raise ValueError("invalid_current_kid")
    if not isinstance(encoded_keys, dict) or not encoded_keys:
        raise ValueError("empty_keyring")

    keys: dict[str, bytes] = {}
    for kid, encoded_key in encoded_keys.items():
        if not isinstance(kid, str) or not kid.startswith("hk_"):
            raise ValueError("invalid_kid")
        if not isinstance(encoded_key, str):
            raise ValueError("invalid_key_encoding")
        keys[kid] = _decode_key(encoded_key)
    if current_kid not in keys:
        raise ValueError("current_key_missing")
    return current_kid, keys


def _read_payload(path: Path) -> tuple[str, dict[str, bytes]]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_object_without_duplicates,
        )
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("unreadable_keyring") from error
    return _parse_payload(value)


@contextmanager
def _exclusive_file_lock(path: Path) -> Iterator[None]:
    lock_path = path.with_name(f".{path.name}.lock")
    with lock_path.open("a+b") as handle:
        os.chmod(lock_path, stat.S_IRUSR | stat.S_IWUSR)
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\x00")
            handle.flush()
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class KeyRing:
    """Keep keyed-digest material in one permission-restricted local file."""

    def __init__(self, path: Path, current_kid: str, keys: dict[str, bytes]) -> None:
        self.path = path
        self._current_kid = current_kid
        self._keys = dict(keys)
        self._lock = threading.RLock()

    @classmethod
    def create(cls, path: str | Path) -> KeyRing:
        target = Path(path).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        kid = _new_kid(set())
        keys = {kid: secrets.token_bytes(_KEY_BYTES)}
        _write_exclusive(target, _serialized_payload(kid, keys))
        return cls(target, kid, keys)

    @classmethod
    def load(cls, path: str | Path) -> KeyRing:
        declared = Path(path).absolute()
        if declared.is_symlink() or not declared.is_file():
            raise ValueError("keyring_not_regular")
        if os.name != "nt":
            mode = stat.S_IMODE(declared.stat().st_mode)
            parent_mode = stat.S_IMODE(declared.parent.stat().st_mode)
            if mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise ValueError("keyring_permissions_too_open")
            if parent_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise ValueError("keyring_parent_permissions_too_open")
        target = declared.resolve()
        current_kid, keys = _read_payload(target)
        return cls(target, current_kid, keys)

    @property
    def current_kid(self) -> str:
        with self._lock:
            return self._current_kid

    @property
    def key_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._keys))

    def current_key(self) -> tuple[str, bytes]:
        with self._lock:
            return self._current_kid, self._keys[self._current_kid]

    def key_for(self, kid: str) -> bytes | None:
        with self._lock:
            key = self._keys.get(kid)
            return bytes(key) if key is not None else None

    @contextmanager
    def stable(self) -> Iterator[None]:
        """Hold one on-disk generation stable across a dependent DB commit."""

        with self._lock:
            with _exclusive_file_lock(self.path):
                current_kid, disk_keys = _read_payload(self.path)
                if current_kid != self._current_kid or disk_keys != self._keys:
                    raise ValueError("keyring_changed_on_disk")
                yield

    def _replace_and_reload(self, current_kid: str, keys: dict[str, bytes]) -> None:
        try:
            _replace_atomically(self.path, _serialized_payload(current_kid, keys))
        except BaseException:
            try:
                self._current_kid, self._keys = _read_payload(self.path)
            except BaseException as reload_error:
                raise KeyringCommitUncertain from reload_error
            raise
        try:
            self._current_kid, self._keys = _read_payload(self.path)
        except BaseException as reload_error:
            raise KeyringCommitUncertain from reload_error

    def rotate(self) -> str:
        with self._lock:
            with _exclusive_file_lock(self.path):
                current_kid, disk_keys = _read_payload(self.path)
                if current_kid != self._current_kid or disk_keys != self._keys:
                    raise ValueError("keyring_changed_on_disk")
                kid = _new_kid(set(self._keys))
                keys = {**self._keys, kid: secrets.token_bytes(_KEY_BYTES)}
                self._replace_and_reload(kid, keys)
                return kid

    def retire(
        self,
        kid: str,
        *,
        in_use: Callable[[str], bool] | None = None,
    ) -> None:
        with self._lock:
            with _exclusive_file_lock(self.path):
                current_kid, disk_keys = _read_payload(self.path)
                if current_kid != self._current_kid or disk_keys != self._keys:
                    raise ValueError("keyring_changed_on_disk")
                if kid == self._current_kid:
                    raise ValueError("cannot_retire_current_key")
                if kid not in self._keys:
                    raise KeyError(kid)
                if in_use is not None and in_use(kid):
                    raise ValueError("key_still_in_use")
                keys = {key_id: key for key_id, key in self._keys.items() if key_id != kid}
                self._replace_and_reload(self._current_kid, keys)

    def backup_with(
        self,
        destination: str | Path,
        database_backup: Callable[[], Path],
    ) -> Path:
        target = Path(destination).resolve()
        if target == self.path:
            raise ValueError("keyring_backup_path_collision")
        if target.exists():
            raise FileExistsError(target)
        if not target.parent.is_dir():
            raise ValueError("keyring_backup_parent_missing")

        with self._lock:
            with _exclusive_file_lock(self.path):
                current_kid, disk_keys = _read_payload(self.path)
                if current_kid != self._current_kid or disk_keys != self._keys:
                    raise ValueError("keyring_changed_on_disk")
                database_path = database_backup()
                try:
                    _write_exclusive(target, _serialized_payload(current_kid, disk_keys))
                except BaseException:
                    database_path.unlink(missing_ok=True)
                    raise
        return target


__all__ = ["KeyRing"]
