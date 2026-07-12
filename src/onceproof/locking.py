"""A host lock makes one HTTP process the sole owner of a SQLite ledger."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


class InstanceBusyError(OSError):
    """Name the active-owner state instead of leaking platform lock errors."""

    def __init__(self) -> None:
        super().__init__("instance_busy")


@contextmanager
def instance_lock(database_path: str | Path) -> Iterator[None]:
    database = Path(database_path).resolve()
    lock_path = database.with_name(f".{database.name}.instance.lock")
    with lock_path.open("a+b") as handle:
        os.chmod(lock_path, stat.S_IRUSR | stat.S_IWUSR)
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\x00")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise InstanceBusyError from error
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


__all__ = ["InstanceBusyError", "instance_lock"]
