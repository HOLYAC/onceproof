"""Instance lock tests pin single-server and offline root-key ownership."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from onceproof.locking import InstanceBusyError, instance_lock


class InstanceLockTests(unittest.TestCase):
    def test_second_owner_fails_without_waiting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "onceproof.sqlite3"
            database.touch()

            with instance_lock(database):
                with self.assertRaises(InstanceBusyError):
                    with instance_lock(database):
                        self.fail("the second owner crossed the lock")

            with instance_lock(database):
                pass


if __name__ == "__main__":
    unittest.main()
