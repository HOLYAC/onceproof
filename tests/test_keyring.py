"""Keyring tests make malformed and unsafe root-key state fail closed."""

from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from onceproof.errors import KeyringCommitUncertain
from onceproof.keyring import KeyRing


class KeyRingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.path = self.root / "keyring.json"

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def write(self, value: object) -> None:
        self.path.write_text(json.dumps(value), encoding="utf-8")
        self.path.chmod(0o600)

    def test_create_is_exclusive_and_unknown_key_is_an_honest_empty(self) -> None:
        keyring = KeyRing.create(self.path)

        self.assertIsNone(keyring.key_for("hk_missing"))
        with self.assertRaises(FileExistsError):
            KeyRing.create(self.path)

    def test_rotation_survives_reload_and_retirement_is_guarded(self) -> None:
        keyring = KeyRing.create(self.path)
        previous = keyring.current_kid
        current = keyring.rotate()
        reloaded = KeyRing.load(self.path)

        self.assertEqual(current, reloaded.current_kid)
        self.assertEqual({previous, current}, set(reloaded.key_ids))
        with self.assertRaisesRegex(ValueError, "cannot_retire_current_key"):
            reloaded.retire(current)
        with self.assertRaisesRegex(ValueError, "key_still_in_use"):
            reloaded.retire(previous, in_use=lambda _: True)
        self.assertIn(previous, reloaded.key_ids)
        reloaded.retire(previous)
        self.assertEqual((current,), KeyRing.load(self.path).key_ids)
        with self.assertRaises(KeyError):
            reloaded.retire(previous)

    def test_stale_writer_cannot_erase_a_concurrent_rotation(self) -> None:
        first = KeyRing.create(self.path)
        stale = KeyRing.load(self.path)
        new_kid = first.rotate()

        with self.assertRaisesRegex(ValueError, "keyring_changed_on_disk"):
            stale.rotate()

        self.assertIn(new_kid, KeyRing.load(self.path).key_ids)

    def test_post_replace_sync_failure_reloads_the_committed_disk_generation(self) -> None:
        keyring = KeyRing.create(self.path)
        previous = keyring.current_kid

        with patch(
            "onceproof.keyring._fsync_parent",
            side_effect=[None, OSError("directory sync failed")],
        ), self.assertRaises(KeyringCommitUncertain):
            keyring.rotate()

        reloaded = KeyRing.load(self.path)
        self.assertEqual(reloaded.current_kid, keyring.current_kid)
        self.assertEqual(reloaded.key_ids, keyring.key_ids)
        self.assertNotEqual(previous, keyring.current_kid)

    def test_failed_pair_backup_removes_the_unpaired_database_copy(self) -> None:
        keyring = KeyRing.create(self.path)
        database_backup = self.root / "backup.sqlite3"

        def write_database() -> Path:
            database_backup.write_bytes(b"database")
            return database_backup

        with patch("onceproof.keyring._write_exclusive", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(OSError, "disk full"):
                keyring.backup_with(self.root / "backup.keyring.json", write_database)

        self.assertFalse(database_backup.exists())

    def test_unreadable_json_and_unknown_shape_are_rejected(self) -> None:
        self.path.write_text("{", encoding="utf-8")
        self.path.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "unreadable_keyring"):
            KeyRing.load(self.path)

        self.write({"version": 1, "current_kid": "hk_a", "keys": {}, "extra": True})
        with self.assertRaisesRegex(ValueError, "invalid_keyring_shape"):
            KeyRing.load(self.path)

        self.path.write_text(
            '{"version":1,"version":1,"current_kid":"hk_a","keys":{}}',
            encoding="utf-8",
        )
        self.path.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "duplicate_keyring_field:version"):
            KeyRing.load(self.path)

    def test_version_current_key_and_key_ids_are_validated(self) -> None:
        encoded = base64.urlsafe_b64encode(bytes(32)).decode("ascii").rstrip("=")
        self.write({"version": 2, "current_kid": "hk_a", "keys": {"hk_a": encoded}})
        with self.assertRaisesRegex(ValueError, "unsupported_keyring_version"):
            KeyRing.load(self.path)

        self.write({"version": 1, "current_kid": "bad", "keys": {"hk_a": encoded}})
        with self.assertRaisesRegex(ValueError, "invalid_current_kid"):
            KeyRing.load(self.path)

        self.write({"version": 1, "current_kid": "hk_a", "keys": {"bad": encoded}})
        with self.assertRaisesRegex(ValueError, "invalid_kid"):
            KeyRing.load(self.path)

        self.write({"version": 1, "current_kid": "hk_missing", "keys": {"hk_a": encoded}})
        with self.assertRaisesRegex(ValueError, "current_key_missing"):
            KeyRing.load(self.path)

    def test_empty_badly_encoded_and_wrong_length_keys_are_rejected(self) -> None:
        self.write({"version": 1, "current_kid": "hk_a", "keys": {}})
        with self.assertRaisesRegex(ValueError, "empty_keyring"):
            KeyRing.load(self.path)

        self.write({"version": 1, "current_kid": "hk_a", "keys": {"hk_a": "***"}})
        with self.assertRaisesRegex(ValueError, "invalid_key_encoding"):
            KeyRing.load(self.path)

        short = base64.urlsafe_b64encode(b"short").decode("ascii").rstrip("=")
        self.write({"version": 1, "current_kid": "hk_a", "keys": {"hk_a": short}})
        with self.assertRaisesRegex(ValueError, "invalid_key_length"):
            KeyRing.load(self.path)


if __name__ == "__main__":
    unittest.main()
