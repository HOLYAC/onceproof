"""Configuration tests make insecure startup an explicit operator decision."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from onceproof.config import InstanceConfig, initialize_instance, load_config
from onceproof.keyring import KeyRing


class ConfigurationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_initialize_creates_loadable_local_only_instance(self) -> None:
        initialized = initialize_instance(self.root / "instance")
        loaded = load_config(initialized.config_path)

        self.assertEqual("127.0.0.1", loaded.host)
        self.assertFalse(loaded.allow_public_bind)
        self.assertTrue(loaded.keyring_path.is_file())
        self.assertEqual(initialized.keyring_path, loaded.keyring_path)
        self.assertTrue(KeyRing.load(loaded.keyring_path).current_kid.startswith("hk_"))

    @unittest.skipIf(os.name == "nt", "Windows chmod does not model the file ACL")
    def test_keyring_is_owner_read_write_only(self) -> None:
        initialized = initialize_instance(self.root / "instance")

        mode = stat.S_IMODE(initialized.keyring_path.stat().st_mode)

        self.assertEqual(0o600, mode)

    def test_existing_instance_is_never_overwritten(self) -> None:
        initialize_instance(self.root / "instance")

        with self.assertRaises(FileExistsError):
            initialize_instance(self.root / "instance")

    def test_public_bind_requires_explicit_configuration(self) -> None:
        initialized = initialize_instance(self.root / "instance")
        text = initialized.config_path.read_text(encoding="utf-8")
        initialized.config_path.write_text(
            text.replace('host = "127.0.0.1"', 'host = "0.0.0.0"'),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(ValueError, "public_bind_not_allowed"):
            load_config(initialized.config_path)

    def test_explicit_public_bind_is_represented_without_pretending_to_add_tls(self) -> None:
        initialized = initialize_instance(self.root / "instance")
        text = initialized.config_path.read_text(encoding="utf-8")
        initialized.config_path.write_text(
            text.replace('host = "127.0.0.1"', 'host = "0.0.0.0"').replace(
                "allow_public_bind = false",
                "allow_public_bind = true",
            ),
            encoding="utf-8",
        )

        loaded = load_config(initialized.config_path)

        self.assertEqual("0.0.0.0", loaded.host)
        self.assertTrue(loaded.allow_public_bind)

    def test_unknown_config_field_is_rejected(self) -> None:
        initialized = initialize_instance(self.root / "instance")
        with initialized.config_path.open("a", encoding="utf-8") as handle:
            handle.write("surprise = true\n")

        with self.assertRaisesRegex(ValueError, "unknown_config_fields"):
            load_config(initialized.config_path)

    def test_missing_keyring_is_a_startup_failure(self) -> None:
        initialized = initialize_instance(self.root / "instance")
        initialized.keyring_path.unlink()

        with self.assertRaisesRegex(ValueError, "keyring_missing"):
            load_config(initialized.config_path)

    def test_config_contains_no_secret_material(self) -> None:
        initialized = initialize_instance(self.root / "instance")
        config_text = initialized.config_path.read_text(encoding="utf-8")
        keyring = json.loads(initialized.keyring_path.read_text(encoding="utf-8"))

        for encoded_key in keyring["keys"].values():
            self.assertNotIn(encoded_key, config_text)

    def test_database_keyring_and_config_paths_must_be_distinct(self) -> None:
        initialized = initialize_instance(self.root / "instance")
        text = initialized.config_path.read_text(encoding="utf-8")
        initialized.config_path.write_text(
            text.replace('database = "onceproof.sqlite3"', 'database = "keyring.json"'),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(ValueError, "config_path_collision"):
            load_config(initialized.config_path)

    def test_instance_config_is_frozen(self) -> None:
        initialized = initialize_instance(self.root / "instance")
        loaded = load_config(initialized.config_path)

        with self.assertRaises((AttributeError, TypeError)):
            loaded.port = 9999  # type: ignore[misc]
        self.assertIsInstance(loaded, InstanceConfig)

    def test_malformed_missing_and_unsupported_config_are_rejected(self) -> None:
        path = self.root / "broken.toml"
        path.write_text("[", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unreadable_config"):
            load_config(path)

        initialized = initialize_instance(self.root / "instance")
        text = initialized.config_path.read_text(encoding="utf-8")
        initialized.config_path.write_text(text.replace("version = 1", "version = 2"), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unsupported_config_version"):
            load_config(initialized.config_path)

        initialized.config_path.write_text(
            "\n".join(line for line in text.splitlines() if not line.startswith("port =")) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "missing_config_fields:port"):
            load_config(initialized.config_path)

    def test_config_scalar_types_and_ranges_are_strict(self) -> None:
        initialized = initialize_instance(self.root / "instance")
        original = initialized.config_path.read_text(encoding="utf-8")
        mutations = (
            ("port = 8787", "port = true", "invalid_port"),
            ("port = 8787", "port = 70000", "invalid_port"),
            ("max_request_bytes = 16384", "max_request_bytes = 12", "invalid_max_request_bytes"),
            ("allow_public_bind = false", 'allow_public_bind = "no"', "invalid_allow_public_bind"),
            ('host = "127.0.0.1"', 'host = ""', "invalid_host"),
        )

        for old, new, error in mutations:
            initialized.config_path.write_text(original.replace(old, new), encoding="utf-8")
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                load_config(initialized.config_path)

    def test_keyring_must_be_a_regular_file(self) -> None:
        initialized = initialize_instance(self.root / "instance")
        initialized.keyring_path.unlink()
        initialized.keyring_path.mkdir()

        with self.assertRaisesRegex(ValueError, "keyring_not_regular"):
            load_config(initialized.config_path)

    def test_config_and_keyring_symlinks_are_rejected(self) -> None:
        initialized = initialize_instance(self.root / "instance")
        config_link = self.root / "config-link.toml"
        keyring_link = initialized.root / "keyring-link.json"
        try:
            config_link.symlink_to(initialized.config_path)
            keyring_link.symlink_to(initialized.keyring_path)
        except OSError as error:
            self.skipTest(f"symlink unavailable: {error}")

        with self.assertRaisesRegex(ValueError, "config_not_regular"):
            load_config(config_link)
        text = initialized.config_path.read_text(encoding="utf-8")
        initialized.config_path.write_text(
            text.replace('keyring = "keyring.json"', 'keyring = "keyring-link.json"'),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "keyring_not_regular"):
            load_config(initialized.config_path)

    @unittest.skipIf(os.name == "nt", "Windows permissions are enforced by ACL, not mode bits")
    def test_group_readable_keyring_is_rejected(self) -> None:
        initialized = initialize_instance(self.root / "instance")
        initialized.keyring_path.chmod(0o640)

        with self.assertRaisesRegex(ValueError, "keyring_permissions_too_open"):
            load_config(initialized.config_path)

    @unittest.skipIf(os.name == "nt", "Windows permissions are enforced by ACL, not mode bits")
    def test_writable_config_or_instance_parent_is_rejected(self) -> None:
        initialized = initialize_instance(self.root / "instance")
        initialized.config_path.chmod(0o620)
        with self.assertRaisesRegex(ValueError, "config_permissions_too_open"):
            load_config(initialized.config_path)

        initialized.config_path.chmod(0o600)
        initialized.root.chmod(0o720)
        with self.assertRaisesRegex(ValueError, "config_parent_permissions_too_open"):
            load_config(initialized.config_path)


if __name__ == "__main__":
    unittest.main()
