"""CLI tests pin one-time credential delivery and fail-closed startup."""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from onceproof.cli import main
from onceproof.keyring import KeyRing
from onceproof.locking import instance_lock
from onceproof.service import OnceproofService


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.instance = self.root / "instance"
        self.config = self.instance / "onceproof.toml"

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def run_cli(self, *arguments: str) -> tuple[int, dict[str, object]]:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(list(arguments))
        output = stdout.getvalue().strip()
        return exit_code, json.loads(output) if output else {}

    def test_init_check_and_client_create(self) -> None:
        init_code, initialized = self.run_cli("init", str(self.instance))
        check_code, checked = self.run_cli("check", "--config", str(self.config))
        credentials_path = self.root / "checkout.credentials.json"
        create_code, created = self.run_cli(
            "client",
            "create",
            "--config",
            str(self.config),
            "--name",
            "checkout",
            "--audience",
            "https://api.example.test/checkout",
            "--credentials-out",
            str(credentials_path),
        )
        credentials = json.loads(credentials_path.read_text(encoding="utf-8"))

        self.assertEqual(0, init_code)
        self.assertEqual(str(self.config.resolve()), initialized["config_path"])
        self.assertEqual(0, check_code)
        self.assertEqual("ready", checked["status"])
        self.assertEqual(0, create_code)
        self.assertEqual(credentials["client_id"], created["client_id"])
        self.assertTrue(credentials["issuance_secret"].startswith("opi1."))
        self.assertTrue(credentials["verification_secret"].startswith("opv1."))
        self.assertNotIn(credentials["issuance_secret"], json.dumps(created))
        inspect_code, inspected = self.run_cli(
            "client",
            "inspect",
            "--config",
            str(self.config),
            "--client-id",
            str(created["client_id"]),
        )
        inspected_ids = {item["credential_id"] for item in inspected["credentials"]}
        self.assertEqual(0, inspect_code)
        self.assertEqual(
            {credentials["issuance_credential_id"], credentials["verification_credential_id"]},
            inspected_ids,
        )

    def test_init_requires_explicit_public_bind_and_renders_container_settings(self) -> None:
        refused_code, refused = self.run_cli(
            "init",
            str(self.instance),
            "--host",
            "0.0.0.0",
        )
        init_code, _ = self.run_cli(
            "init",
            str(self.instance),
            "--host",
            "0.0.0.0",
            "--port",
            "9797",
            "--allow-public-bind",
        )
        config = self.config.read_text(encoding="utf-8")

        self.assertEqual((2, "public_bind_not_allowed"), (refused_code, refused["error"]))
        self.assertEqual(0, init_code)
        self.assertIn('host = "0.0.0.0"', config)
        self.assertIn("port = 9797", config)
        self.assertIn("allow_public_bind = true", config)

    @unittest.skipIf(os.name == "nt", "Windows chmod does not model the file ACL")
    def test_credentials_file_is_owner_read_write_only(self) -> None:
        self.run_cli("init", str(self.instance))
        credentials_path = self.root / "client.json"

        self.run_cli(
            "client",
            "create",
            "--config",
            str(self.config),
            "--name",
            "checkout",
            "--audience",
            "urn:onceproof:test",
            "--credentials-out",
            str(credentials_path),
        )

        self.assertEqual(0o600, stat.S_IMODE(credentials_path.stat().st_mode))

    def test_existing_credentials_file_is_not_overwritten(self) -> None:
        self.run_cli("init", str(self.instance))
        credentials_path = self.root / "client.json"
        credentials_path.write_text("sentinel", encoding="utf-8")

        exit_code, result = self.run_cli(
            "client",
            "create",
            "--config",
            str(self.config),
            "--name",
            "checkout",
            "--audience",
            "urn:onceproof:test",
            "--credentials-out",
            str(credentials_path),
        )

        self.assertEqual(2, exit_code)
        self.assertEqual("credentials_output_exists", result["error"])
        self.assertEqual("sentinel", credentials_path.read_text(encoding="utf-8"))

    def test_secret_delivery_is_durable_before_client_database_mutation(self) -> None:
        self.run_cli("init", str(self.instance))
        credentials_path = self.root / "recoverable.credentials.json"

        with patch("onceproof.store.Store.create_client", side_effect=OSError("store_failed")):
            exit_code, result = self.run_cli(
                "client",
                "create",
                "--config",
                str(self.config),
                "--name",
                "checkout",
                "--audience",
                "urn:onceproof:test",
                "--credentials-out",
                str(credentials_path),
            )

        credentials = json.loads(credentials_path.read_text(encoding="utf-8"))
        with closing(sqlite3.connect(self.instance / "onceproof.sqlite3")) as database:
            client_count = int(database.execute("SELECT COUNT(*) FROM clients").fetchone()[0])
        self.assertEqual((2, "store_failed"), (exit_code, result["error"]))
        self.assertTrue(credentials["issuance_secret"].startswith("opi1."))
        self.assertEqual(0, client_count)
        inspect_code, inspect = self.run_cli(
            "client",
            "inspect",
            "--config",
            str(self.config),
            "--client-id",
            credentials["client_id"],
        )
        self.assertEqual((2, "not_found"), (inspect_code, inspect["error"]))

    def test_delivery_failure_prevents_client_database_mutation(self) -> None:
        self.run_cli("init", str(self.instance))

        with patch("onceproof.cli._write_secret_json", side_effect=OSError("delivery_failed")):
            exit_code, result = self.run_cli(
                "client",
                "create",
                "--config",
                str(self.config),
                "--name",
                "checkout",
                "--audience",
                "urn:onceproof:test",
                "--credentials-out",
                str(self.root / "never-created.json"),
            )

        with closing(sqlite3.connect(self.instance / "onceproof.sqlite3")) as database:
            client_count = int(database.execute("SELECT COUNT(*) FROM clients").fetchone()[0])
        self.assertEqual((2, "delivery_failed"), (exit_code, result["error"]))
        self.assertEqual(0, client_count)

    def test_post_publish_sync_failure_leaves_only_complete_credentials(self) -> None:
        self.run_cli("init", str(self.instance))
        credentials_path = self.root / "complete.credentials.json"

        with patch("onceproof.cli._fsync_parent", side_effect=OSError("sync_failed")):
            exit_code, result = self.run_cli(
                "client",
                "create",
                "--config",
                str(self.config),
                "--name",
                "checkout",
                "--audience",
                "urn:onceproof:test",
                "--credentials-out",
                str(credentials_path),
            )

        credentials = json.loads(credentials_path.read_text(encoding="utf-8"))
        with closing(sqlite3.connect(self.instance / "onceproof.sqlite3")) as database:
            client_count = int(database.execute("SELECT COUNT(*) FROM clients").fetchone()[0])
        self.assertEqual((2, "sync_failed"), (exit_code, result["error"]))
        self.assertTrue(credentials["verification_secret"].startswith("opv1."))
        self.assertEqual(0, client_count)

    def test_credential_rotation_writes_only_the_replacement_secret(self) -> None:
        self.run_cli("init", str(self.instance))
        original_path = self.root / "original.json"
        _, created = self.run_cli(
            "client",
            "create",
            "--config",
            str(self.config),
            "--name",
            "checkout",
            "--audience",
            "urn:onceproof:test",
            "--credentials-out",
            str(original_path),
        )
        replacement_path = self.root / "replacement.json"

        rotate_code, rotated = self.run_cli(
            "client",
            "rotate",
            "--config",
            str(self.config),
            "--client-id",
            str(created["client_id"]),
            "--role",
            "verification",
            "--grace-seconds",
            "30",
            "--credentials-out",
            str(replacement_path),
        )
        replacement = json.loads(replacement_path.read_text(encoding="utf-8"))

        self.assertEqual(0, rotate_code)
        self.assertEqual("verification", replacement["role"])
        self.assertTrue(replacement["secret"].startswith("opv1."))
        self.assertNotIn(replacement["secret"], json.dumps(rotated))

    def test_rotation_secret_is_durable_before_credential_activation(self) -> None:
        self.run_cli("init", str(self.instance))
        original_path = self.root / "original.json"
        _, created = self.run_cli(
            "client",
            "create",
            "--config",
            str(self.config),
            "--name",
            "checkout",
            "--audience",
            "urn:onceproof:test",
            "--credentials-out",
            str(original_path),
        )
        replacement_path = self.root / "recoverable.rotation.json"

        with patch("onceproof.store.Store.rotate_credential", side_effect=OSError("store_failed")):
            exit_code, result = self.run_cli(
                "client",
                "rotate",
                "--config",
                str(self.config),
                "--client-id",
                str(created["client_id"]),
                "--role",
                "verification",
                "--grace-seconds",
                "0",
                "--credentials-out",
                str(replacement_path),
            )

        replacement = json.loads(replacement_path.read_text(encoding="utf-8"))
        with closing(sqlite3.connect(self.instance / "onceproof.sqlite3")) as database:
            statuses = database.execute(
                "SELECT status FROM credentials WHERE client_id = ? AND role = 'verification'",
                (created["client_id"],),
            ).fetchall()
        self.assertEqual((2, "store_failed"), (exit_code, result["error"]))
        self.assertTrue(replacement["secret"].startswith("opv1."))
        self.assertEqual([("current",)], statuses)

    def test_missing_config_fails_without_creating_demo_state(self) -> None:
        exit_code, result = self.run_cli("check", "--config", str(self.config))

        self.assertEqual(2, exit_code)
        self.assertEqual("unreadable_config", result["error"])
        self.assertFalse(self.instance.exists())

    def test_client_revocation_requires_confirmation_and_is_idempotent(self) -> None:
        self.run_cli("init", str(self.instance))
        credentials_path = self.root / "client.json"
        _, created = self.run_cli(
            "client",
            "create",
            "--config",
            str(self.config),
            "--name",
            "checkout",
            "--audience",
            "urn:onceproof:test",
            "--credentials-out",
            str(credentials_path),
        )

        refused_code, refused = self.run_cli(
            "client",
            "revoke",
            "--config",
            str(self.config),
            "--client-id",
            str(created["client_id"]),
        )
        revoked_code, revoked = self.run_cli(
            "client",
            "revoke",
            "--config",
            str(self.config),
            "--client-id",
            str(created["client_id"]),
            "--yes-revoke",
        )
        repeated_code, repeated = self.run_cli(
            "client",
            "revoke",
            "--config",
            str(self.config),
            "--client-id",
            str(created["client_id"]),
            "--yes-revoke",
        )

        self.assertEqual(2, refused_code)
        self.assertEqual("revocation_confirmation_required", refused["error"])
        self.assertEqual(0, revoked_code)
        self.assertEqual("revoked", revoked["status"])
        self.assertEqual(0, repeated_code)
        self.assertEqual("already_revoked", repeated["status"])

    def test_doctor_key_inspection_integrity_and_backup_are_executable(self) -> None:
        self.run_cli("init", str(self.instance))
        doctor_code, doctor = self.run_cli("doctor", "--config", str(self.config))
        key_code, keys = self.run_cli("key", "inspect", "--config", str(self.config))
        integrity_code, integrity = self.run_cli(
            "db",
            "integrity-check",
            "--config",
            str(self.config),
        )
        backup_directory = self.root / "onceproof-backup"
        backup_path = backup_directory / "onceproof.sqlite3"
        keyring_backup_path = backup_directory / "keyring.json"
        backup_code, backup = self.run_cli(
            "db",
            "backup",
            "--config",
            str(self.config),
            "--output",
            str(backup_directory),
        )

        with closing(sqlite3.connect(backup_path)) as database:
            backup_integrity = database.execute("PRAGMA integrity_check").fetchone()[0]
        restored = OnceproofService(
            database_path=backup_path,
            keyring=KeyRing.load(keyring_backup_path),
        )
        verify_code, verified_backup = self.run_cli(
            "db",
            "verify-backup",
            "--input",
            str(backup_directory),
        )

        self.assertEqual(0, doctor_code)
        self.assertEqual("healthy", doctor["status"])
        self.assertEqual("delete", doctor["database"]["journal_mode"])
        self.assertEqual(3, doctor["database"]["synchronous"])
        self.assertEqual(0, key_code)
        self.assertIn(keys["current_hash_kid"], keys["hash_kids"])
        self.assertEqual(0, integrity_code)
        self.assertEqual("ok", integrity["integrity"])
        self.assertEqual(0, backup_code)
        self.assertEqual(str(backup_path.resolve()), backup["database_backup_path"])
        self.assertEqual(str(keyring_backup_path.resolve()), backup["keyring_backup_path"])
        self.assertEqual(
            str((backup_directory / "manifest.json").resolve()),
            backup["manifest_path"],
        )
        self.assertTrue(keyring_backup_path.is_file())
        self.assertFalse(restored.ready())
        restored.activate_restored_backup()
        self.assertTrue(restored.ready())
        self.assertEqual((0, "valid"), (verify_code, verified_backup["status"]))
        self.assertEqual("ok", backup_integrity)

    def test_stdout_delivery_is_refused_and_key_lifecycle_remains_executable(self) -> None:
        self.run_cli("init", str(self.instance))
        refused_code, refused = self.run_cli(
            "client",
            "create",
            "--config",
            str(self.config),
            "--name",
            "stdout-client",
            "--audience",
            "urn:onceproof:stdout",
            "--credentials-out",
            "-",
        )
        with closing(sqlite3.connect(self.instance / "onceproof.sqlite3")) as database:
            client_count = int(database.execute("SELECT COUNT(*) FROM clients").fetchone()[0])
        credentials_path = self.root / "lifecycle.credentials.json"
        create_code, _ = self.run_cli(
            "client",
            "create",
            "--config",
            str(self.config),
            "--name",
            "lifecycle-client",
            "--audience",
            "urn:onceproof:lifecycle",
            "--credentials-out",
            str(credentials_path),
        )
        _, before = self.run_cli("key", "inspect", "--config", str(self.config))
        old_kid = str(before["current_hash_kid"])
        rotate_code, rotated = self.run_cli("key", "rotate", "--config", str(self.config))
        retire_code, retire = self.run_cli(
            "key",
            "retire",
            "--config",
            str(self.config),
            "--kid",
            old_kid,
        )
        cleanup_code, cleanup = self.run_cli("cleanup", "--config", str(self.config))

        self.assertEqual((2, "credentials_output_must_be_file"), (refused_code, refused["error"]))
        self.assertEqual(0, client_count)
        self.assertEqual(0, create_code)
        self.assertTrue(json.loads(credentials_path.read_text())["issuance_secret"].startswith("opi1."))
        self.assertEqual(0, rotate_code)
        self.assertNotEqual(old_kid, rotated["current_hash_kid"])
        self.assertEqual(2, retire_code)
        self.assertEqual("key_still_in_use", retire["error"])
        self.assertEqual(0, cleanup_code)
        self.assertEqual("cleaned", cleanup["status"])

    def test_root_key_mutation_is_refused_while_the_instance_is_owned(self) -> None:
        self.run_cli("init", str(self.instance))

        with instance_lock(self.instance / "onceproof.sqlite3"):
            exit_code, result = self.run_cli("key", "rotate", "--config", str(self.config))

        self.assertEqual((2, "instance_busy"), (exit_code, result["error"]))

    def test_existing_instance_backup_and_unknown_client_fail_without_mutation(self) -> None:
        self.run_cli("init", str(self.instance))
        duplicate_code, duplicate = self.run_cli("init", str(self.instance))
        backup_path = self.root / "existing-backup"
        backup_path.write_bytes(b"sentinel")
        backup_code, backup = self.run_cli(
            "db",
            "backup",
            "--config",
            str(self.config),
            "--output",
            str(backup_path),
        )
        revoke_code, revoke = self.run_cli(
            "client",
            "revoke",
            "--config",
            str(self.config),
            "--client-id",
            "opc_missing",
            "--yes-revoke",
        )

        self.assertEqual((2, "instance_exists"), (duplicate_code, duplicate["error"]))
        self.assertEqual((2, "backup_output_exists"), (backup_code, backup["error"]))
        self.assertEqual(b"sentinel", backup_path.read_bytes())
        self.assertEqual((2, "not_found"), (revoke_code, revoke["error"]))

    def test_incomplete_backup_directory_is_reconciled_on_retry(self) -> None:
        self.run_cli("init", str(self.instance))
        backup_directory = self.root / "interrupted-backup"
        backup_directory.mkdir()
        (backup_directory / ".onceproof-incomplete").write_text(
            '{"format":1,"state":"incomplete"}\n',
            encoding="utf-8",
        )
        (backup_directory / "onceproof.sqlite3").write_bytes(b"partial")

        exit_code, result = self.run_cli(
            "db",
            "backup",
            "--config",
            str(self.config),
            "--output",
            str(backup_directory),
        )

        self.assertEqual(0, exit_code)
        self.assertEqual("backed_up", result["status"])
        self.assertTrue((backup_directory / "manifest.json").is_file())
        self.assertFalse((backup_directory / ".onceproof-incomplete").exists())
        with (backup_directory / "keyring.json").open("ab") as handle:
            handle.write(b"tampered")
        verify_code, verify = self.run_cli(
            "db",
            "verify-backup",
            "--input",
            str(backup_directory),
        )
        self.assertEqual((2, "backup_checksum_mismatch:keyring"), (verify_code, verify["error"]))

    def test_backup_manifest_and_reconciliation_reject_ambiguous_inputs(self) -> None:
        self.run_cli("init", str(self.instance))
        not_directory = self.root / "not-directory"
        not_directory.write_text("file", encoding="utf-8")
        code, result = self.run_cli(
            "db",
            "verify-backup",
            "--input",
            str(not_directory),
        )
        self.assertEqual((2, "backup_directory_not_regular"), (code, result["error"]))

        invalid = self.root / "invalid-backup"
        invalid.mkdir()
        (invalid / "manifest.json").write_text("{}", encoding="utf-8")
        code, result = self.run_cli("db", "verify-backup", "--input", str(invalid))
        self.assertEqual((2, "backup_manifest_invalid"), (code, result["error"]))

        ambiguous = self.root / "ambiguous-backup"
        ambiguous.mkdir()
        (ambiguous / ".onceproof-incomplete").write_text("marker", encoding="utf-8")
        (ambiguous / "unknown").write_text("do not delete", encoding="utf-8")
        code, result = self.run_cli(
            "db",
            "backup",
            "--config",
            str(self.config),
            "--output",
            str(ambiguous),
        )
        self.assertEqual(
            (2, "incomplete_backup_not_reconcilable"),
            (code, result["error"]),
        )
        self.assertEqual("do not delete", (ambiguous / "unknown").read_text(encoding="utf-8"))

        complete = self.root / "complete-backup"
        self.run_cli(
            "db",
            "backup",
            "--config",
            str(self.config),
            "--output",
            str(complete),
        )
        code, result = self.run_cli(
            "db",
            "backup",
            "--config",
            str(self.config),
            "--output",
            str(complete),
        )
        self.assertEqual((2, "backup_output_exists"), (code, result["error"]))

    def test_restore_activation_requires_confirmation_and_revokes_snapshot_clients(self) -> None:
        self.run_cli("init", str(self.instance))
        credentials_path = self.root / "restore-client.json"
        _, created = self.run_cli(
            "client",
            "create",
            "--config",
            str(self.config),
            "--name",
            "restore-client",
            "--audience",
            "urn:onceproof:restore",
            "--credentials-out",
            str(credentials_path),
        )
        backup_directory = self.root / "restore-backup"
        self.run_cli(
            "db",
            "backup",
            "--config",
            str(self.config),
            "--output",
            str(backup_directory),
        )
        shutil.copyfile(backup_directory / "onceproof.sqlite3", self.instance / "onceproof.sqlite3")
        shutil.copyfile(backup_directory / "keyring.json", self.instance / "keyring.json")

        refused_code, refused = self.run_cli(
            "db",
            "activate-restore",
            "--config",
            str(self.config),
        )
        activated_code, activated = self.run_cli(
            "db",
            "activate-restore",
            "--config",
            str(self.config),
            "--yes-invalidate-prior-authority",
        )
        _, inspected = self.run_cli(
            "client",
            "inspect",
            "--config",
            str(self.config),
            "--client-id",
            str(created["client_id"]),
        )

        self.assertEqual(
            (2, "restore_activation_confirmation_required"),
            (refused_code, refused["error"]),
        )
        self.assertEqual((0, "activated"), (activated_code, activated["status"]))
        self.assertEqual("revoked", inspected["client"]["status"])

    def test_serve_command_builds_the_validated_single_instance(self) -> None:
        self.run_cli("init", str(self.instance))

        def assert_lock_held(**_: object) -> None:
            with self.assertRaisesRegex(OSError, "instance_busy"):
                with instance_lock(self.instance / "onceproof.sqlite3"):
                    self.fail("serve released the instance lock")

        with patch("onceproof.cli.serve", side_effect=assert_lock_held) as mocked_serve:
            exit_code, result = self.run_cli("serve", "--config", str(self.config))

        self.assertEqual(0, exit_code)
        self.assertEqual("stopped", result["status"])
        self.assertEqual(1, mocked_serve.call_count)
        self.assertEqual("127.0.0.1", mocked_serve.call_args.kwargs["host"])
        self.assertTrue(mocked_serve.call_args.kwargs["instance_lock_held"])

    def test_python_module_entrypoint_reports_the_installed_version(self) -> None:
        completed = subprocess.run(
            [sys.executable, "-m", "onceproof", "--version"],
            check=True,
            capture_output=True,
            text=True,
        )

        self.assertEqual("onceproof 0.1.0a1", completed.stdout.strip())


if __name__ == "__main__":
    unittest.main()
