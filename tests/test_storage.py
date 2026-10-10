"""Unit tests for StorageManager, path traversal protection, and file safety."""

import tempfile
import unittest
from pathlib import Path

from cftp.storage import StorageManager, StorageSecurityError


class TestStorageManager(unittest.TestCase):
    """Test suite for safe filesystem operations and security constraints."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.storage = StorageManager(self.tmp_dir.name, max_file_size=1024 * 1024)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_valid_filenames(self) -> None:
        valid_cases = ["data.txt", "my_report.pdf", "sample-v2.tar.gz", "notes 2026.doc"]
        for name in valid_cases:
            cleaned = StorageManager.validate_filename(name)
            self.assertEqual(cleaned, name)

    def test_reject_empty_filename(self) -> None:
        with self.assertRaises(StorageSecurityError):
            StorageManager.validate_filename("")
        with self.assertRaises(StorageSecurityError):
            StorageManager.validate_filename("   ")

    def test_reject_path_traversal(self) -> None:
        traversal_attempts = [
            "..",
            "../secret.txt",
            "..\\windows\\system32",
            "foo/../../etc/passwd",
            "a/b/c.txt",
            "sub\\doc.txt",
        ]
        for bad in traversal_attempts:
            with self.assertRaises(StorageSecurityError):
                StorageManager.validate_filename(bad)

    def test_reject_windows_device_names(self) -> None:
        reserved = ["CON", "con.txt", "PRN", "aux.dat", "NUL", "COM1", "lpt3.log"]
        for bad in reserved:
            with self.assertRaises(StorageSecurityError):
                StorageManager.validate_filename(bad)

    def test_reject_illegal_characters(self) -> None:
        illegal = ['bad<name>.txt', 'bad>name', 'file:stream', 'file"quote', 'pipe|name', 'wild*card', 'null\x00byte']
        for bad in illegal:
            with self.assertRaises(StorageSecurityError):
                StorageManager.validate_filename(bad)

    def test_resolve_safe_path(self) -> None:
        path = self.storage.resolve_safe_path("allowed.txt")
        self.assertEqual(path.parent, self.storage.root_dir)
        self.assertEqual(path.name, "allowed.txt")

    def test_atomic_file_commit_and_list(self) -> None:
        # Create a temp staging file
        temp_path = self.storage.get_temp_path("document.txt")
        temp_path.write_bytes(b"CFTP storage test content")

        # Commit it
        final_path = self.storage.commit_temp_file(temp_path, "document.txt")
        self.assertTrue(final_path.is_file())
        self.assertFalse(temp_path.exists())

        # Check list_files()
        file_list = self.storage.list_files()
        self.assertEqual(len(file_list), 1)
        self.assertEqual(file_list[0]["name"], "document.txt")
        self.assertEqual(file_list[0]["size"], 25)

    def test_cleanup_temp_file(self) -> None:
        temp_path = self.storage.get_temp_path("aborted.txt")
        temp_path.write_bytes(b"partial payload")
        self.assertTrue(temp_path.exists())

        self.storage.cleanup_temp_file(temp_path)
        self.assertFalse(temp_path.exists())


if __name__ == "__main__":
    unittest.main()
