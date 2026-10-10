"""Unit tests for SHA-256 file integrity calculation and verification."""

import tempfile
import unittest
from pathlib import Path

from cftp.integrity import (
    StreamingHasher,
    calculate_bytes_sha256,
    calculate_file_sha256,
    verify_file_sha256,
)


class TestIntegrityVerification(unittest.TestCase):
    """Test suite for SHA-256 integrity functions."""

    EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_empty_bytes_sha256(self) -> None:
        self.assertEqual(calculate_bytes_sha256(b""), self.EMPTY_SHA256)

    def test_empty_file_sha256(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as f:
            filepath = Path(f.name)
        try:
            self.assertEqual(calculate_file_sha256(filepath), self.EMPTY_SHA256)
            self.assertTrue(verify_file_sha256(filepath, self.EMPTY_SHA256))
        finally:
            filepath.unlink()

    def test_binary_file_sha256(self) -> None:
        data = bytes(range(256)) * 16  # 4096 bytes
        expected_hash = calculate_bytes_sha256(data)

        with tempfile.NamedTemporaryFile(delete=False) as f:
            filepath = Path(f.name)
            f.write(data)

        try:
            actual_hash = calculate_file_sha256(filepath)
            self.assertEqual(actual_hash, expected_hash)
            self.assertTrue(verify_file_sha256(filepath, expected_hash))
            # Test corrupt verification
            self.assertFalse(verify_file_sha256(filepath, "0" * 64))
        finally:
            filepath.unlink()

    def test_streaming_hasher(self) -> None:
        hasher = StreamingHasher()
        chunk1 = b"Custom File "
        chunk2 = b"Transfer Protocol"
        hasher.update(chunk1)
        hasher.update(chunk2)

        self.assertEqual(hasher.bytes_processed, len(chunk1) + len(chunk2))
        expected = calculate_bytes_sha256(chunk1 + chunk2)
        self.assertEqual(hasher.hexdigest(), expected)


if __name__ == "__main__":
    unittest.main()
