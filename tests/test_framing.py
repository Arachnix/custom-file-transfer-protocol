"""Deterministic unit tests for TCP stream framing and byte-stream boundary handling."""

import io
import socket
import tempfile
import unittest
from pathlib import Path

from cftp.integrity import StreamingHasher
from cftp.protocol import ConnectionClosedError, FramedSocket, FramingError


class TestTCPFraming(unittest.TestCase):
    """Test suite for TCP byte stream framing and buffered socket behavior."""

    def setUp(self) -> None:
        self.sock_a, self.sock_b = socket.socketpair()
        self.framed = FramedSocket(self.sock_b, max_line_length=128)

    def tearDown(self) -> None:
        self.sock_a.close()
        self.sock_b.close()

    def test_single_message_normal(self) -> None:
        self.sock_a.sendall(b"CFTP/1.0 LIST\r\n")
        line = self.framed.read_line()
        self.assertEqual(line, "CFTP/1.0 LIST")
        self.assertEqual(self.framed.buffered_bytes_count, 0)

    def test_message_received_in_multiple_fragments(self) -> None:
        """Verify that line reader reassembles message split across multiple TCP fragments."""
        self.sock_a.sendall(b"CFTP")
        self.sock_a.sendall(b"/1.0 ")
        self.sock_a.sendall(b"GET sample")
        self.sock_a.sendall(b".txt\r\n")

        line = self.framed.read_line()
        self.assertEqual(line, "CFTP/1.0 GET sample.txt")

    def test_delimiter_split_across_reads(self) -> None:
        """Verify that \\r in one segment and \\n in the next segment resolves correctly."""
        self.sock_a.sendall(b"CFTP/1.0 QUIT\r")
        self.sock_a.sendall(b"\n")

        line = self.framed.read_line()
        self.assertEqual(line, "CFTP/1.0 QUIT")

    def test_multiple_control_messages_in_single_buffer(self) -> None:
        """Verify that multiple control messages arriving in one TCP chunk are not lost."""
        payload = b"CFTP/1.0 LIST\r\nCFTP/1.0 QUIT\r\n"
        self.sock_a.sendall(payload)

        line1 = self.framed.read_line()
        self.assertEqual(line1, "CFTP/1.0 LIST")

        line2 = self.framed.read_line()
        self.assertEqual(line2, "CFTP/1.0 QUIT")
        self.assertEqual(self.framed.buffered_bytes_count, 0)

    def test_control_message_exceeding_max_line_length(self) -> None:
        """Verify that unbounded line without newline raises FramingError."""
        # Configured max_line_length is 128 in setUp
        long_junk = b"A" * 150
        self.sock_a.sendall(long_junk)

        with self.assertRaises(FramingError):
            self.framed.read_line()

    def test_clean_eof_on_empty_buffer(self) -> None:
        """Verify that orderly connection closure returns None when buffer is empty."""
        self.sock_a.close()
        line = self.framed.read_line()
        self.assertIsNone(line)

    def test_premature_eof_on_incomplete_line(self) -> None:
        """Verify that connection closing before delimiter raises FramingError."""
        self.sock_a.sendall(b"CFTP/1.0 GET incomplete")
        self.sock_a.close()

        with self.assertRaises(FramingError):
            self.framed.read_line()

    def test_read_exact_payload(self) -> None:
        """Verify reading exact byte payloads across packet boundaries."""
        data = b"0123456789ABCDEF"  # 16 bytes
        self.sock_a.sendall(data[:5])
        self.sock_a.sendall(data[5:12])
        self.sock_a.sendall(data[12:])

        received = self.framed.read_exact(16)
        self.assertEqual(received, data)
        self.assertEqual(self.framed.buffered_bytes_count, 0)

    def test_zero_byte_payload(self) -> None:
        """Verify that zero-byte payload does not block or wait on network."""
        result = self.framed.read_exact(0)
        self.assertEqual(result, b"")

    def test_control_line_followed_immediately_by_payload(self) -> None:
        """Verify that payload arriving in same TCP packet as control header is preserved."""
        combined = b"CFTP/1.0 200 OK SIZE=10\r\n1234567890EXTRA"
        self.sock_a.sendall(combined)

        header = self.framed.read_line()
        self.assertEqual(header, "CFTP/1.0 200 OK SIZE=10")

        # Read exact 10 bytes payload
        payload = self.framed.read_exact(10)
        self.assertEqual(payload, b"1234567890")

        # Verify EXTRA remains in buffer untouched
        self.assertEqual(self.framed.buffered_bytes_count, 5)
        extra = self.framed.read_exact(5)
        self.assertEqual(extra, b"EXTRA")

    def test_stream_exact_to_file_and_hash(self) -> None:
        """Verify streaming payload to file object with on-the-fly hashing."""
        data = b"Hello, Custom File Transfer Protocol!" * 50
        hasher = StreamingHasher()

        # Send in fragmented chunks
        self.sock_a.sendall(data[:100])
        self.sock_a.sendall(data[100:500])
        self.sock_a.sendall(data[500:])

        with tempfile.TemporaryDirectory() as tmpdir:
            dest_path = Path(tmpdir) / "streamed.bin"
            with open(dest_path, "wb") as f:
                bytes_written = self.framed.stream_exact_to_file(
                    f, len(data), hasher=hasher
                )

            self.assertEqual(bytes_written, len(data))
            self.assertEqual(dest_path.read_bytes(), data)
            import hashlib
            expected_hash = hashlib.sha256(data).hexdigest()
            self.assertEqual(hasher.hexdigest(), expected_hash)


if __name__ == "__main__":
    unittest.main()
