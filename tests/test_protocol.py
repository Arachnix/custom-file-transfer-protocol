"""Unit tests for CFTP protocol parsing, serialization, and status codes."""

import unittest

from cftp.config import Config
from cftp.protocol import (
    STATUS_BAD_REQUEST,
    STATUS_NOT_FOUND,
    STATUS_OK,
    STATUS_VERSION_NOT_SUPPORTED,
    ProtocolError,
    Request,
    Response,
)


class TestProtocolParsing(unittest.TestCase):
    """Test suite for parsing and validating CFTP requests and responses."""

    def test_parse_valid_list(self) -> None:
        req = Request.parse("CFTP/1.0 LIST")
        self.assertEqual(req.version, "CFTP/1.0")
        self.assertEqual(req.command, "LIST")
        self.assertIsNone(req.argument)
        self.assertEqual(req.params, {})

    def test_parse_valid_get(self) -> None:
        req = Request.parse("CFTP/1.0 GET notes.txt")
        self.assertEqual(req.command, "GET")
        self.assertEqual(req.argument, "notes.txt")

    def test_parse_get_with_spaces_in_quotes(self) -> None:
        req = Request.parse('CFTP/1.0 GET "lecture notes 2026.pdf"')
        self.assertEqual(req.command, "GET")
        self.assertEqual(req.argument, "lecture notes 2026.pdf")

    def test_parse_valid_put(self) -> None:
        chk = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        req = Request.parse(f"CFTP/1.0 PUT data.bin SIZE=2048 CHECKSUM={chk}")
        self.assertEqual(req.command, "PUT")
        self.assertEqual(req.argument, "data.bin")
        self.assertEqual(req.params.get("SIZE"), "2048")
        self.assertEqual(req.params.get("CHECKSUM"), chk)

    def test_parse_valid_quit(self) -> None:
        req = Request.parse("CFTP/1.0 QUIT")
        self.assertEqual(req.command, "QUIT")

    def test_parse_unsupported_version(self) -> None:
        with self.assertRaises(ProtocolError) as ctx:
            Request.parse("CFTP/2.0 LIST")
        self.assertEqual(ctx.exception.code, STATUS_VERSION_NOT_SUPPORTED)

    def test_parse_empty_request(self) -> None:
        with self.assertRaises(ProtocolError) as ctx:
            Request.parse("   ")
        self.assertEqual(ctx.exception.code, STATUS_BAD_REQUEST)

    def test_parse_incomplete_request(self) -> None:
        with self.assertRaises(ProtocolError) as ctx:
            Request.parse("CFTP/1.0")
        self.assertEqual(ctx.exception.code, STATUS_BAD_REQUEST)

    def test_serialize_request(self) -> None:
        req = Request(command="GET", argument="report.txt")
        self.assertEqual(req.to_wire(), "CFTP/1.0 GET report.txt")

        req_space = Request(command="GET", argument="my report.txt")
        self.assertEqual(req_space.to_wire(), 'CFTP/1.0 GET "my report.txt"')

    def test_parse_response_ok(self) -> None:
        resp = Response.parse("CFTP/1.0 200 OK SIZE=100 CHECKSUM=abc")
        self.assertEqual(resp.code, STATUS_OK)
        self.assertEqual(resp.reason, "OK")
        self.assertEqual(resp.params.get("SIZE"), "100")
        self.assertEqual(resp.params.get("CHECKSUM"), "abc")

    def test_parse_response_error(self) -> None:
        resp = Response.parse('CFTP/1.0 404 NOT_FOUND MESSAGE="File not found"')
        self.assertEqual(resp.code, STATUS_NOT_FOUND)
        self.assertEqual(resp.reason, "NOT_FOUND")
        self.assertEqual(resp.params.get("MESSAGE"), "File not found")

    def test_serialize_response(self) -> None:
        resp = Response.ok(params={"COUNT": "2", "SIZE": "150"})
        self.assertEqual(resp.to_wire(), "CFTP/1.0 200 OK COUNT=2 SIZE=150")


if __name__ == "__main__":
    unittest.main()
