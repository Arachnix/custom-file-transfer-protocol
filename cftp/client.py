"""CFTP/1.0 Client Implementation with Interactive Shell and CLI."""

import argparse
import json
import logging
import os
import socket
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from cftp.config import Config
from cftp.integrity import (
    StreamingHasher,
    calculate_file_sha256,
    verify_file_sha256,
)
from cftp.protocol import (
    STATUS_OK,
    ConnectionClosedError,
    FramedSocket,
    FramingError,
    ProtocolError,
    Request,
    Response,
)
from cftp.storage import StorageManager, StorageSecurityError

logger = logging.getLogger("cftp.client")


@dataclass
class TransferResult:
    """Detailed summary of a completed or failed file transfer."""

    success: bool
    filename: str
    bytes_transferred: int
    duration_seconds: float
    throughput_mb_s: float
    expected_sha256: str
    actual_sha256: str
    integrity_matched: bool
    error_message: Optional[str] = None

    def print_summary(self) -> None:
        """Print an academic transfer summary report to stdout."""
        status_str = "SUCCESS" if self.success else "FAILED"
        integrity_str = "MATCHED (VERIFIED)" if self.integrity_matched else "MISMATCH / UNVERIFIED"
        print("+" + "-" * 62 + "+")
        print(f"| TRANSFER RESULT: {status_str:<43} |")
        print("+" + "-" * 62 + "+")
        print(f"| File:               {self.filename:<40} |")
        print(f"| Transferred:        {self.bytes_transferred} bytes ({self.bytes_transferred / (1024*1024):.2f} MB)")
        print(f"| Duration:           {self.duration_seconds:.4f} seconds")
        print(f"| Throughput:         {self.throughput_mb_s:.2f} MB/s")
        print(f"| Expected SHA-256:   {self.expected_sha256[:16]}...")
        print(f"| Actual SHA-256:     {self.actual_sha256[:16]}...")
        print(f"| Integrity Status:   {integrity_str}")
        if self.error_message:
            print(f"| Error:              {self.error_message}")
        print("+" + "-" * 62 + "+")


class CFTPClient:
    """Client for CFTP/1.0 custom file transfer protocol."""

    def __init__(
        self,
        host: str = Config.DEFAULT_HOST,
        port: int = Config.DEFAULT_PORT,
        download_dir: Union[str, Path] = Config.DEFAULT_CLIENT_DOWNLOADS,
        timeout: float = Config.DEFAULT_SOCKET_TIMEOUT,
    ) -> None:
        self.host = host
        self.port = port
        self.download_dir = Path(download_dir).resolve()
        self.timeout = timeout
        self.download_dir.mkdir(parents=True, exist_ok=True)
        self._sock: Optional[socket.socket] = None
        self._framed: Optional[FramedSocket] = None

    @property
    def is_connected(self) -> bool:
        """Check if client currently maintains an open TCP socket."""
        return self._framed is not None

    def connect(self) -> None:
        """Establish TCP connection to the CFTP server."""
        if self.is_connected:
            return

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.host, self.port))
        except OSError as err:
            sock.close()
            raise ConnectionError(f"Failed to connect to CFTP server at {self.host}:{self.port}: {err}") from err

        self._sock = sock
        self._framed = FramedSocket(sock)
        logger.info(f"Connected to CFTP server at {self.host}:{self.port}")

    def disconnect(self) -> None:
        """Close the connection gracefully."""
        if self._framed:
            try:
                self._framed.close()
            except Exception:
                pass
            self._framed = None
            self._sock = None
        logger.info("Disconnected from CFTP server.")

    def list_files(self) -> List[Dict[str, Union[str, int]]]:
        """Request remote file listing via LIST command."""
        self._ensure_connected()
        req = Request(command="LIST")
        self._framed.send_line(req.to_wire())

        resp_line = self._framed.read_line()
        if resp_line is None:
            raise ConnectionClosedError("Server closed connection unexpectedly.")

        resp = Response.parse(resp_line)
        if resp.code != STATUS_OK:
            raise ProtocolError(f"Server error on LIST: {resp.code} {resp.reason} ({resp.params.get('MESSAGE', '')})")

        payload_size = int(resp.params.get("SIZE", "0"))
        payload_bytes = self._framed.read_exact(payload_size)

        if not payload_bytes:
            return []

        try:
            files = json.loads(payload_bytes.decode(Config.CHARSET))
            return files
        except Exception as err:
            raise ProtocolError(f"Failed to parse server LIST payload: {err}") from err

    def get_file(
        self,
        remote_filename: str,
        local_destination: Optional[Union[str, Path]] = None,
        progress_callback: Optional[callable] = None,
    ) -> TransferResult:
        """Download a file from server with SHA-256 integrity verification.

        Safely streams into a temporary .cftp_part file, checks hash against
        server's CHECKSUM header, and atomically replaces local target on success.
        """
        self._ensure_connected()
        safe_name = StorageManager.validate_filename(remote_filename)

        if local_destination is None:
            local_path = (self.download_dir / safe_name).resolve()
        else:
            local_path = Path(local_destination).resolve()

        req = Request(command="GET", argument=safe_name)
        start_time = time.perf_counter()
        self._framed.send_line(req.to_wire())

        resp_line = self._framed.read_line()
        if resp_line is None:
            raise ConnectionClosedError("Server closed connection during GET.")

        resp = Response.parse(resp_line)
        if resp.code != STATUS_OK:
            msg = resp.params.get("MESSAGE", resp.reason)
            return TransferResult(
                success=False,
                filename=safe_name,
                bytes_transferred=0,
                duration_seconds=time.perf_counter() - start_time,
                throughput_mb_s=0.0,
                expected_sha256="",
                actual_sha256="",
                integrity_matched=False,
                error_message=f"Server returned {resp.code} {resp.reason}: {msg}",
            )

        expected_size = int(resp.params.get("SIZE", "0"))
        expected_checksum = resp.params.get("CHECKSUM", "")

        # Stream into temporary staging file
        temp_dest = local_path.with_name(f"{local_path.name}.{os.getpid()}.cftp_part")
        hasher = StreamingHasher()

        try:
            with open(temp_dest, "wb") as f:
                self._framed.stream_exact_to_file(
                    f, expected_size, hasher=hasher, progress_cb=progress_callback
                )

            duration = max(time.perf_counter() - start_time, 1e-9)
            actual_checksum = hasher.hexdigest()
            integrity_match = actual_checksum.lower() == expected_checksum.lower()

            if not integrity_match:
                if temp_dest.exists():
                    temp_dest.unlink()
                return TransferResult(
                    success=False,
                    filename=safe_name,
                    bytes_transferred=expected_size,
                    duration_seconds=duration,
                    throughput_mb_s=(expected_size / (1024 * 1024)) / duration,
                    expected_sha256=expected_checksum,
                    actual_sha256=actual_checksum,
                    integrity_matched=False,
                    error_message=f"SHA-256 mismatch: expected {expected_checksum}, calculated {actual_checksum}",
                )

            # Atomic commit to destination
            os.replace(temp_dest, local_path)
            return TransferResult(
                success=True,
                filename=safe_name,
                bytes_transferred=expected_size,
                duration_seconds=duration,
                throughput_mb_s=(expected_size / (1024 * 1024)) / duration,
                expected_sha256=expected_checksum,
                actual_sha256=actual_checksum,
                integrity_matched=True,
            )
        except Exception as err:
            if temp_dest.exists():
                try:
                    temp_dest.unlink()
                except OSError:
                    pass
            raise

    def put_file(
        self,
        local_path: Union[str, Path],
        remote_filename: Optional[str] = None,
        progress_callback: Optional[callable] = None,
    ) -> TransferResult:
        """Upload a file to the server with SHA-256 checksum negotiation."""
        self._ensure_connected()
        src_path = Path(local_path).resolve()
        if not src_path.is_file():
            raise FileNotFoundError(f"Local file not found: {src_path}")

        target_name = remote_filename or src_path.name
        safe_name = StorageManager.validate_filename(target_name)

        file_size = src_path.stat().st_size
        sha256_hash = calculate_file_sha256(src_path)

        start_time = time.perf_counter()

        # Send PUT request header
        req = Request(
            command="PUT",
            argument=safe_name,
            params={"SIZE": str(file_size), "CHECKSUM": sha256_hash},
        )
        self._framed.send_line(req.to_wire())

        # Wait for server readiness response
        resp_line = self._framed.read_line()
        if resp_line is None:
            raise ConnectionClosedError("Server closed connection before acknowledging PUT.")

        resp = Response.parse(resp_line)
        if resp.code != STATUS_OK or resp.reason != "READY_FOR_DATA":
            msg = resp.params.get("MESSAGE", resp.reason)
            return TransferResult(
                success=False,
                filename=safe_name,
                bytes_transferred=0,
                duration_seconds=time.perf_counter() - start_time,
                throughput_mb_s=0.0,
                expected_sha256=sha256_hash,
                actual_sha256="",
                integrity_matched=False,
                error_message=f"Server rejected PUT: {resp.code} {resp.reason} ({msg})",
            )

        # Stream payload to server
        hasher = StreamingHasher()
        with open(src_path, "rb") as f:
            self._framed.stream_file_to_socket(
                f, file_size, hasher=hasher, progress_cb=progress_callback
            )

        # Await completion response
        final_line = self._framed.read_line()
        if final_line is None:
            raise ConnectionClosedError("Server closed connection before confirming transfer.")

        final_resp = Response.parse(final_line)
        duration = max(time.perf_counter() - start_time, 1e-9)

        if final_resp.code == STATUS_OK:
            server_checksum = final_resp.params.get("CHECKSUM", sha256_hash)
            integrity_match = server_checksum.lower() == sha256_hash.lower()
            return TransferResult(
                success=True,
                filename=safe_name,
                bytes_transferred=file_size,
                duration_seconds=duration,
                throughput_mb_s=(file_size / (1024 * 1024)) / duration,
                expected_sha256=sha256_hash,
                actual_sha256=server_checksum,
                integrity_matched=integrity_match,
            )
        else:
            msg = final_resp.params.get("MESSAGE", final_resp.reason)
            return TransferResult(
                success=False,
                filename=safe_name,
                bytes_transferred=file_size,
                duration_seconds=duration,
                throughput_mb_s=(file_size / (1024 * 1024)) / duration,
                expected_sha256=sha256_hash,
                actual_sha256=final_resp.params.get("CHECKSUM", ""),
                integrity_matched=False,
                error_message=f"Server error {final_resp.code} {final_resp.reason}: {msg}",
            )

    def quit(self) -> None:
        """Send QUIT request and close connection."""
        if not self.is_connected:
            return

        try:
            req = Request(command="QUIT")
            self._framed.send_line(req.to_wire())
            resp_line = self._framed.read_line()
            if resp_line:
                resp = Response.parse(resp_line)
                logger.info(f"Server acknowledged QUIT: {resp.reason}")
        except Exception as err:
            logger.warning(f"Error during QUIT handshake: {err}")
        finally:
            self.disconnect()

    def _ensure_connected(self) -> None:
        """Ensure connection is open or reconnect."""
        if not self.is_connected:
            self.connect()


def run_interactive_repl(client: CFTPClient) -> None:
    """Run interactive CFTP terminal session."""
    print("=" * 64)
    print("  CFTP/1.0 — Custom File Transfer Protocol Interactive Shell")
    print(f"  Target Server: {client.host}:{client.port}")
    print("  Type 'help' for available commands, 'quit' to exit.")
    print("=" * 64)

    try:
        client.connect()
        print(f"[+] Connected to {client.host}:{client.port}\n")
    except Exception as err:
        print(f"[-] Connection failed: {err}")
        return

    while True:
        try:
            line = input("cftp> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting...")
            break

        if not line:
            continue

        parts = line.split(maxsplit=2)
        cmd = parts[0].lower()

        if cmd in ("quit", "exit", "q"):
            client.quit()
            print("Session terminated. Goodbye!")
            break
        elif cmd == "help":
            print("\nCFTP Commands:")
            print("  list                       - List files hosted on the server")
            print("  get <remote_file> [local]  - Download file with SHA-256 verification")
            print("  put <local_file> [remote]  - Upload file with SHA-256 verification")
            print("  status                     - Show connection status and settings")
            print("  quit                       - Terminate TCP session and exit\n")
        elif cmd == "status":
            conn_str = "CONNECTED" if client.is_connected else "DISCONNECTED"
            print(f"Status: {conn_str}")
            print(f"Server: {client.host}:{client.port}")
            print(f"Downloads directory: {client.download_dir}\n")
        elif cmd == "list":
            try:
                files = client.list_files()
                if not files:
                    print("(No files on server)")
                else:
                    print(f"\n{'Filename':<30} {'Size (Bytes)':<14} {'Modified (UTC)':<24}")
                    print("-" * 70)
                    for item in files:
                        print(f"{item['name']:<30} {item['size']:<14} {item['modified'][:19]:<24}")
                    print()
            except Exception as err:
                print(f"[-] Error listing files: {err}\n")
        elif cmd == "get":
            if len(parts) < 2:
                print("Usage: get <remote_filename> [optional_local_destination]\n")
                continue
            remote_name = parts[1]
            local_dest = parts[2] if len(parts) > 2 else None
            try:
                print(f"[*] Downloading '{remote_name}'...")
                res = client.get_file(remote_name, local_destination=local_dest)
                res.print_summary()
            except Exception as err:
                print(f"[-] GET failed: {err}\n")
        elif cmd == "put":
            if len(parts) < 2:
                print("Usage: put <local_filepath> [optional_remote_name]\n")
                continue
            local_file = parts[1]
            remote_name = parts[2] if len(parts) > 2 else None
            try:
                print(f"[*] Uploading '{local_file}'...")
                res = client.put_file(local_file, remote_filename=remote_name)
                res.print_summary()
            except Exception as err:
                print(f"[-] PUT failed: {err}\n")
        else:
            print(f"Unknown command: '{cmd}'. Type 'help' for command list.\n")


def main() -> None:
    """Entry point for CFTP client."""
    parser = argparse.ArgumentParser(description="CFTP/1.0 Custom File Transfer Protocol Client")
    parser.add_argument("--host", default=Config.DEFAULT_HOST, help="Server IP/host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=Config.DEFAULT_PORT, help="Server port (default: 9000)")
    parser.add_argument(
        "--download-dir",
        default=str(Config.DEFAULT_CLIENT_DOWNLOADS),
        help="Local directory for downloaded files (default: downloads)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # CLI sub-commands
    subparsers.add_parser("list", help="List server files")

    get_parser = subparsers.add_parser("get", help="Download a file")
    get_parser.add_argument("filename", help="Remote filename to download")
    get_parser.add_argument("--dest", default=None, help="Local destination file or directory")

    put_parser = subparsers.add_parser("put", help="Upload a file")
    put_parser.add_argument("filepath", help="Path to local file to upload")
    put_parser.add_argument("--remote-name", default=None, help="Name for file on server")

    args = parser.parse_args()

    client = CFTPClient(host=args.host, port=args.port, download_dir=args.download_dir)

    if not args.command:
        # Launch interactive REPL
        run_interactive_repl(client)
        return

    # Non-interactive CLI mode
    try:
        client.connect()
        if args.command == "list":
            files = client.list_files()
            if not files:
                print("(No files on server)")
            else:
                print(f"{'Filename':<30} {'Size (Bytes)':<14} {'Modified (UTC)':<24}")
                print("-" * 70)
                for item in files:
                    print(f"{item['name']:<30} {item['size']:<14} {item['modified'][:19]:<24}")
        elif args.command == "get":
            res = client.get_file(args.filename, local_destination=args.dest)
            res.print_summary()
            if not res.success:
                sys.exit(1)
        elif args.command == "put":
            res = client.put_file(args.filepath, remote_filename=args.remote_name)
            res.print_summary()
            if not res.success:
                sys.exit(1)
    except Exception as err:
        print(f"Error: {err}", file=sys.stderr)
        sys.exit(1)
    finally:
        client.quit()


if __name__ == "__main__":
    main()
