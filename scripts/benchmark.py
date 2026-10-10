"""CFTP/1.0 Repeatable Benchmark and Performance Evaluation Suite.

Measures transfer duration, throughput (MB/s), file size scaling, and
verifies end-to-end SHA-256 integrity across multiple trials.
"""

import argparse
import os
import statistics
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, List, Tuple

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cftp.client import CFTPClient
from cftp.config import Config
from cftp.integrity import calculate_file_sha256
from cftp.server import CFTPServer


def generate_benchmark_file(path: Path, size_bytes: int) -> str:
    """Generate a pseudo-random or patterned file of exact byte size."""
    if size_bytes == 0:
        path.write_bytes(b"")
    else:
        # Pattern repeated to fill size
        chunk = os.urandom(min(size_bytes, 65536))
        with open(path, "wb") as f:
            written = 0
            while written < size_bytes:
                to_write = min(len(chunk), size_bytes - written)
                f.write(chunk[:to_write])
                written += to_write
    return calculate_file_sha256(path)


def run_benchmark(
    host: str,
    port: int,
    trials: int = 3,
    test_sizes: List[Tuple[str, int]] = None,
) -> None:
    """Execute repeatable throughput benchmarks across multiple file sizes."""
    if test_sizes is None:
        test_sizes = [
            ("Empty File (0 B)", 0),
            ("Small Text (1 KB)", 1024),
            ("Medium Buffer (64 KB)", 64 * 1024),
            ("Large Binary (1 MB)", 1024 * 1024),
            ("Streaming Bulk (5 MB)", 5 * 1024 * 1024),
        ]

    print("=" * 78)
    print("  CFTP/1.0 PERFORMANCE EVALUATION & BENCHMARK SUITE")
    print(f"  Target: {host}:{port} | Trials per size: {trials}")
    print("=" * 78)

    with tempfile.TemporaryDirectory() as client_tmp:
        client_dir = Path(client_tmp)
        client = CFTPClient(host=host, port=port, download_dir=client_dir)
        client.connect()

        try:
            print(f"\n{'Test Case':<24} {'Size':<10} {'Op':<6} {'Median Time':<14} {'Median Throughput':<18} {'Integrity'}")
            print("-" * 78)

            for label, size in test_sizes:
                src_file = client_dir / f"bench_src_{size}.dat"
                generate_benchmark_file(src_file, size)

                put_durations = []
                put_throughputs = []
                get_durations = []
                get_throughputs = []
                integrity_ok = True

                # --- PUT Trials ---
                for trial_idx in range(trials):
                    remote_name = f"bench_remote_{size}.dat"
                    put_res = client.put_file(src_file, remote_filename=remote_name)
                    if not put_res.success or not put_res.integrity_matched:
                        integrity_ok = False
                    put_durations.append(put_res.duration_seconds)
                    put_throughputs.append(put_res.throughput_mb_s)

                # --- GET Trials ---
                for trial_idx in range(trials):
                    dest_file = client_dir / f"bench_get_{size}_{trial_idx}.dat"
                    get_res = client.get_file(f"bench_remote_{size}.dat", local_destination=dest_file)
                    if not get_res.success or not get_res.integrity_matched:
                        integrity_ok = False
                    get_durations.append(get_res.duration_seconds)
                    get_throughputs.append(get_res.throughput_mb_s)

                # Aggregate metrics
                med_put_time = statistics.median(put_durations)
                med_put_tp = statistics.median(put_throughputs)
                med_get_time = statistics.median(get_durations)
                med_get_tp = statistics.median(get_throughputs)

                size_str = f"{size} B" if size < 1024 else f"{size//1024} KB" if size < 1024*1024 else f"{size//(1024*1024)} MB"
                verif_str = "PASS (SHA-256)" if integrity_ok else "FAIL"

                print(f"{label:<24} {size_str:<10} {'PUT':<6} {med_put_time*1000:>8.2f} ms     {med_put_tp:>8.2f} MB/s       {verif_str}")
                print(f"{'':<24} {'':<10} {'GET':<6} {med_get_time*1000:>8.2f} ms     {med_get_tp:>8.2f} MB/s       {verif_str}")

            print("-" * 78)
            print("[+] Benchmark completed successfully.")

        finally:
            client.quit()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run CFTP benchmark suite")
    parser.add_argument("--host", default=Config.DEFAULT_HOST, help="Server host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=Config.DEFAULT_PORT, help="Server port (default: 9000)")
    parser.add_argument("--trials", type=int, default=3, help="Number of trials per test size (default: 3)")
    parser.add_argument(
        "--standalone",
        action="store_true",
        help="Launch an ephemeral background server for benchmarking if one is not running",
    )
    args = parser.parse_args()

    server = None
    server_thread = None

    if args.standalone:
        server_tmp = tempfile.TemporaryDirectory()
        server = CFTPServer(
            host=args.host,
            port=0,
            storage_dir=server_tmp.name,
            max_file_size=50 * 1024 * 1024,
        )
        server_thread = threading.Thread(target=server.start, daemon=True)
        server_thread.start()
        while server.port == 0:
            time.sleep(0.05)
        benchmark_port = server.port
    else:
        benchmark_port = args.port

    try:
        run_benchmark(host=args.host, port=benchmark_port, trials=args.trials)
    finally:
        if server:
            server.stop()


if __name__ == "__main__":
    main()
