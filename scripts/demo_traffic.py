"""Demonstration script to generate clean, repeatable CFTP traffic for Wireshark inspection.

Runs a complete session:
1. Connects to server (TCP 3-way handshake: SYN, SYN-ACK, ACK)
2. Issues LIST
3. Issues PUT with sample text file
4. Issues GET to download the file back
5. Issues QUIT (TCP 4-way termination: FIN, ACK, FIN, ACK)
"""

import sys
import time
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cftp.client import CFTPClient
from cftp.config import Config


def main() -> None:
    host = Config.DEFAULT_HOST
    port = Config.DEFAULT_PORT
    print(f"[*] Connecting to CFTP server at {host}:{port} for traffic generation...")

    # Prepare demo sample file in uploads/
    demo_file = Path("uploads") / "wireshark_demo.txt"
    demo_file.parent.mkdir(exist_ok=True)
    demo_content = (
        "=== CFTP WIRESHARK DEMO PACKET PAYLOAD ===\n"
        "Custom File Transfer Protocol running over raw TCP.\n"
        "Notice the newline delimiter in control frames and explicit byte length in data streams.\n"
        "==========================================\n"
    )
    demo_file.write_text(demo_content, encoding="utf-8")

    client = CFTPClient(host=host, port=port, download_dir="downloads")
    try:
        client.connect()
        print("[+] TCP Connection established.")
        time.sleep(0.5)

        print("[*] Sending LIST command...")
        files = client.list_files()
        print(f"[+] Received LIST response ({len(files)} files found).")
        time.sleep(0.5)

        print(f"[*] Uploading '{demo_file.name}' via PUT...")
        put_res = client.put_file(demo_file)
        print(f"[+] PUT completed: success={put_res.success}, SHA-256={put_res.actual_sha256[:16]}...")
        time.sleep(0.5)

        print(f"[*] Downloading '{demo_file.name}' back via GET...")
        get_res = client.get_file(demo_file.name)
        print(f"[+] GET completed: success={get_res.success}, integrity={get_res.integrity_matched}")
        time.sleep(0.5)

        print("[*] Sending QUIT to terminate session...")
        client.quit()
        print("[+] Session closed gracefully. Check your Wireshark capture!")

    except ConnectionError as err:
        print(f"[-] Could not connect to CFTP server: {err}")
        print("[!] Ensure the CFTP server is running: python -m cftp.server")
        sys.exit(1)


if __name__ == "__main__":
    main()
