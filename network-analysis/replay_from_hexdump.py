"""
replay_from_hexdump.py

Extracts hex bytes from a Wireshark "Follow TCP Stream" hexdump export and replays
the reconstructed payload to a local endpoint.

Notes:
- This is a raw TCP payload replay. It does not attempt to be protocol-compliant.
- Intended for local/lab analysis and reproducibility (e.g., loopback captures).
"""

from __future__ import annotations

import pathlib
import re
import socket
import sys
import time


# --- Configuration (edit as needed) ---
INPUT_FILE = "client_stream_hex.txt"
SERVER_IP = "127.0.0.1"
SERVER_PORT = 25565
SLEEP_BEFORE_SEND_SEC = 0.02
SOCKET_TIMEOUT_SEC = 5
# -------------------------------------


HEX_BYTE_RE = re.compile(r"\b([0-9A-Fa-f]{2})\b")


def load_text(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        raise RuntimeError(f"Failed to read input file: {path}") from exc


def extract_hex_bytes(text: str) -> bytes:
    hex_pairs = HEX_BYTE_RE.findall(text)
    if not hex_pairs:
        raise ValueError("No hex byte pairs were found in the input text.")

    hex_stream = "".join(hex_pairs)
    try:
        return bytes.fromhex(hex_stream)
    except ValueError as exc:
        raise ValueError(f"Invalid hex stream after extraction: {exc}") from exc


def send_payload(payload: bytes) -> None:
    with socket.create_connection((SERVER_IP, SERVER_PORT), timeout=SOCKET_TIMEOUT_SEC) as sock:
        time.sleep(SLEEP_BEFORE_SEND_SEC)
        sock.sendall(payload)


def main() -> int:
    input_path = pathlib.Path(INPUT_FILE)

    if not input_path.exists():
        print(f"[ERROR] Input file not found: {input_path}")
        return 1

    try:
        text = load_text(input_path)
        payload = extract_hex_bytes(text)
    except Exception as exc:
        print(f"[ERROR] {exc}")
        return 1

    print(f"[OK] Payload ready: {len(payload)} bytes extracted from hexdump")

    try:
        send_payload(payload)
    except Exception as exc:
        print(f"[ERROR] Failed to send payload: {exc}")
        return 1

    print("[OK] Payload sent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
