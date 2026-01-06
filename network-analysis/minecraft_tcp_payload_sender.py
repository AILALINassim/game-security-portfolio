"""
minecraft_tcp_payload_sender.py

Replays a raw TCP payload toward a local Minecraft server endpoint.
This script is intended for traffic reproduction and protocol analysis
during network inspection exercises (e.g. Wireshark analysis).

Scope:
- Client-side TCP payload injection
- No protocol compliance guarantee
- Educational and analytical usage only
"""

import socket
import time
import sys

SERVER_IP = "127.0.0.1"
SERVER_PORT = 25565

HEX_STREAM = (
    "02000000450003b433174000800600007f0000017f00000163dddaca9f2bb534a5161b3e50"
    "1820f9475b00009e42c7aa971c5ce71f77ffd55c8ce59bfb8ae9956be4a990d9b4c1aef77f9"
    "47263445af0db9952d4f487979e35d3111b0a9c061a39f7d12434a7a9fe9f7e7f8ed7eb8b20"
    "290a24f1498f13dd1b85e39181f4e1386133aa71cb5413e53427341b83443980524098553d"
    "757f0e4a7cc256537009f0a1dc88808b3e21ed1fc14b9f6ef0f724affee4e846f547d965e13"
    "0a5918444c36e4c0c3b6aa220205d3d2ebed19a30e052072f289a2ac136828be810a39943e1"
    "e2f98db529aba349e7b7351d11bdcba979ef915b4efe6f0226816499af6f23db76dabd31d47"
    "8affe2c51f7b3c9ea6d2bf67af9d0610818c42f263b8d16f317f08a4bfd2cddb1b0edbed757"
    "b57c489c91d498bcc968e27a4e8eea712ea5053d89a283f076a2cddaf3a88d8a01b037fa21"
)

FORCE_SOURCE_BIND = False
SOURCE_IP = "127.0.0.1"
SOURCE_PORT = 56010


def build_payload(hex_stream: str) -> bytes:
    try:
        return bytes.fromhex(hex_stream.replace(" ", "").replace("\n", ""))
    except ValueError as exc:
        print(f"[ERROR] Invalid hex stream: {exc}")
        sys.exit(1)


def send_payload(payload: bytes) -> None:
    try:
        if FORCE_SOURCE_BIND:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.bind((SOURCE_IP, SOURCE_PORT))
            sock.connect((SERVER_IP, SERVER_PORT))
        else:
            sock = socket.create_connection((SERVER_IP, SERVER_PORT), timeout=5)

        time.sleep(0.05)
        sock.sendall(payload)
        sock.close()
        print(f"[OK] Payload sent ({len(payload)} bytes)")

    except Exception as exc:
        print(f"[ERROR] Payload transmission failed: {exc}")


def main() -> None:
    payload = build_payload(HEX_STREAM)
    send_payload(payload)


if __name__ == "__main__":
    main()
