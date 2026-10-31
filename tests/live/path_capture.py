"""Passive Lab-only AF_PACKET recorder; only encrypted payloads leave the helper.

Runs in the target's network namespace, with NET_RAW on this helper alone. Config/key
arrive on stdin, Docker logging is disabled, and only guard→target-port traffic is kept.
"""

import base64
import json
import signal
import socket
import struct
import sys
import time

from cryptography.fernet import Fernet

MAX_BYTES = 32 * 1024 * 1024
MAX_SECONDS = 2100
stopping = False


def stop(_signal: int, _frame: object) -> None:
    global stopping
    stopping = True


def main() -> None:
    config = json.loads(sys.stdin.readline())
    cipher = Fernet(config["key"].encode())
    source, target, port = config["source"], config["target"], int(config["port"])
    if source != "10.89.10.254" or not target.startswith("10.89.10."):
        raise ValueError("capture is restricted to the isolated live Lab")
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    # Linux constants: ETH_P_IP, SOL_PACKET, PACKET_STATISTICS (not available on macOS).
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))  # type: ignore[attr-defined]
    capture.bind(("eth0", 0))
    capture.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    capture.settimeout(0.5)
    started, size, packets = time.monotonic(), 0, 0

    def emit(value: dict[str, object]) -> None:
        sys.stdout.buffer.write(cipher.encrypt(json.dumps(value).encode()) + b"\n")
        sys.stdout.buffer.flush()

    emit({"kind": "ready"})
    while time.monotonic() - started < MAX_SECONDS and size < MAX_BYTES:
        try:
            raw = capture.recv(65535)
        except TimeoutError:
            if stopping:
                break
            continue
        if len(raw) < 54 or raw[12:14] != b"\x08\x00":
            continue
        ip = raw[14:]
        if ip[0] >> 4 != 4 or ip[9] != 6:
            continue
        src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
        tcp = ip[(ip[0] & 15) * 4 : int.from_bytes(ip[2:4])]
        if src != source or dst != target or len(tcp) < 20:
            continue
        sport, dport, sequence = struct.unpack("!HHI", tcp[:8])
        if dport != port:
            continue
        if int.from_bytes(ip[6:8]) & 0x3FFF:
            emit({"kind": "error", "reason": "fragmented IP packet"})
            break
        payload = tcp[(tcp[12] >> 4) * 4 :]
        size += len(payload)
        packets += 1
        emit(
            {
                "kind": "packet",
                "time": time.time(),
                "source": src,
                "destination": dst,
                "sport": sport,
                "dport": dport,
                "seq": sequence,
                "flags": tcp[13],
                "payload": base64.b64encode(payload).decode(),
            }
        )
    counts = capture.getsockopt(263, 6, 8)
    received, dropped = struct.unpack("II", counts)
    emit(
        {
            "kind": "complete",
            "packets": packets,
            "bytes": size,
            "received": received,
            "dropped": dropped,
            "limit_reached": size >= MAX_BYTES or time.monotonic() - started >= MAX_SECONDS,
        }
    )
    capture.close()


if __name__ == "__main__":
    main()
