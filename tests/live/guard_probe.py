"""live 測試的探針（在 scan_net 上的容器內執行）：把原始的 HTTP 請求逐一送到指定的位址。

stdin 是 JSON：{"target": "ip:port", "cases": [{"name": ..., "raw": base64}]}（帳密在 raw 中，
不出現在 argv）。stdout 每個 case 一行 JSON：狀態碼、X-Secscan-Guard 與 Location（沒有回應時是
連線錯誤的類別）。每個 case 一條新的連線。

watch 模式（{"target": ..., "watch": {"raw": base64, "interval": 秒, "seconds": 秒}}）：在一段時間內
反覆送同一個請求，每次一行 JSON（含容器內的時間），用來觀察取消前後的轉變。
"""

import base64
import json
import socket
import sys
import time

TIMEOUT_SECONDS = 5


def _response(connection: socket.socket) -> bytes:
    data = b""
    while True:
        try:
            chunk = connection.recv(65536)
        except TimeoutError:
            break
        if not chunk:
            break
        data += chunk
        head, separator, body = data.partition(b"\r\n\r\n")
        if separator and _complete(head, body):
            break
    return data


def _complete(head: bytes, body: bytes) -> bool:
    for line in head.split(b"\r\n")[1:]:
        key, _, value = line.partition(b":")
        if key.strip().lower() == b"content-length":
            return len(body) >= int(value.strip())
    return head.startswith(b"HTTP/1.1 1")


def _header(head: str, name: str) -> str | None:
    for line in head.split("\r\n")[1:]:
        key, _, value = line.partition(":")
        if key.strip().lower() == name:
            return value.strip()
    return None


def _send(target: str, raw: bytes) -> dict[str, object]:
    host, _, port = target.rpartition(":")
    try:
        with socket.create_connection((host, int(port)), timeout=TIMEOUT_SECONDS) as connection:
            connection.sendall(raw)
            data = _response(connection)
    except OSError as exc:
        return {"status": None, "error": type(exc).__name__}
    head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    # 100 Continue 之後才是真正的回應。
    while head.startswith("HTTP/1.1 100"):
        data = data.split(b"\r\n\r\n", 1)[1]
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    parts = head.split(" ", 2)
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
    return {
        "status": status,
        "reason": _header(head, "x-secscan-guard"),
        "location": _header(head, "location"),
        "error": None,
    }


def _watch(target: str, watch: dict[str, object]) -> None:
    raw = base64.b64decode(str(watch["raw"]))
    deadline = time.time() + float(str(watch["seconds"]))
    while time.time() < deadline:
        started = time.time()
        result = _send(target, raw)
        sys.stdout.write(json.dumps({"t": started, **result}) + "\n")
        sys.stdout.flush()
        time.sleep(float(str(watch["interval"])))


def main() -> None:
    request = json.load(sys.stdin)
    if "watch" in request:
        _watch(request["target"], request["watch"])
        return
    for case in request["cases"]:
        result = _send(request["target"], base64.b64decode(case["raw"]))
        sys.stdout.write(json.dumps({"name": case["name"], **result}) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
