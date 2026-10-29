"""live 測試的接收端（在容器內執行）：記下每一個 TCP accept 與收到的請求（docs/DECISIONS.md §15）。

收包證據以這裡的紀錄為準（CLAUDE.md §12：不能只看 guard 回了什麼）。每個 accept 輸出一行 JSON：
名稱、來源 IP、method、path、Host、header 的名稱（不含值）、是否帶 Proxy-Authorization。
  python3 receiver.py <名稱> <port>
固定的 path 會回 redirect（SEC-03）：/api/items/redirect → canary；/api/items/redirect-excluded →
同一個 origin 的排除 path。/me 是 preflight 的受保護端點（T12）：帶 Authorization 回 200 與
{"status": "success"}，沒帶回 401。
"""

import json
import socket
import sys

MAX_HEAD = 64 * 1024
REDIRECTS = {
    "/api/items/redirect": "http://lab-canary:8080/api/items/7",
    "/api/items/redirect-excluded": "/api/admin",
}


def _head(connection: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data and len(data) < MAX_HEAD:
        chunk = connection.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def _record(name: str, peer: str, head: bytes) -> dict[str, object]:
    lines = head.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
    method, _, rest = lines[0].partition(" ")
    path = rest.rpartition(" ")[0] if " " in rest else rest
    headers = [line.split(":", 1) for line in lines[1:] if ":" in line]
    names = [key.strip() for key, _ in headers]
    hosts = [value.strip() for key, value in headers if key.strip().lower() == "host"]
    return {
        "receiver": name,
        "peer": peer,
        "method": method,
        "path": path,
        "host": hosts,
        "header_names": names,
        "proxy_authorization": any(key.lower().startswith("proxy-") for key in names),
    }


def _respond(connection: socket.socket, path: str, *, authorized: bool) -> None:
    if path == "/me":
        status, body = (
            ("200 OK", b'{"status": "success"}') if authorized else ("401 Unauthorized", b"{}")
        )
        head = f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\n"
        head += f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        connection.sendall(head.encode("ascii") + body)
        return
    location = REDIRECTS.get(path)
    if location is not None:
        head = f"HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n"
        connection.sendall(head.encode("ascii") + b"Connection: close\r\n\r\n")
        return
    connection.sendall(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n"
        b"Connection: close\r\n\r\nok"
    )


def main(name: str, port: int) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))  # noqa: S104 - 容器內的測試接收端，只接在 internal network
    server.listen(64)
    sys.stdout.write(json.dumps({"receiver": name, "ready": True}) + "\n")
    sys.stdout.flush()
    while True:
        connection, (peer, _) = server.accept()
        with connection:
            connection.settimeout(3)
            try:
                head = _head(connection)
            except OSError:
                head = b""
            record = _record(name, peer, head)
            sys.stdout.write(json.dumps(record) + "\n")
            sys.stdout.flush()
            try:
                authorized = b"\r\nauthorization:" in head.split(b"\r\n\r\n", 1)[0].lower()
                _respond(connection, str(record["path"]), authorized=authorized)
            except OSError:
                continue


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]))
