"""ZAP 的 live 測試用的小型網站（在容器內執行；docs/DECISIONS.md §18.10）。

只在 live 自己的 lab 網路上，不是真的靶機：頁面有範圍內的連結、grant 排除的 path、另一個 origin
的連結與 2 MiB 的 JS；API 有 /api/items 與 /api/items/{id}；/me 是 preflight 的受保護端點。
每個請求輸出一行 JSON（收包證據）：時間（VM 的時鐘）、method、path（含 query）、header 的名稱、
認證 header 值的 sha256 前 12 碼（不記值）、表單 body 的參數名稱（量測 _method）。
HTTP/1.0，每個連線一個請求。
  python3 zap_site.py <名稱> <port>
"""

import hashlib
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

MAX_BODY = 64 * 1024
AUTH_HEADERS = ("authorization", "x-api-key", "cookie")
BIG_JS = b"var filler = '" + b"a" * (2 * 1024 * 1024) + b"';\n"
HOME = b"""<!doctype html><html><head><title>lab shop</title>
<script src="/static/big.js"></script></head><body>
<a href="/shop?item=1">item 1</a> <a href="/shop?item=2">item 2</a>
<a href="/search?q=hello">search</a> <a href="/admin">admin</a>
<a href="http://lab-canary:8080/outside">elsewhere</a>
<form action="/search" method="get"><input name="q"><input type="submit"></form>
<form action="/login" method="post"><input name="user"><input name="pass" type="password">
<input type="submit"></form>
</body></html>"""
PAGE = b"<!doctype html><html><body><p>page</p><a href='/'>home</a></body></html>"
ITEMS = b'[{"id": 1, "name": "apple"}, {"id": 2, "name": "pear"}]'
ITEM = b'{"id": 1, "name": "apple"}'


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("latin-1")).hexdigest()[:12]


class Handler(BaseHTTPRequestHandler):
    server_version = "lab-site"
    sys_version = ""

    def log_message(self, format: str, *args: object) -> None:
        return

    def _record(self, form: list[str]) -> None:
        names = sorted({name.lower() for name in self.headers})
        auth = {name: _digest(self.headers[name]) for name in AUTH_HEADERS if name in self.headers}
        line = {
            "t": time.time(),
            "site": self.server.name,  # type: ignore[attr-defined]
            "method": self.command,
            "path": self.path,
            "headers": names,
            "auth": auth,
            "form": form,
        }
        sys.stdout.write(json.dumps(line) + "\n")
        sys.stdout.flush()

    def _form(self) -> list[str]:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(min(length, MAX_BODY)) if length > 0 else b""
        if "x-www-form-urlencoded" not in (self.headers.get("Content-Type") or ""):
            return []
        pairs = parse_qsl(body.decode("latin-1"), keep_blank_values=True)
        return sorted({name for name, _ in pairs})

    def _respond(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _handle(self) -> None:
        form = self._form()
        self._record(form)
        path = urlsplit(self.path).path
        authorized = any(name in self.headers for name in AUTH_HEADERS)
        if path == "/":
            self._respond(200, HOME, "text/html")
        elif path == "/static/big.js":
            self._respond(200, BIG_JS, "application/javascript")
        elif path in {"/shop", "/search", "/admin", "/login"}:
            self._respond(200, PAGE, "text/html")
        elif path == "/me":
            body = b'{"status": "success"}' if authorized else b'{"status": "fail"}'
            self._respond(200 if authorized else 401, body, "application/json")
        elif path == "/api/items":
            self._respond(200, ITEMS, "application/json")
        elif path.startswith("/api/items/"):
            status = 204 if self.command == "DELETE" else 200
            self._respond(status, b"" if status == 204 else ITEM, "application/json")
        else:
            self._respond(404, b"not found", "text/plain")

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_OPTIONS = do_PATCH = _handle  # noqa: N815


def main(name: str, port: int) -> None:
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)  # noqa: S104
    server.name = name  # type: ignore[attr-defined]
    sys.stdout.write(json.dumps({"site": name, "ready": True}) + "\n")
    sys.stdout.flush()
    server.serve_forever()


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]))
