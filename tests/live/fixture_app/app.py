"""fixture app 的 HTTP 外殼與純函式入口（T30）。

`handle(mode, request, state)` 是純函式：做路由、分派到 secure/insecure 的 handler，再依
mode 套用全域行為（修補版補安全 header，案例 FX-05；弱點版加 CORS 萬用字元，案例 FX-06）。單元測試
直接呼叫它、不開 socket。`main()` 以 ThreadingHTTPServer 包起同一個 handle，供 live 掃描用。

只用標準函式庫（在 guard 映像的 python 內執行）。啟動：
    python3 -I -B -u -c "import sys; sys.path.insert(0, '/site'); \
        from fixture_app.app import main; main()" <name> <port> <vulnerable>
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from . import insecure, secure
from .helpers import SECURITY_HEADERS
from .model import Mode, Request, Response
from .routes import match
from .store import State, new_state

MAX_BODY = 64 * 1024
AUTH_HEADERS = ("authorization", "x-api-key", "cookie")
_IMPL = {"secure": secure.HANDLERS, "insecure": insecure.HANDLERS}


def handle(mode: Mode, request: Request, state: State) -> Response:
    """路由、分派並套用全域的模式行為。"""
    matched = match(request.method, request.path)
    if matched is None:
        response = Response(status=404, body=b"not found")
    else:
        route, params = matched
        if route.handler == "__405__":
            response = Response(status=405, body=b"method not allowed")
        else:
            bound = dataclasses.replace(request, params=params)
            response = _dispatch(mode, route.handler, bound, state)
    return _decorate(mode, request, response)


def _dispatch(mode: Mode, handler: str, request: Request, state: State) -> Response:
    try:
        return _IMPL[mode][handler](request, state)
    except Exception:  # noqa: BLE001 - 弱點版未處理的例外故意回 500（案例 C1/C2/C4/C5）
        return Response(status=500, body=b"internal server error")


def _decorate(mode: Mode, request: Request, response: Response) -> Response:
    present = {name.lower() for name, _ in response.headers}
    extra: list[tuple[str, str]] = []
    if mode == "secure":
        extra = [(name, value) for name, value in SECURITY_HEADERS if name.lower() not in present]
    elif "access-control-allow-origin" not in present:
        # 弱點版：對每個回應加 CORS 萬用字元（案例 FX-06）。
        origin = request.header("origin") or "*"
        extra = [("Access-Control-Allow-Origin", origin), ("Vary", "Origin")]
    if not extra:
        return response
    return dataclasses.replace(response, headers=response.headers + tuple(extra))


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("latin-1")).hexdigest()[:12]


class Handler(BaseHTTPRequestHandler):
    server_version = "fixture-app"
    sys_version = ""
    protocol_version = "HTTP/1.0"

    def log_message(self, format: str, *args: object) -> None:
        return

    def _request(self) -> Request:
        split = urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(min(length, MAX_BODY)) if length > 0 else b""
        headers = {name.lower(): value for name, value in self.headers.items()}
        content_type = headers.get("content-type", "")
        form: dict[str, str] = {}
        if "x-www-form-urlencoded" in content_type:
            form = dict(parse_qsl(body.decode("latin-1"), keep_blank_values=True))
        query = dict(parse_qsl(split.query, keep_blank_values=True))
        return Request(
            method=self.command,
            path=split.path,
            query=query,
            headers=headers,
            form=form,
            body=body,
            raw_query=split.query,
        )

    def _record(self, request: Request) -> None:
        auth = {
            name: _digest(request.headers[name]) for name in AUTH_HEADERS if name in request.headers
        }
        line: dict[str, Any] = {
            "t": time.time(),
            "site": self.server.name,  # type: ignore[attr-defined]
            "mode": self.server.mode,  # type: ignore[attr-defined]
            "method": request.method,
            "path": self.path,
            "headers": sorted(request.headers),
            "auth": auth,
            "form": sorted(request.form),
        }
        sys.stdout.write(json.dumps(line) + "\n")
        sys.stdout.flush()

    def _handle(self) -> None:
        request = self._request()
        self._record(request)
        response = handle(self.server.mode, request, self.server.state)  # type: ignore[attr-defined]
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        for name, value in response.headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(response.body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(response.body)

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_OPTIONS = do_PATCH = _handle  # noqa: N815


class Server(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], name: str, mode: Mode, state: State) -> None:
        super().__init__(address, Handler)
        self.name = name
        self.mode: Mode = mode
        self.state = state


def main() -> None:
    name, port, vulnerable = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    mode: Mode = "insecure" if vulnerable in {"1", "true", "True"} else "secure"
    server = Server(("0.0.0.0", port), name, mode, new_state())  # noqa: S104 - 隔離的 lab_net
    sys.stdout.write(json.dumps({"site": name, "mode": mode, "ready": True}) + "\n")
    sys.stdout.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()
