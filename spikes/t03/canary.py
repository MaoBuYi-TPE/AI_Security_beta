"""lab_net 上的 canary：接收端證據用的最小 HTTP 伺服器。

把收到的每個請求（method、path、header 名稱，不記 header 值與 body）印到 stdout，
前綴 CANARYLOG。guard 擋下的請求「實際上有沒有送達」就看這裡有沒有紀錄。
用 mitmproxy 映像內的 Python 執行（entrypoint 改成 python）。
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MARKER = "CANARYLOG"
PORT = 8000


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _log_and_reply(self) -> None:
        # 先把 body 讀乾淨，避免 keep-alive 連線上的下一個請求錯位。
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        record = {
            "ts": time.time(),
            "method": self.command,
            "path": self.path.split("?", 1)[0],
            "header_names": sorted(self.headers.keys()),
            "client": self.client_address[0] if self.client_address else None,
        }
        print(f"{MARKER} {json.dumps(record, ensure_ascii=True)}", flush=True)
        body = b'{"canary":"received"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def __getattr__(self, name: str) -> Callable[[], None]:
        # 任何 do_<METHOD>（含 PATCH/TRACE/QUERY 等非標準 method）都記錄並回 200，
        # 確保「canary 沒收到 = 請求未送達」這個證據對所有 method 都成立。
        if name.startswith("do_"):
            return self._log_and_reply
        raise AttributeError(name)

    def log_message(self, *args: object) -> None:
        # 關閉 BaseHTTPRequestHandler 預設的 stderr 存取紀錄，只留我們的 CANARYLOG。
        return


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"{MARKER} listening on {PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
