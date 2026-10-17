"""T03 spike 專用的 mitmproxy addon：量測工具 + 最小 allowlist。

這不是 M2 的 egress guard。它只做這些事，用來取得 spike 需要的證據：
  - 只允許 plain HTTP；一律拒絕 CONNECT 與 Upgrade。
  - 依 proxy 帳號比對 host:port allowlist（policy 檔以唯讀掛載）。
  - 掃描器帳號額外禁止破壞性操作（DELETE 與 /createdb）。
  - 每個請求印一行 JSONL 到 stdout（前綴 GUARDLOG），只記中繼資料，不記 header 值或 body。

安全姿態：fail-closed。policy 載入失敗 → 空 allowlist（全部 403）；判斷過程若丟例外 → 該請求回 500。
（mitmproxy 的 addon 例外預設會被吞掉並放行，所以判斷碼自行包 try/except。）

M2 才做的：DNS/IP 綁定、共享預算、redirect 重新檢查、HTTPS、完整路徑正規化。

policy 檔（GUARD_POLICY，JSON）結構見 spikes/t03/policy.json。
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from typing import Any
from urllib.parse import unquote

from mitmproxy import http

logger = logging.getLogger("guard_spike")

MARKER = "GUARDLOG"


def _load_policy() -> dict[str, Any]:
    """載入 policy；任何錯誤都回傳空 allowlist（fail-closed：全部拒絕）。"""
    try:
        with open(os.environ["GUARD_POLICY"], encoding="utf-8") as handle:
            data: dict[str, Any] = json.load(handle)
    except (KeyError, OSError, ValueError):
        logger.critical("guard policy 載入失敗，改為 deny-all", exc_info=True)
        return {"allow": {}}
    return data


def _normalize_path(raw: str) -> str:
    """給禁用比對用的保守正規化：去 query、percent-decode、去 /./、轉小寫。"""
    path = unquote(raw.split("?", 1)[0])
    parts = [seg for seg in path.split("/") if seg not in ("", ".")]
    return ("/" + "/".join(parts)).lower()


class GuardSpike:
    def __init__(self) -> None:
        self.policy = _load_policy()
        self.allow: dict[str, set[str]] = {
            acct: set(hosts) for acct, hosts in self.policy.get("allow", {}).items()
        }
        self.scanner_accounts: set[str] = set(self.policy.get("scanner_accounts", []))
        self.deny_methods: set[str] = {
            m.upper() for m in self.policy.get("deny_methods_for_scanners", [])
        }
        self.deny_path_substrings: list[str] = [
            s.lower() for s in self.policy.get("deny_path_substrings_for_scanners", [])
        ]

    # --- helpers -------------------------------------------------------
    def _account(self, flow: http.HTTPFlow) -> str:
        meta = flow.metadata.get("proxyauth")
        value = meta[0] if isinstance(meta, (tuple, list)) and meta else meta
        if isinstance(value, bytes):
            value = value.decode("utf-8", "replace")
        return value or "anonymous"

    def _emit(self, flow: http.HTTPFlow, decision: str, status: int | None) -> None:
        req = flow.request
        auth = req.headers.get("Authorization")
        record = {
            "ts": time.time(),
            "account": self._account(flow),
            "method": req.method,
            "host": req.host,
            "port": req.port,
            "path": req.path.split("?", 1)[0],
            "query_keys": sorted(req.query.keys()),
            "decision": decision,
            "status": status,
            "resp_bytes": len(flow.response.raw_content or b"") if flow.response else None,
            "upstream": list(flow.server_conn.peername) if flow.server_conn.peername else None,
            "has_authorization": auth is not None,
            "authorization_sha12": hashlib.sha256(auth.encode()).hexdigest()[:12] if auth else None,
        }
        # ensure_ascii=True：避免 U+2028／NEL／lone surrogate 破壞逐行消費或讓 print 拋例外而漏記。
        print(f"{MARKER} {json.dumps(record, ensure_ascii=True)}", flush=True)

    def _deny(self, flow: http.HTTPFlow, status: int, reason: str) -> None:
        flow.response = http.Response.make(
            status, f"guard-spike denied: {reason}\n".encode(), {"Content-Type": "text/plain"}
        )
        self._emit(flow, f"deny:{reason}", status)

    # --- hooks ---------------------------------------------------------
    def running(self) -> None:
        logger.warning("%s guard-spike ready (accounts=%s)", MARKER, sorted(self.allow))

    def http_connect(self, flow: http.HTTPFlow) -> None:
        # 內建 proxyauth 先跑；未認證的 CONNECT 它已回 407，保留即可。
        if flow.response is not None:
            return
        # P0 只支援 plain HTTP；已認證的 CONNECT（HTTPS/tunnel）一律拒絕。
        self._deny(flow, 403, "connect")

    def request(self, flow: http.HTTPFlow) -> None:
        # fail-closed：判斷過程的任何例外都拒絕，不讓 mitmproxy 吞掉例外後放行。
        try:
            self._decide(flow)
        except Exception:  # guard 必須 fail-closed：任何例外都拒絕
            logger.exception("guard 判斷發生例外，拒絕該請求")
            self._deny(flow, 500, "guard-error")

    def _decide(self, flow: http.HTTPFlow) -> None:
        # proxyauth 內建 addon 先跑；驗證失敗它已設好 407，不要覆寫。
        if flow.response is not None:
            if flow.response.status_code == 407:
                self._emit(flow, "deny:proxyauth", 407)
            return

        account = self._account(flow)

        if flow.request.scheme != "http":
            self._deny(flow, 403, "scheme")
            return

        if "Upgrade" in flow.request.headers:
            self._deny(flow, 403, "upgrade")
            return

        target = f"{flow.request.host}:{flow.request.port}"
        if target not in self.allow.get(account, set()):
            self._deny(flow, 403, "not-in-allowlist")
            return

        if account in self.scanner_accounts:
            if flow.request.method.upper() in self.deny_methods:
                self._deny(flow, 403, "method")
                return
            path = _normalize_path(flow.request.path)
            if any(sub in path for sub in self.deny_path_substrings):
                self._deny(flow, 403, "path")
                return
        # 允許：放行，到 response hook 再記錄實際結果與上游 IP。

    def response(self, flow: http.HTTPFlow) -> None:
        # 只記錄真正打到上游的請求（deny 已在 request/http_connect 記過，那時沒有 peername）。
        if flow.response is not None and flow.server_conn.peername is not None:
            self._emit(flow, "allow", flow.response.status_code)

    def error(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            self._emit(flow, "error", None)


addons = [GuardSpike()]
