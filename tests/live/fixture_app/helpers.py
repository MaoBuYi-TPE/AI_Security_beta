"""fixture app 的回應建構與輸入驗證工具（T30）。純函式，無副作用。"""

from __future__ import annotations

import html
import json
from typing import Any

from .model import Response

# 修補版在每個回應附上的安全 header（弱點版省略；案例 FX-05）。
SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("X-Content-Type-Options", "nosniff"),
    ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
)

# 開放轉址的修補版只允許這些相對目的地（案例 FX-08）。
REDIRECT_ALLOWLIST: frozenset[str] = frozenset({"/", "/search", "/greet"})


def html_response(
    markup: str,
    *,
    status: int = 200,
    headers: tuple[tuple[str, str], ...] = (),
) -> Response:
    return Response(
        status=status,
        body=markup.encode("utf-8"),
        content_type="text/html; charset=utf-8",
        headers=headers,
    )


def json_response(
    payload: Any,
    *,
    status: int = 200,
    headers: tuple[tuple[str, str], ...] = (),
) -> Response:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return Response(
        status=status,
        body=body,
        content_type="application/json; charset=utf-8",
        headers=headers,
    )


def text_response(
    message: str,
    *,
    status: int = 200,
    headers: tuple[tuple[str, str], ...] = (),
) -> Response:
    return Response(
        status=status,
        body=message.encode("utf-8"),
        content_type="text/plain; charset=utf-8",
        headers=headers,
    )


def escape(value: str) -> str:
    """HTML 轉義（修補版用；弱點版的反射型 XSS 故意不呼叫）。"""
    return html.escape(value, quote=True)


def parse_int(value: str | None) -> int | None:
    """嚴格把字串轉成十進位整數；不是整數時回 None（修補版據此回 400）。"""
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    sign = ""
    if text[0] in "+-":
        sign, text = text[0], text[1:]
    if not text.isdigit():
        return None
    return int(sign + text)
