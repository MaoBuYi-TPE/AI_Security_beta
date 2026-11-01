"""fixture app 的請求／回應模型（T30）。純資料，無副作用。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

# secure = 修補版（負例）；insecure = 弱點版（正例）。掃描中途不切換。
Mode = Literal["secure", "insecure"]

DEFAULT_CONTENT_TYPE = "text/plain; charset=utf-8"


@dataclass(frozen=True)
class Request:
    """外殼解析後交給純函式的請求（path 不含 query；header 名稱一律小寫）。"""

    method: str
    path: str
    params: dict[str, str] = field(default_factory=dict)
    query: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    form: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    raw_query: str = ""

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())

    def bearer(self) -> str | None:
        value = self.header("authorization")
        if value is None or not value.lower().startswith("bearer "):
            return None
        return value[len("bearer ") :].strip()


@dataclass(frozen=True)
class Response:
    """純函式回傳的回應；由外殼寫到 socket。"""

    status: int
    body: bytes = b""
    content_type: str = DEFAULT_CONTENT_TYPE
    headers: tuple[tuple[str, str], ...] = ()
