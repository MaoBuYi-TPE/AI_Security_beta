"""假的 Docker Engine API：取代 Docker SDK 的 HTTP adapter，記錄請求、回傳預先設定的回應。

不開任何 socket（unit 測試以 pytest-socket 與 tests/isolation.py 封鎖網路與 Docker daemon）。
"""

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

import requests
from requests.adapters import BaseAdapter
from requests.structures import CaseInsensitiveDict

type Handler = Callable[["Recorded"], tuple[int, object]]


@dataclass(frozen=True)
class Recorded:
    method: str
    path: str
    query: Mapping[str, str]
    body: Any


@dataclass
class StubDocker(BaseAdapter):
    """routes：(method, 解碼後的 path) → handler；沒有設定的一律 404。"""

    routes: dict[tuple[str, str], Handler] = field(default_factory=dict)
    requests_seen: list[Recorded] = field(default_factory=list)
    fail_with: type[Exception] | None = None

    def __post_init__(self) -> None:
        super().__init__()

    def reply(self, method: str, path: str, status: int, payload: object = None) -> None:
        self.routes[(method, path)] = lambda _request: (status, payload)

    def send(  # type: ignore[override]
        self, request: requests.PreparedRequest, **_kwargs: object
    ) -> requests.Response:
        url = urlsplit(request.url or "")
        body = json.loads(request.body) if request.body else None
        recorded = Recorded(
            method=request.method or "",
            path=unquote(url.path),
            query=dict(parse_qsl(url.query)),
            body=body,
        )
        self.requests_seen.append(recorded)
        if self.fail_with is not None:
            raise self.fail_with("stub connection failure")
        handler = self.routes.get((recorded.method, recorded.path))
        status, payload = (
            handler(recorded) if handler is not None else (404, {"message": "No such object"})
        )
        response = requests.Response()
        response.status_code = status
        response.headers = CaseInsensitiveDict({"Content-Type": "application/json"})
        response._content = b"" if payload is None else json.dumps(payload).encode()
        response.url = request.url or ""
        response.request = request
        response.reason = "stub"
        return response

    def close(self) -> None:
        pass

    @property
    def paths(self) -> list[tuple[str, str]]:
        return [(item.method, item.path) for item in self.requests_seen]
