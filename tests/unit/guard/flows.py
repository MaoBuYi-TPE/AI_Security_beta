"""模擬 mitmproxy flow 的假物件（只有 guard 用到的部分，語意依 docs/DECISIONS.md §15 的實測）。

- headers.fields 是原始的 (bytes, bytes)；指定與刪除都不分大小寫，刪除不存在的名稱拋 KeyError。
- 設定 request.host 時，Host header 會被改成 `ip:port`（mitmproxy 的 _update_host_and_authority）。
- request.data.method／path 是轉送時的原始 bytes。
live 的 contract 測試以映像內真的 mitmproxy flow 核對同一組行為。
"""

from collections.abc import Mapping
from dataclasses import dataclass, field


class FakeHeaders:
    def __init__(self, fields: list[tuple[str, str]] | None = None) -> None:
        self._fields = [(name, value) for name, value in fields or []]

    @property
    def fields(self) -> tuple[tuple[bytes, bytes], ...]:
        return tuple(
            (name.encode("latin-1"), value.encode("latin-1")) for name, value in self._fields
        )

    def __setitem__(self, name: str, value: str) -> None:
        kept = [(key, item) for key, item in self._fields if key.lower() != name.lower()]
        self._fields = [*kept, (name, value)]

    def __delitem__(self, name: str) -> None:
        kept = [(key, item) for key, item in self._fields if key.lower() != name.lower()]
        if len(kept) == len(self._fields):
            raise KeyError(name)
        self._fields = kept

    def get_all(self, name: str) -> list[str]:
        return [value for key, value in self._fields if key.lower() == name.lower()]

    def names(self) -> list[str]:
        return [key for key, _ in self._fields]


@dataclass
class FakeRequestData:
    method: bytes
    path: bytes


class FakeRequest:
    def __init__(
        self,
        *,
        method: str = "GET",
        target: str = "/api/items/7",
        scheme: str = "http",
        host: str = "lab-target",
        port: int = 8080,
        headers: list[tuple[str, str]] | None = None,
        trailers: FakeHeaders | None = None,
    ) -> None:
        self.data = FakeRequestData(method=method.encode("latin-1"), path=target.encode("latin-1"))
        self.scheme = scheme
        self._host = host
        self.port = port
        self.headers = FakeHeaders(headers)
        self.trailers = trailers

    @property
    def host(self) -> str:
        return self._host

    @host.setter
    def host(self, value: str) -> None:
        self._host = value
        if self.headers.get_all("host"):
            self.headers["Host"] = f"{value}:{self.port}"


@dataclass
class FakeClient:
    id: str = "client-1"
    peername: tuple[str, int] | None = ("10.89.8.2", 40000)
    error: str | None = None


@dataclass
class FakeServer:
    address: tuple[str, int] | None = None
    error: str | None = None
    peername: tuple[str, int] | None = None


@dataclass
class FakeResponse:
    status_code: int
    content: bytes
    headers: dict[str, str]


def make_response(status: int, content: bytes, headers: Mapping[str, str]) -> FakeResponse:
    return FakeResponse(status_code=status, content=content, headers=dict(headers))


@dataclass
class FakeFlow:
    request: FakeRequest = field(default_factory=FakeRequest)
    client_conn: FakeClient = field(default_factory=FakeClient)
    server_conn: FakeServer = field(default_factory=FakeServer)
    response: object | None = None
    metadata: dict[str, object] = field(default_factory=dict)
    killed: bool = False

    def kill(self) -> None:
        self.killed = True


@dataclass
class FakeServerConnection:
    client: FakeClient
    server: FakeServer
