"""addon 用到的 mitmproxy flow 屬性，以 Protocol 描述（docs/DECISIONS.md §15.1）。

guard 的程式不 import mitmproxy：在 3.12 的測試環境以假物件測試，在映像中由真的 flow 滿足同樣的
介面（live 的 contract 測試核對）。只列出用到的屬性；唯讀的以 property 宣告。
"""

from collections.abc import Mapping
from typing import Protocol


class Headers(Protocol):
    @property
    def fields(self) -> tuple[tuple[bytes, bytes], ...]: ...

    def __setitem__(self, key: str, value: str) -> None: ...

    def __delitem__(self, key: str) -> None: ...


class RequestData(Protocol):
    @property
    def method(self) -> bytes: ...

    @property
    def path(self) -> bytes: ...


class Request(Protocol):
    host: str

    @property
    def data(self) -> RequestData: ...

    @property
    def scheme(self) -> str: ...

    @property
    def port(self) -> int: ...

    @property
    def headers(self) -> Headers: ...

    @property
    def trailers(self) -> Headers | None: ...


class Client(Protocol):
    error: str | None

    @property
    def id(self) -> str: ...

    @property
    def peername(self) -> tuple[object, ...] | None: ...


class Server(Protocol):
    error: str | None

    @property
    def address(self) -> tuple[str, int] | None: ...

    @property
    def peername(self) -> tuple[object, ...] | None: ...


class Flow(Protocol):
    """HTTP flow；response 由 addon 以注入的 factory 建立。"""

    response: object | None

    @property
    def request(self) -> Request: ...

    @property
    def client_conn(self) -> Client: ...

    @property
    def server_conn(self) -> Server: ...

    @property
    def metadata(self) -> dict[str, object]: ...

    def kill(self) -> None: ...


class KillableFlow(Protocol):
    """tcp、udp、websocket 的 flow：guard 只會中止它們。"""

    def kill(self) -> None: ...


class ServerConnection(Protocol):
    @property
    def client(self) -> Client: ...

    @property
    def server(self) -> Server: ...


class ResponseFactory(Protocol):
    """mitmproxy.http.Response.make（由啟動程式注入）。"""

    def __call__(self, status: int, content: bytes, headers: Mapping[str, str]) -> object: ...
