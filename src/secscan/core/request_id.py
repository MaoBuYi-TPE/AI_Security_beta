"""每個請求一個由伺服器產生的 request_id：放在 request.state 與 X-Request-ID 回應 header。

不採用 client 送來的值，避免被拿來注入日誌或偽造追蹤（docs/API_CONTRACT.md §12）。
請求處理期間也放在 context variable，service 等不經手 Request 物件的程式碼寫日誌時可以帶上。
"""

from contextvars import ContextVar
from uuid import uuid4

from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

REQUEST_ID_HEADER = "X-Request-ID"
_STATE_KEY = "request_id"
_current_request_id: ContextVar[str | None] = ContextVar("request_id", default=None)


def new_request_id() -> str:
    return uuid4().hex


class RequestIdMiddleware:
    """純 ASGI middleware（不用 BaseHTTPMiddleware，避免它對串流與 contextvars 的副作用）。"""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        request_id = new_request_id()
        scope.setdefault("state", {})[_STATE_KEY] = request_id

        async def send_with_request_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)[REQUEST_ID_HEADER] = request_id
            await send(message)

        token = _current_request_id.set(request_id)
        try:
            await self._app(scope, receive, send_with_request_id)
        finally:
            _current_request_id.reset(token)


def request_id_of(request: Request) -> str:
    """取得目前請求的 request_id；沒有經過 middleware 時另外產生一個，錯誤回應仍可追蹤。"""
    value = getattr(request.state, _STATE_KEY, None)
    return value if isinstance(value, str) else new_request_id()


def current_request_id() -> str | None:
    """目前請求的 request_id；不在請求中（例如 CLI）時為 None。"""
    return _current_request_id.get()
