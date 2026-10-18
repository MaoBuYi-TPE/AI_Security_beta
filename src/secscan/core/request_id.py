"""每個請求一個由伺服器產生的 request_id：放在 request.state 與 X-Request-ID 回應 header。

不採用 client 送來的值，避免被拿來注入日誌或偽造追蹤（docs/API_CONTRACT.md §12）。
"""

from uuid import uuid4

from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

REQUEST_ID_HEADER = "X-Request-ID"
_STATE_KEY = "request_id"


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

        await self._app(scope, receive, send_with_request_id)


def request_id_of(request: Request) -> str:
    """取得目前請求的 request_id；沒有經過 middleware 時另外產生一個，錯誤回應仍可追蹤。"""
    value = getattr(request.state, _STATE_KEY, None)
    return value if isinstance(value, str) else new_request_id()
