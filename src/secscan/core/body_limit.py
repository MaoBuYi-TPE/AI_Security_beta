"""請求大小上限（pure ASGI，docs/DECISIONS.md §11.1）。

FastAPI 會先把整個 JSON body 讀進記憶體，這裡在那之前擋下太大的請求：
- 有 Content-Length：超過上限就直接回 413，不讀 body；格式不對回 400。
- 沒有 Content-Length（chunked）：逐塊累計，超過上限時從 receive 拋出框架的 HTTPException(413)。
  FastAPI 解析 body 時會把框架的 HTTPException 原樣往外拋（其他例外會變成 400），
  再由 core.errors 的 handler 轉成 envelope。

規格上傳另有更小的上限與自己的錯誤碼（specs.dependencies）。
"""

from http import HTTPStatus

from starlette.datastructures import Headers
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from secscan.core.errors import REQUEST_TOO_LARGE_MESSAGE, AppError, ErrorCode, error_response

MAX_REQUEST_BODY_BYTES = 2 * 1024 * 1024
# Content-Length 超過這個位數就一定超過上限；先比長度，超長的字串不交給 int()。
_MAX_LENGTH_DIGITS = 18


class BodyLimitMiddleware:
    def __init__(self, app: ASGIApp, *, max_bytes: int = MAX_REQUEST_BODY_BYTES) -> None:
        self._app = app
        self._max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        rejection = self._check_declared(Headers(scope=scope).get("content-length"))
        if rejection is not None:
            await error_response(Request(scope), rejection)(scope, receive, send)
            return
        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self._max_bytes:
                    raise HTTPException(status_code=HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return message

        await self._app(scope, limited_receive, send)

    def _check_declared(self, declared: str | None) -> AppError | None:
        if declared is None:
            return None
        if not (declared.isascii() and declared.isdigit()):
            return AppError(
                status_code=HTTPStatus.BAD_REQUEST,
                code=ErrorCode.INVALID_REQUEST,
                message="Content-Length 必須是十進位的整數。",
            )
        if len(declared) > _MAX_LENGTH_DIGITS or int(declared) > self._max_bytes:
            return AppError(
                status_code=HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                code=ErrorCode.REQUEST_TOO_LARGE,
                message=REQUEST_TOO_LARGE_MESSAGE,
            )
        return None
