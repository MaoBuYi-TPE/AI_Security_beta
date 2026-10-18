"""穩定錯誤碼與失敗 envelope（docs/API_CONTRACT.md §1、§12）。

所有錯誤回應都是 envelope，並帶 request_id：
- AppError：service 與 route 表示「可預期、可對外說明」的錯誤。
- 框架產生的 HTTP 錯誤（404 路徑不存在、405 方法不符…）：對應固定錯誤碼與訊息。
- 請求驗證失敗（422）：只列出欄位位置，不回顯輸入值（可能是秘密）。
- 未處理的例外（500）：通用訊息；伺服器端記下 request_id 與例外類別，不記例外訊息。
"""

import logging
from collections.abc import Mapping
from enum import StrEnum
from http import HTTPStatus

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from secscan.core.envelope import Envelope, ErrorDetail
from secscan.core.request_id import REQUEST_ID_HEADER, request_id_of

logger = logging.getLogger(__name__)

# 422 訊息最多列出幾個欄位、每個位置最多幾個字元（位置可能含 client 送來的欄位名稱）。
MAX_REPORTED_FIELDS = 5
MAX_LOCATION_LENGTH = 64


class ErrorCode(StrEnum):
    """對外的穩定錯誤碼；隨功能逐步加入（M1 起）。"""

    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
    METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
    HTTP_ERROR = "HTTP_ERROR"
    INVALID_REQUEST = "INVALID_REQUEST"
    DEPENDENCY_UNAVAILABLE = "DEPENDENCY_UNAVAILABLE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class AppError(Exception):
    """可預期的 API 錯誤：HTTP 狀態碼、穩定錯誤碼與給使用者看的訊息。"""

    def __init__(self, *, status_code: int, code: ErrorCode, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


_HTTP_ERRORS: dict[int, tuple[ErrorCode, str]] = {
    HTTPStatus.NOT_FOUND: (ErrorCode.RESOURCE_NOT_FOUND, "找不到資源。"),
    HTTPStatus.METHOD_NOT_ALLOWED: (ErrorCode.METHOD_NOT_ALLOWED, "不支援這個 HTTP 方法。"),
}


def failure_envelope(code: ErrorCode, message: str, request_id: str) -> Envelope[None]:
    return Envelope[None](
        success=False,
        error=ErrorDetail(code=code, message=message, request_id=request_id),
    )


def _failure_response(
    request: Request,
    status_code: int,
    code: ErrorCode,
    message: str,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    body = failure_envelope(code, message, request_id_of(request))
    return JSONResponse(
        status_code=status_code, content=body.model_dump(mode="json"), headers=headers
    )


async def app_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """把 AppError 轉成失敗 envelope。只註冊給 AppError；收到其他例外時原樣拋出，不吞掉。"""
    if not isinstance(exc, AppError):
        raise exc
    return _failure_response(request, exc.status_code, exc.code, exc.message)


async def http_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """框架的 HTTP 錯誤：保留必要的 header（例如 405 的 Allow），不回傳 detail 原文。"""
    if not isinstance(exc, StarletteHTTPException):
        raise exc
    # 以 int 查表：非標準狀態碼（例如 499）不會因 HTTPStatus(...) 轉換失敗而變成 500。
    generic = (ErrorCode.HTTP_ERROR, f"請求無法處理（HTTP {exc.status_code}）。")
    code, message = _HTTP_ERRORS.get(exc.status_code, generic)
    return _failure_response(request, exc.status_code, code, message, headers=exc.headers)


async def validation_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """請求驗證失敗：只列出欄位位置（例如 query.page），不回顯 input、ctx 等內容。"""
    if not isinstance(exc, RequestValidationError):
        raise exc
    locations = [_location(error.get("loc", ())) for error in exc.errors()]
    listed = "、".join(locations[:MAX_REPORTED_FIELDS])
    if len(locations) > MAX_REPORTED_FIELDS:
        listed += "…"
    return _failure_response(
        request,
        HTTPStatus.UNPROCESSABLE_ENTITY,
        ErrorCode.INVALID_REQUEST,
        f"請求格式不正確：{listed}",
    )


async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """未處理的例外：通用訊息加 request_id。

    這個 handler 由最外層的 ServerErrorMiddleware 呼叫，RequestIdMiddleware 加不到 header，
    所以這裡自己帶上。完整 traceback 由 ASGI server 記錄；這裡只記可對應的 request_id
    與例外類別，不記例外訊息（可能含秘密或個資）。
    """
    request_id = request_id_of(request)
    logger.error("unhandled exception: request_id=%s error_type=%s", request_id, type(exc).__name__)
    body = failure_envelope(
        ErrorCode.INTERNAL_ERROR, "伺服器發生錯誤；回報問題時請附上 request_id。", request_id
    )
    return JSONResponse(
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        content=body.model_dump(mode="json"),
        headers={REQUEST_ID_HEADER: request_id},
    )


def _location(loc: object) -> str:
    parts = loc if isinstance(loc, tuple | list) else (loc,)
    return ".".join(str(part) for part in parts)[:MAX_LOCATION_LENGTH]


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, app_error_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(Exception, unhandled_error_handler)
