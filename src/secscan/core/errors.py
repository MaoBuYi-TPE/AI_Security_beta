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

    UNAUTHENTICATED = "UNAUTHENTICATED"
    API_KEY_EXPIRED = "API_KEY_EXPIRED"
    ROLE_NOT_ALLOWED = "ROLE_NOT_ALLOWED"
    SCOPE_NOT_APPROVED = "SCOPE_NOT_APPROVED"
    SCOPE_EXPIRED = "SCOPE_EXPIRED"
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
    METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
    PROJECT_NAME_CONFLICT = "PROJECT_NAME_CONFLICT"
    TARGET_ORIGIN_CONFLICT = "TARGET_ORIGIN_CONFLICT"
    INVALID_STATE_TRANSITION = "INVALID_STATE_TRANSITION"
    TARGET_DISABLED = "TARGET_DISABLED"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    HTTP_ERROR = "HTTP_ERROR"
    REQUEST_TOO_LARGE = "REQUEST_TOO_LARGE"
    REQUEST_TIMEOUT = "REQUEST_TIMEOUT"
    SPEC_TOO_LARGE = "SPEC_TOO_LARGE"
    UNSUPPORTED_MEDIA_TYPE = "UNSUPPORTED_MEDIA_TYPE"
    INVALID_REQUEST = "INVALID_REQUEST"
    INVALID_TARGET = "INVALID_TARGET"
    SCOPE_OUTSIDE_LAB = "SCOPE_OUTSIDE_LAB"
    INVALID_SPEC = "INVALID_SPEC"
    UNSUPPORTED_SCHEMA = "UNSUPPORTED_SCHEMA"
    EXTERNAL_REF_FORBIDDEN = "EXTERNAL_REF_FORBIDDEN"
    DEPENDENCY_UNAVAILABLE = "DEPENDENCY_UNAVAILABLE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class AppError(Exception):
    """可預期的 API 錯誤：HTTP 狀態碼、穩定錯誤碼、給使用者看的訊息，以及必要的回應 header。"""

    def __init__(
        self,
        *,
        status_code: int,
        code: ErrorCode,
        message: str,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.headers = dict(headers) if headers is not None else None


NOT_FOUND_MESSAGE = "找不到資源。"
REQUEST_TOO_LARGE_MESSAGE = "請求內容超過大小上限。"

_HTTP_ERRORS: dict[int, tuple[ErrorCode, str]] = {
    HTTPStatus.NOT_FOUND: (ErrorCode.RESOURCE_NOT_FOUND, NOT_FOUND_MESSAGE),
    HTTPStatus.METHOD_NOT_ALLOWED: (ErrorCode.METHOD_NOT_ALLOWED, "不支援這個 HTTP 方法。"),
    # core.body_limit 讀 body 時超過上限：在 FastAPI 解析 body 的過程中拋出，
    # 必須是框架的 HTTPException 才不會被 FastAPI 改成 400。
    HTTPStatus.REQUEST_ENTITY_TOO_LARGE: (ErrorCode.REQUEST_TOO_LARGE, REQUEST_TOO_LARGE_MESSAGE),
}


def not_found_error() -> AppError:
    """物件不存在或無權存取：回應與「路徑不存在」完全相同，不洩漏物件是否存在。"""
    return AppError(
        status_code=HTTPStatus.NOT_FOUND,
        code=ErrorCode.RESOURCE_NOT_FOUND,
        message=NOT_FOUND_MESSAGE,
    )


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


def error_response(request: Request, error: AppError) -> JSONResponse:
    """AppError 的失敗回應。exception handler 與在路由之前就回應的 middleware 共用。"""
    return _failure_response(
        request, error.status_code, error.code, error.message, headers=error.headers
    )


async def app_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """把 AppError 轉成失敗 envelope。只註冊給 AppError；收到其他例外時原樣拋出，不吞掉。"""
    if not isinstance(exc, AppError):
        raise exc
    return error_response(request, exc)


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
