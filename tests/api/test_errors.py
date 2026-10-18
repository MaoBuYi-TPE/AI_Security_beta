"""統一錯誤 envelope 與 request_id（docs/API_CONTRACT.md §1、§12）。

所有錯誤（含框架產生的 404/405/422 與未處理例外的 500）都要是 envelope、帶 request_id，
而且不能回顯請求內容或例外訊息。
"""

import asyncio
import logging
import re
from collections.abc import Callable, Coroutine
from typing import Any

import pytest
from fastapi import FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import Response
from fastapi.testclient import TestClient
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from secscan.core.errors import (
    AppError,
    ErrorCode,
    app_error_handler,
    http_exception_handler,
    register_error_handlers,
    validation_error_handler,
)
from secscan.core.request_id import REQUEST_ID_HEADER, RequestIdMiddleware

REQUEST_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
SECRET_INPUT = "Bearer canary-secret-input-0001"
SECRET_EXCEPTION_DETAIL = "canary-exception-detail-0002"

type Handler = Callable[[Request, Exception], Coroutine[Any, Any, Response]]


class _Payload(BaseModel):
    token: str = Field(max_length=4)


class _Wide(BaseModel):
    f1: int
    f2: int
    f3: int
    f4: int
    f5: int
    f6: int


def _app(*, with_request_id: bool = True) -> FastAPI:
    app = FastAPI()
    if with_request_id:
        app.add_middleware(RequestIdMiddleware)
    register_error_handlers(app)

    @app.get("/unavailable")
    def unavailable() -> None:
        raise AppError(
            status_code=503, code=ErrorCode.DEPENDENCY_UNAVAILABLE, message="依賴無法使用。"
        )

    @app.get("/fine")
    def fine() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/items")
    def items(page: int = Query(ge=1)) -> dict[str, int]:
        return {"page": page}

    @app.post("/payload")
    def payload(body: _Payload) -> dict[str, str]:
        return {"token": body.token}

    @app.post("/wide")
    def wide(body: _Wide) -> dict[str, int]:
        return {"f1": body.f1}

    @app.get("/closed")
    def closed() -> None:
        raise StarletteHTTPException(status_code=499, detail=SECRET_EXCEPTION_DETAIL)

    @app.get("/crash")
    def crash() -> None:
        raise RuntimeError(SECRET_EXCEPTION_DETAIL)

    return app


def _error(response_json: object) -> dict[str, object]:
    assert isinstance(response_json, dict)
    assert response_json["success"] is False
    assert response_json["data"] is None
    assert response_json["meta"] is None
    error = response_json["error"]
    assert isinstance(error, dict)
    assert set(error) == {"code", "message", "request_id"}
    return error


def test_app_error_becomes_failure_envelope_with_request_id() -> None:
    with TestClient(_app()) as client:
        response = client.get("/unavailable")

    assert response.status_code == 503
    request_id = response.headers[REQUEST_ID_HEADER]
    assert response.json() == {
        "success": False,
        "data": None,
        "error": {
            "code": "DEPENDENCY_UNAVAILABLE",
            "message": "依賴無法使用。",
            "request_id": request_id,
        },
        "meta": None,
    }
    assert REQUEST_ID_PATTERN.match(request_id)


def test_every_response_gets_a_distinct_server_generated_request_id() -> None:
    with TestClient(_app()) as client:
        first = client.get("/fine").headers[REQUEST_ID_HEADER]
        second = client.get("/fine").headers[REQUEST_ID_HEADER]

    assert REQUEST_ID_PATTERN.match(first)
    assert REQUEST_ID_PATTERN.match(second)
    assert first != second


def test_client_supplied_request_id_is_ignored() -> None:
    with TestClient(_app()) as client:
        response = client.get("/unavailable", headers={REQUEST_ID_HEADER: "attacker\r\nX: 1"})

    assert response.headers[REQUEST_ID_HEADER] != "attacker\r\nX: 1"
    assert REQUEST_ID_PATTERN.match(str(_error(response.json())["request_id"]))


def test_error_envelope_still_has_request_id_without_middleware() -> None:
    with TestClient(_app(with_request_id=False)) as client:
        response = client.get("/unavailable")

    assert REQUEST_ID_PATTERN.match(str(_error(response.json())["request_id"]))


def test_unknown_route_is_a_not_found_envelope() -> None:
    with TestClient(_app()) as client:
        response = client.get("/nope")

    assert response.status_code == 404
    error = _error(response.json())
    assert (error["code"], error["message"]) == ("RESOURCE_NOT_FOUND", "找不到資源。")
    assert error["request_id"] == response.headers[REQUEST_ID_HEADER]


def test_wrong_method_keeps_allow_header() -> None:
    with TestClient(_app()) as client:
        response = client.delete("/fine")

    assert response.status_code == 405
    assert _error(response.json())["code"] == "METHOD_NOT_ALLOWED"
    assert response.headers["allow"] == "GET"


def test_validation_error_names_fields_without_echoing_input() -> None:
    with TestClient(_app()) as client:
        query = client.get("/items", params={"page": "0"})
        body = client.post("/payload", json={"token": SECRET_INPUT})

    assert query.status_code == body.status_code == 422
    query_error, body_error = _error(query.json()), _error(body.json())
    assert query_error["code"] == body_error["code"] == "INVALID_REQUEST"
    assert "query.page" in str(query_error["message"])
    assert "body.token" in str(body_error["message"])
    assert SECRET_INPUT not in body.text


def test_validation_error_lists_at_most_five_fields() -> None:
    with TestClient(_app()) as client:
        response = client.post("/wide", json={})

    message = str(_error(response.json())["message"])
    assert message.endswith("…")
    assert "body.f5" in message
    assert "body.f6" not in message


def test_non_standard_http_status_is_a_generic_envelope() -> None:
    """非標準狀態碼不能讓 handler 自己出錯；detail 原文也不回傳。"""
    with TestClient(_app()) as client:
        response = client.get("/closed")

    assert response.status_code == 499
    error = _error(response.json())
    assert error["code"] == "HTTP_ERROR"
    assert SECRET_EXCEPTION_DETAIL not in response.text


def test_unhandled_exception_is_a_generic_envelope_with_request_id(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with (
        caplog.at_level(logging.ERROR, logger="secscan.core.errors"),
        TestClient(_app(), raise_server_exceptions=False) as client,
    ):
        response = client.get("/crash")

    assert response.status_code == 500
    error = _error(response.json())
    assert error["code"] == "INTERNAL_ERROR"
    assert error["request_id"] == response.headers[REQUEST_ID_HEADER]
    assert SECRET_EXCEPTION_DETAIL not in response.text
    # 伺服器端留下可對應 request_id 的紀錄，但不寫入例外訊息（可能含秘密或個資）。
    logged = [record.getMessage() for record in caplog.records]
    assert any(str(error["request_id"]) in line and "RuntimeError" in line for line in logged)
    assert all(SECRET_EXCEPTION_DETAIL not in line for line in logged)


def test_real_app_uses_the_same_error_envelope(client: TestClient) -> None:
    response = client.get("/nope")

    assert response.status_code == 404
    assert _error(response.json())["code"] == "RESOURCE_NOT_FOUND"


@pytest.mark.parametrize(
    "handler",
    [app_error_handler, http_exception_handler, validation_error_handler],
    ids=["app_error", "http_exception", "validation_error"],
)
def test_specific_handlers_reraise_unrelated_exceptions(handler: Handler) -> None:
    """各 handler 只處理自己的例外型別；收到其他例外時原樣拋出，不包裝成看似正常的回應。"""
    request = Request({"type": "http", "headers": []})

    with pytest.raises(LookupError, match="unexpected"):
        asyncio.run(handler(request, LookupError("unexpected")))


def test_handler_types_match_registration() -> None:
    """確認註冊的例外型別（避免把 handler 掛錯型別而默默失效）。"""
    app = FastAPI()
    register_error_handlers(app)

    assert app.exception_handlers[AppError] is app_error_handler
    assert app.exception_handlers[StarletteHTTPException] is http_exception_handler
    assert app.exception_handlers[RequestValidationError] is validation_error_handler
