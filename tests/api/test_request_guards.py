"""驗證之前的兩道關卡（docs/DECISIONS.md §11.1）。這裡的測試不連 DB：

- `/api/v1` 沒有 Bearer 或 key 格式不符：回與 current_principal 完全相同的 401，不讀 body。
- 任何請求超過 2 MiB：回 413 REQUEST_TOO_LARGE；先看 Content-Length，再逐塊累計。
- 兩者的順序：沒有 key 的大請求回 401。
"""

import asyncio
import logging
from collections.abc import Iterator

import pytest
from fastapi import FastAPI, Request
from fastapi.security import HTTPBearer
from fastapi.testclient import TestClient
from hypothesis import find, given
from hypothesis import strategies as st
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import Message, Receive, Scope, Send

from secscan.api_keys.dependencies import rejection_error
from secscan.api_keys.domain import RejectionReason
from secscan.api_keys.middleware import BearerKeyFormatMiddleware, credential_problem
from secscan.core.body_limit import MAX_REQUEST_BODY_BYTES, BodyLimitMiddleware
from secscan.core.errors import register_error_handlers
from secscan.core.request_id import REQUEST_ID_HEADER, RequestIdMiddleware
from secscan.security.api_key_tokens import parse_prefix

# 格式正確、但不存在的 key（不會查 DB 的測試才使用）。以程式組出，避免被 pre-commit 當成外洩。
WELL_FORMED_KEY = "_".join(("secscan", "0" * 16, "a" * 64))
CANARY = "canary-credential-0007"


def _bearer(value: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {value}"}


def _chunks(total: int, size: int = 64 * 1024) -> Iterator[bytes]:
    """不帶 Content-Length 的 chunked body。"""
    sent = 0
    while sent < total:
        part = min(size, total - sent)
        sent += part
        yield b" " * part


# --- 沒有 key 時先回 401 ------------------------------------------------------------------------


def test_missing_key_is_rejected_before_the_body_is_parsed(client: TestClient) -> None:
    """語法錯誤的 JSON：沒有 key 時先得到 401，看不到 422。"""
    response = client.post(
        "/api/v1/projects",
        content=b'{"name": "canary-body',
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"
    assert response.headers["www-authenticate"] == "Bearer"
    assert "canary-body" not in response.text


def test_middleware_rejection_is_identical_to_the_dependency_rejection(client: TestClient) -> None:
    """中介層回的 401 與 current_principal 回的 401 分不出來（除了 request_id）。"""
    from_middleware = client.get("/api/v1/projects", headers=_bearer(CANARY))
    app = FastAPI()
    app.add_middleware(RequestIdMiddleware)
    register_error_handlers(app)

    @app.get("/plain")
    def plain() -> None:
        raise rejection_error(RejectionReason.MALFORMED)

    with TestClient(app) as bare:
        from_dependency = bare.get("/plain")

    assert from_middleware.status_code == from_dependency.status_code == 401
    challenge = from_dependency.headers["www-authenticate"]
    assert from_middleware.headers["www-authenticate"] == challenge
    first, second = from_middleware.json(), from_dependency.json()
    assert first["error"].pop("request_id") == from_middleware.headers[REQUEST_ID_HEADER]
    second["error"].pop("request_id")
    assert first == second


def test_unknown_v1_path_without_a_key_is_401_but_with_a_key_is_404(client: TestClient) -> None:
    assert client.get("/api/v1/nope").status_code == 401
    assert client.delete("/api/v1/projects").status_code == 401
    assert client.get("/api/v1/nope", headers=_bearer(WELL_FORMED_KEY)).status_code == 404
    assert client.get("/api/v1x/projects").status_code == 404


def test_paths_outside_api_v1_do_not_need_a_key(client: TestClient) -> None:
    assert client.get("/health/live").status_code == 200


def test_well_formed_key_still_lets_fastapi_parse_json_first(client: TestClient) -> None:
    """已知行為（§9.5）：格式正確的 key 要查 DB 才知道是否有效，FastAPI 在那之前先解析 JSON。"""
    response = client.post(
        "/api/v1/projects",
        content=b'{"name": "canary-body',
        headers={"Content-Type": "application/json", **_bearer(WELL_FORMED_KEY)},
    )

    assert response.status_code == 422
    assert "canary-body" not in response.text


def test_middleware_rejections_are_logged_with_reason_but_without_the_credential(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="secscan.api_keys.dependencies"):
        malformed = client.get("/api/v1/projects", headers=_bearer(CANARY))
        missing = client.get("/api/v1/projects", headers={"Authorization": f"Basic {CANARY}"})

    logged = " ".join(record.getMessage() for record in caplog.records)
    assert "reason=malformed" in logged
    assert "reason=missing" in logged
    assert malformed.headers[REQUEST_ID_HEADER] in logged
    assert missing.headers[REQUEST_ID_HEADER] in logged
    assert CANARY not in logged


def _header_scope(value: str | None) -> Scope:
    headers = [] if value is None else [(b"authorization", value.encode("latin-1"))]
    return {"type": "http", "method": "GET", "path": "/api/v1/projects", "headers": headers}


def _reference_problem(value: str | None) -> RejectionReason | None:
    """current_principal 的判斷。

    HTTPBearer 取不到憑證就是 MISSING，parse_prefix 不認得就是 MALFORMED。
    """
    bearer = HTTPBearer(auto_error=False)
    credentials = asyncio.run(bearer(Request(_header_scope(value))))
    if credentials is None:
        return RejectionReason.MISSING
    if parse_prefix(credentials.credentials) is None:
        return RejectionReason.MALFORMED
    return None


_HEADER_VALUES = st.one_of(
    st.none(),
    st.text(alphabet=st.characters(min_codepoint=0x20, max_codepoint=0xFF), max_size=120),
    st.builds(
        "".join,
        st.lists(
            st.sampled_from(
                [
                    *("Bearer", "bearer", "BEARER", "Basic", " ", "  ", "\t"),
                    *("secscan", "_", "0" * 16, "a" * 64, "A" * 64, WELL_FORMED_KEY, "x"),
                ]
            ),
            max_size=6,
        ),
    ),
)


@given(_HEADER_VALUES)
def test_middleware_and_dependency_classify_every_header_the_same_way(value: str | None) -> None:
    assert credential_problem(value) == _reference_problem(value)


@pytest.mark.parametrize("outcome", [None, RejectionReason.MISSING, RejectionReason.MALFORMED])
def test_header_strategy_reaches_every_outcome(outcome: RejectionReason | None) -> None:
    """上面的比對不能只測到其中一種結果（找不到時 find 會拋出 NoSuchExample）。"""
    find(_HEADER_VALUES, lambda value: credential_problem(value) == outcome)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, RejectionReason.MISSING),
        ("", RejectionReason.MISSING),
        ("Bearer", RejectionReason.MISSING),
        ("Bearer   ", RejectionReason.MISSING),
        (f"Basic {WELL_FORMED_KEY}", RejectionReason.MISSING),
        (f"Bearer {CANARY}", RejectionReason.MALFORMED),
        (f"Bearer {WELL_FORMED_KEY.upper()}", RejectionReason.MALFORMED),
        (f"Bearer {WELL_FORMED_KEY}", None),
        (f"bearer  {WELL_FORMED_KEY} ", None),
    ],
)
def test_credential_problem_table(value: str | None, expected: RejectionReason | None) -> None:
    assert credential_problem(value) == expected
    assert _reference_problem(value) == expected


# --- 大小上限 ----------------------------------------------------------------------------------


def test_declared_body_over_the_limit_is_413(client: TestClient) -> None:
    response = client.post(
        "/api/v1/projects",
        content=b" " * (MAX_REQUEST_BODY_BYTES + 1),
        headers={"Content-Type": "application/json", **_bearer(WELL_FORMED_KEY)},
    )

    assert response.status_code == 413
    error = response.json()["error"]
    assert error["code"] == "REQUEST_TOO_LARGE"
    assert error["request_id"] == response.headers[REQUEST_ID_HEADER]


def test_streamed_body_over_the_limit_is_413_not_400(client: TestClient) -> None:
    """chunked（沒有 Content-Length）：讀到超過上限就停；FastAPI 不能把它變成 400。"""
    response = client.post(
        "/api/v1/projects",
        content=_chunks(MAX_REQUEST_BODY_BYTES + 1),
        headers={"Content-Type": "application/json", **_bearer(WELL_FORMED_KEY)},
    )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "REQUEST_TOO_LARGE"


def test_missing_key_wins_over_the_size_limit(client: TestClient) -> None:
    response = client.post(
        "/api/v1/projects",
        content=b" " * (MAX_REQUEST_BODY_BYTES + 1),
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 401


class _Recorder:
    """直接以 ASGI 呼叫 middleware：記下送出的訊息，以及 app 有沒有被呼叫、body 讀了多少。"""

    def __init__(self, body: list[bytes]) -> None:
        self._body = list(body)
        self.receive_calls = 0
        self.sent: list[Message] = []
        self.app_called = False
        self.app_read = 0

    async def receive(self) -> Message:
        self.receive_calls += 1
        chunk = self._body.pop(0) if self._body else b""
        return {"type": "http.request", "body": chunk, "more_body": bool(self._body)}

    async def send(self, message: Message) -> None:
        self.sent.append(message)

    async def app(self, scope: Scope, receive: Receive, send: Send) -> None:
        self.app_called = True
        while True:
            message = await receive()
            self.app_read += len(message.get("body", b""))
            if not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    @property
    def status(self) -> int:
        return int(self.sent[0]["status"])


def _scope(*, path: str = "/api/v1/projects", headers: list[tuple[bytes, bytes]]) -> Scope:
    return {"type": "http", "method": "POST", "path": path, "headers": headers, "state": {}}


def test_key_rejection_never_reads_the_body() -> None:
    recorder = _Recorder([b"x" * 10])
    middleware = BearerKeyFormatMiddleware(recorder.app)

    asyncio.run(middleware(_scope(headers=[]), recorder.receive, recorder.send))

    assert recorder.status == 401
    assert recorder.receive_calls == 0
    assert not recorder.app_called


def test_declared_size_rejection_never_reads_the_body() -> None:
    recorder = _Recorder([b"x"])
    middleware = BodyLimitMiddleware(recorder.app, max_bytes=8)
    headers = [(b"content-length", b"9")]

    asyncio.run(middleware(_scope(headers=headers), recorder.receive, recorder.send))

    assert recorder.status == 413
    assert recorder.receive_calls == 0
    assert not recorder.app_called


@pytest.mark.parametrize("declared", [b"8", b"0"])
def test_body_at_the_limit_passes(declared: bytes) -> None:
    body = b"x" * int(declared)
    recorder = _Recorder([body[:3], body[3:]])
    middleware = BodyLimitMiddleware(recorder.app, max_bytes=8)

    asyncio.run(
        middleware(_scope(headers=[(b"content-length", declared)]), recorder.receive, recorder.send)
    )

    assert recorder.status == 200
    assert recorder.app_read == len(body)


def test_streamed_body_one_byte_over_the_limit_is_rejected_while_reading() -> None:
    recorder = _Recorder([b"x" * 4, b"x" * 4, b"x"])
    middleware = BodyLimitMiddleware(recorder.app, max_bytes=8)

    with pytest.raises(StarletteHTTPException) as raised:
        asyncio.run(middleware(_scope(headers=[]), recorder.receive, recorder.send))

    assert raised.value.status_code == 413
    assert recorder.app_read == 8


@pytest.mark.parametrize(
    ("declared", "status"),
    [(b"abc", 400), (b"-1", 400), (b"1.5", 400), ("\uff11".encode(), 400), (b"9" * 40, 413)],
    ids=["letters", "negative", "fraction", "fullwidth-digit", "huge"],
)
def test_unusable_content_length_is_rejected_without_reading(declared: bytes, status: int) -> None:
    recorder = _Recorder([b"x"])
    middleware = BodyLimitMiddleware(recorder.app, max_bytes=8)

    asyncio.run(
        middleware(_scope(headers=[(b"content-length", declared)]), recorder.receive, recorder.send)
    )

    assert recorder.status == status
    assert recorder.receive_calls == 0
    assert not recorder.app_called


@pytest.mark.parametrize("middleware_type", [BodyLimitMiddleware, BearerKeyFormatMiddleware])
def test_non_http_scopes_pass_through(middleware_type: type) -> None:
    calls: list[str] = []

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        calls.append(scope["type"])

    async def receive() -> Message:
        return {"type": "lifespan.startup"}

    async def send(message: Message) -> None:
        return None

    asyncio.run(middleware_type(app)({"type": "lifespan"}, receive, send))

    assert calls == ["lifespan"]


def test_disconnect_messages_pass_through_uncounted() -> None:
    seen: list[Message] = []

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        seen.append(await receive())

    async def receive() -> Message:
        return {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        return None

    asyncio.run(BodyLimitMiddleware(app, max_bytes=8)(_scope(headers=[]), receive, send))

    assert seen == [{"type": "http.disconnect"}]
