"""讀取上傳的規格（docs/DECISIONS.md §11.1）：Content-Type 決定格式；超過 1 MiB 就停止讀取。

直接以 ASGI 的 receive 呼叫依賴，確認超過上限之後不再讀下一塊（app 層的上限，不只靠 middleware）。
"""

import asyncio
from collections.abc import Callable

import pytest
from starlette.requests import Request
from starlette.types import Message

from secscan.core.errors import AppError
from secscan.specs import dependencies
from secscan.specs.dependencies import read_spec_upload, spec_format_of
from secscan.specs.domain.documents import MAX_SPEC_BYTES, SpecFormat

HALF = MAX_SPEC_BYTES // 2


def _request(chunks: list[bytes], headers: dict[str, str]) -> tuple[Request, list[bytes]]:
    pending, consumed = list(chunks), []

    async def receive() -> Message:
        chunk = pending.pop(0) if pending else b""
        consumed.append(chunk)
        return {"type": "http.request", "body": chunk, "more_body": bool(pending)}

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "headers": [(name.encode(), value.encode()) for name, value in headers.items()],
    }
    return Request(scope, receive), consumed


def _rejected(call: Callable[[], object]) -> AppError:
    with pytest.raises(AppError) as raised:
        call()
    return raised.value


@pytest.mark.parametrize(
    ("content_type", "expected"),
    [
        ("application/json", SpecFormat.JSON),
        ("application/yaml", SpecFormat.YAML),
        ("Application/YAML; charset=UTF-8", SpecFormat.YAML),
        ("application/json; charset=utf8", SpecFormat.JSON),
    ],
)
def test_supported_content_types(content_type: str, expected: SpecFormat) -> None:
    assert spec_format_of(content_type) is expected


@pytest.mark.parametrize(
    "content_type",
    [
        None,
        "",
        "text/plain",
        "application/x-yaml",
        "application/vnd.oai.openapi",
        "application/vnd.oai.openapi+json",
        "application/json; charset=utf-16",
        "json",
    ],
)
def test_other_content_types_are_415(content_type: str | None) -> None:
    error = _rejected(lambda: spec_format_of(content_type))

    assert (error.status_code, error.code) == (415, "UNSUPPORTED_MEDIA_TYPE")


def test_declared_size_over_the_limit_is_rejected_without_reading() -> None:
    headers = {"content-type": "application/json", "content-length": str(MAX_SPEC_BYTES + 1)}
    request, consumed = _request([b"x"], headers)

    error = _rejected(lambda: asyncio.run(read_spec_upload(request)))

    assert (error.status_code, error.code) == (413, "SPEC_TOO_LARGE")
    assert consumed == []


def test_huge_declared_size_is_rejected_without_int_conversion() -> None:
    headers = {"content-type": "application/json", "content-length": "9" * 5000}
    request, consumed = _request([b"x"], headers)

    assert _rejected(lambda: asyncio.run(read_spec_upload(request))).status_code == 413
    assert consumed == []


def test_streamed_body_stops_at_the_first_chunk_over_the_limit() -> None:
    chunks = [b"x" * HALF, b"x" * HALF, b"x", b"never read"]
    request, consumed = _request(chunks, {"content-type": "application/yaml"})

    error = _rejected(lambda: asyncio.run(read_spec_upload(request)))

    assert error.code == "SPEC_TOO_LARGE"
    assert len(consumed) == 3


def test_body_at_the_limit_is_read_completely() -> None:
    request, _ = _request([b"x" * HALF, b"x" * HALF], {"content-type": "application/yaml"})

    upload = asyncio.run(read_spec_upload(request))

    assert upload.spec_format is SpecFormat.YAML
    assert len(upload.content) == MAX_SPEC_BYTES


# --- 審查後補上：讀 body 的期間不能無限長、斷線不是 500 -----------------------------------------


def test_slow_uploads_are_cut_off(monkeypatch: pytest.MonkeyPatch) -> None:
    """審查發現：讀 body 時已經佔住 DB 連線，很慢的上傳可以耗盡連線池；總讀取時間有上限。"""
    monkeypatch.setattr(dependencies, "SPEC_READ_TIMEOUT_SECONDS", 0.05)

    async def stalled() -> Message:
        await asyncio.sleep(10)
        return {"type": "http.request", "body": b"", "more_body": False}

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "headers": [(b"content-type", b"application/json")],
    }
    request = Request(scope, stalled)

    error = _rejected(lambda: asyncio.run(read_spec_upload(request)))

    assert (error.status_code, error.code) == (408, "REQUEST_TIMEOUT")


def test_client_disconnect_is_a_client_error() -> None:
    async def disconnected() -> Message:
        return {"type": "http.disconnect"}

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "headers": [(b"content-type", b"application/yaml")],
    }
    request = Request(scope, disconnected)

    error = _rejected(lambda: asyncio.run(read_spec_upload(request)))

    assert (error.status_code, error.code) == (400, "INVALID_REQUEST")
