"""讀取上傳的規格（docs/DECISIONS.md §11.1）：raw body，格式由 Content-Type 決定。

- Content-Type 只接受 application/json 與 application/yaml，charset 只能是 UTF-8；其他回 415。
- 大小：先看 Content-Length，再逐塊累計，超過 1 MiB 就停止讀取並回 413 SPEC_TOO_LARGE。
  更外層的 core.body_limit 對所有請求另有 2 MiB 的上限。

以 async 依賴逐塊讀取；解析是 CPU 工作，在 service（threadpool）中進行。這個依賴在 router 層的
身分驗證之後執行：沒有有效 key 的請求不會被讀取 body。
"""

from email.message import Message
from http import HTTPStatus
from types import MappingProxyType
from typing import Annotated

from fastapi import Depends, Request

from secscan.core.errors import AppError, ErrorCode
from secscan.specs.domain.documents import (
    MAX_SPEC_BYTES,
    InvalidSpecError,
    SpecFormat,
    SpecProblem,
)
from secscan.specs.domain.model import SpecUpload
from secscan.specs.errors import invalid_spec_error

# application/yaml 由 RFC 9512 註冊。OpenAPI 專用的 application/vnd.oai.openapi
# 不在 IANA 的登記表中，不接受（docs/DECISIONS.md §11.1）。
MEDIA_TYPES = MappingProxyType(
    {"application/json": SpecFormat.JSON, "application/yaml": SpecFormat.YAML}
)
UTF8_CHARSETS = frozenset({"utf-8", "utf8"})
# Content-Length 超過這個位數就一定超過上限；先比長度，超長的字串不交給 int()。
_MAX_LENGTH_DIGITS = 18


def spec_format_of(content_type: str | None) -> SpecFormat:
    """Content-Type 對應的格式；不支援時拋出 415 的 AppError。"""
    message = Message()
    if content_type is not None:
        message["content-type"] = content_type
    spec_format = MEDIA_TYPES.get(message.get_content_type())
    charset = message.get_content_charset()
    if spec_format is None or (charset is not None and charset not in UTF8_CHARSETS):
        raise AppError(
            status_code=HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
            code=ErrorCode.UNSUPPORTED_MEDIA_TYPE,
            message=("規格請以 Content-Type: application/json 或 application/yaml 上傳（UTF-8）。"),
        )
    return spec_format


async def read_spec_upload(request: Request) -> SpecUpload:
    spec_format = spec_format_of(request.headers.get("content-type"))
    declared = request.headers.get("content-length")
    # 不是十進位整數的 Content-Length 已由 core.body_limit 回 400。
    if (
        declared is not None
        and declared.isascii()
        and declared.isdigit()
        and (len(declared) > _MAX_LENGTH_DIGITS or int(declared) > MAX_SPEC_BYTES)
    ):
        raise _too_large()
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_SPEC_BYTES:
            raise _too_large()
        chunks.append(chunk)
    return SpecUpload(spec_format=spec_format, content=b"".join(chunks))


def _too_large() -> AppError:
    return invalid_spec_error(
        InvalidSpecError(SpecProblem.TOO_LARGE, f"規格不可超過 {MAX_SPEC_BYTES:,} bytes")
    )


SpecBody = Annotated[SpecUpload, Depends(read_spec_upload)]
