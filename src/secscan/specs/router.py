"""API 規格的端點（docs/API_CONTRACT.md §15）。只做輸入驗證與呼叫 service。"""

from http import HTTPStatus
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Query, Request

from secscan.api_keys.dependencies import CurrentPrincipal
from secscan.core.api import PageQuery, ok_page
from secscan.core.db import DbSession
from secscan.core.envelope import Envelope, ok
from secscan.core.request_id import request_id_of
from secscan.specs.dependencies import MEDIA_TYPES, SpecBody
from secscan.specs.schemas import ApiSpecOut, SpecOperationOut
from secscan.specs.service import ApiSpecService

router = APIRouter(tags=["api-specs"])

# 上傳是 raw body（不是 multipart、也不是 JSON 物件），在 API 文件中另外描述。
_UPLOAD_BODY: dict[str, Any] = {
    "requestBody": {
        "required": True,
        "description": "OpenAPI 3.0 規格（JSON 或 YAML，UTF-8，最多 1 MiB）。",
        "content": {media_type: {"schema": {"type": "string"}} for media_type in MEDIA_TYPES},
    }
}


@router.post(
    "/targets/{target_id}/api-specs",
    status_code=HTTPStatus.CREATED,
    openapi_extra=_UPLOAD_BODY,
)
def upload_spec(
    target_id: UUID,
    upload: SpecBody,
    principal: CurrentPrincipal,
    session: DbSession,
    request: Request,
) -> Envelope[ApiSpecOut]:
    """上傳 OpenAPI 3.0 規格（operator、admin）；servers 一律改綁到 target 的 origin。"""
    spec = ApiSpecService(session).upload(
        principal, target_id, upload, request_id=request_id_of(request)
    )
    return ok(ApiSpecOut.of(spec))


@router.get("/targets/{target_id}/api-specs")
def list_specs(
    target_id: UUID, principal: CurrentPrincipal, session: DbSession, page: PageQuery
) -> Envelope[list[ApiSpecOut]]:
    """target 的所有版本，新版本在前。"""
    specs = ApiSpecService(session).list_for_target(principal, target_id, page)
    return ok_page(specs, ApiSpecOut.of)


@router.get("/api-specs/{spec_id}")
def get_spec(
    spec_id: UUID, principal: CurrentPrincipal, session: DbSession
) -> Envelope[ApiSpecOut]:
    """其他 project 的規格與不存在的一樣回 404。"""
    return ok(ApiSpecOut.of(ApiSpecService(session).get(principal, spec_id)))


@router.get("/api-specs/{spec_id}/operations")
def list_operations(
    spec_id: UUID,
    principal: CurrentPrincipal,
    session: DbSession,
    page: PageQuery,
    scope_grant_id: Annotated[
        UUID | None, Query(description="以這個 grant 判斷每個 operation 是否在範圍內")
    ] = None,
) -> Envelope[list[SpecOperationOut]]:
    """operation inventory，依 path、method 排序；被排除的 operation 也照樣列出並附上原因。"""
    entries = ApiSpecService(session).operations(principal, spec_id, page, grant_id=scope_grant_id)
    return ok_page(entries, SpecOperationOut.of)
