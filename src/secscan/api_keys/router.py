"""平台 API key 的端點（docs/API_CONTRACT.md §13）。只做輸入驗證與呼叫 service。"""

from datetime import UTC, datetime
from http import HTTPStatus
from uuid import UUID

from fastapi import APIRouter, Request, Response

from secscan.api_keys.dependencies import CurrentPrincipal
from secscan.api_keys.schemas import ApiKeyCreate, IssuedApiKeyOut
from secscan.api_keys.service import ApiKeyService
from secscan.core.db import DbSession
from secscan.core.envelope import Envelope, ok
from secscan.core.request_id import request_id_of

router = APIRouter(tags=["api-keys"])


@router.post("/projects/{project_id}/keys", status_code=HTTPStatus.CREATED)
def create_project_key(
    project_id: UUID,
    body: ApiKeyCreate,
    principal: CurrentPrincipal,
    session: DbSession,
    request: Request,
    response: Response,
) -> Envelope[IssuedApiKeyOut]:
    """為 project 建立 operator 或 viewer key（只限 platform_admin）。

    完整的 key 只出現在這個回應。
    """
    issued = ApiKeyService(session).issue_project_key(
        principal,
        project_id,
        name=body.name,
        role=body.role,
        expires_at=body.expires_at,
        now=datetime.now(UTC),
        request_id=request_id_of(request),
    )
    # 回應含完整的 key：不得被 proxy 或 client 快取。
    response.headers["Cache-Control"] = "no-store"
    return ok(IssuedApiKeyOut.of(issued))


@router.delete("/keys/{key_id}", status_code=HTTPStatus.NO_CONTENT)
def revoke_key(
    key_id: UUID, principal: CurrentPrincipal, session: DbSession, request: Request
) -> None:
    """撤銷 key（只限 platform_admin）；重複撤銷也回 204。"""
    ApiKeyService(session).revoke(principal, key_id, request_id=request_id_of(request))
