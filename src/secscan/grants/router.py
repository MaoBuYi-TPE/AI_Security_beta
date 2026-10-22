"""scope grant 的端點（docs/API_CONTRACT.md §14）。只做輸入驗證與呼叫 service。"""

from datetime import UTC, datetime
from functools import partial
from http import HTTPStatus
from uuid import UUID

from fastapi import APIRouter, Request

from secscan.api_keys.dependencies import CurrentPrincipal
from secscan.core.api import PageQuery, ok_page
from secscan.core.db import DbSession
from secscan.core.envelope import Envelope, ok
from secscan.core.request_id import request_id_of
from secscan.grants.schemas import GrantDecision, GrantRevocation, ScopeGrantCreate, ScopeGrantOut
from secscan.grants.service import ScopeGrantService
from secscan.targets.dependencies import CurrentLab

router = APIRouter(tags=["scope-grants"])


@router.post("/targets/{target_id}/scope-grants", status_code=HTTPStatus.CREATED)
def request_grant(
    target_id: UUID,
    body: ScopeGrantCreate,
    principal: CurrentPrincipal,
    session: DbSession,
    lab: CurrentLab,
    request: Request,
) -> Envelope[ScopeGrantOut]:
    """申請 scope grant（operator、admin），狀態為 pending；核准前不能用來掃描。"""
    now = datetime.now(UTC)
    grant = ScopeGrantService(session, lab=lab).request(
        principal, target_id, body.to_request(), now=now, request_id=request_id_of(request)
    )
    return ok(ScopeGrantOut.of(grant, now=now))


@router.get("/targets/{target_id}/scope-grants")
def list_grants(
    target_id: UUID,
    principal: CurrentPrincipal,
    session: DbSession,
    lab: CurrentLab,
    page: PageQuery,
) -> Envelope[list[ScopeGrantOut]]:
    """target 的所有版本，新版本在前；status 是讀取當下的狀態。"""
    grants = ScopeGrantService(session, lab=lab).list_for_target(principal, target_id, page)
    return ok_page(grants, partial(ScopeGrantOut.of, now=datetime.now(UTC)))


@router.get("/scope-grants/{grant_id}")
def get_grant(
    grant_id: UUID, principal: CurrentPrincipal, session: DbSession, lab: CurrentLab
) -> Envelope[ScopeGrantOut]:
    """其他 project 的 grant 與不存在的一樣回 404。"""
    grant = ScopeGrantService(session, lab=lab).get(principal, grant_id)
    return ok(ScopeGrantOut.of(grant, now=datetime.now(UTC)))


@router.post("/scope-grants/{grant_id}/approve")
def approve_grant(
    grant_id: UUID,
    body: GrantDecision,
    principal: CurrentPrincipal,
    session: DbSession,
    lab: CurrentLab,
    request: Request,
) -> Envelope[ScopeGrantOut]:
    """核准 pending 的 grant（只限 platform_admin）；核准時以目前的 LAB_CIDR 重新檢查。"""
    now = datetime.now(UTC)
    grant = ScopeGrantService(session, lab=lab).approve(
        principal, grant_id, note=body.note, now=now, request_id=request_id_of(request)
    )
    return ok(ScopeGrantOut.of(grant, now=now))


@router.post("/scope-grants/{grant_id}/revoke")
def revoke_grant(
    grant_id: UUID,
    body: GrantRevocation,
    principal: CurrentPrincipal,
    session: DbSession,
    lab: CurrentLab,
    request: Request,
) -> Envelope[ScopeGrantOut]:
    """撤銷 pending 或 approved 的 grant（只限 platform_admin）；重複撤銷回 200，不重記 audit。"""
    now = datetime.now(UTC)
    grant = ScopeGrantService(session, lab=lab).revoke(
        principal, grant_id, reason=body.reason, now=now, request_id=request_id_of(request)
    )
    return ok(ScopeGrantOut.of(grant, now=now))
