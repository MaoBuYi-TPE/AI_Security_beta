"""targets 的端點（docs/API_CONTRACT.md §14）。只做輸入驗證與呼叫 service。"""

from http import HTTPStatus
from uuid import UUID

from fastapi import APIRouter, Request

from secscan.api_keys.dependencies import CurrentPrincipal
from secscan.core.api import PageQuery, ok_page
from secscan.core.db import DbSession
from secscan.core.envelope import Envelope, ok
from secscan.core.request_id import request_id_of
from secscan.targets.dependencies import CurrentLab
from secscan.targets.schemas import TargetCreate, TargetOut, TargetPatch
from secscan.targets.service import TargetService

router = APIRouter(tags=["targets"])


@router.post("/projects/{project_id}/targets", status_code=HTTPStatus.CREATED)
def create_target(
    project_id: UUID,
    body: TargetCreate,
    principal: CurrentPrincipal,
    session: DbSession,
    lab: CurrentLab,
    request: Request,
) -> Envelope[TargetOut]:
    """建立 target（operator、admin）。target 存在不代表可以掃描：還需要核准的 scope grant。"""
    target = TargetService(session, lab=lab).create(
        principal,
        project_id,
        name=body.name,
        kind=body.kind,
        base_url=body.base_url,
        request_id=request_id_of(request),
        environment=body.environment,
    )
    return ok(TargetOut.of(target))


@router.get("/projects/{project_id}/targets")
def list_targets(
    project_id: UUID,
    principal: CurrentPrincipal,
    session: DbSession,
    lab: CurrentLab,
    page: PageQuery,
) -> Envelope[list[TargetOut]]:
    """project 的 target，依建立時間由舊到新。"""
    targets = TargetService(session, lab=lab).list_in_project(principal, project_id, page)
    return ok_page(targets, TargetOut.of)


@router.get("/targets/{target_id}")
def get_target(
    target_id: UUID, principal: CurrentPrincipal, session: DbSession, lab: CurrentLab
) -> Envelope[TargetOut]:
    """其他 project 的 target 與不存在的一樣回 404。"""
    return ok(TargetOut.of(TargetService(session, lab=lab).get(principal, target_id)))


@router.patch("/targets/{target_id}")
def update_target(
    target_id: UUID,
    body: TargetPatch,
    principal: CurrentPrincipal,
    session: DbSession,
    lab: CurrentLab,
    request: Request,
) -> Envelope[TargetOut]:
    """修改名稱或啟用狀態（operator、admin）；origin 不能改。"""
    target = TargetService(session, lab=lab).update(
        principal, target_id, body.to_update(), request_id=request_id_of(request)
    )
    return ok(TargetOut.of(target))
