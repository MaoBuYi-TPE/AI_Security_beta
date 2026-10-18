"""projects 的端點（docs/API_CONTRACT.md §13）。只做輸入驗證與呼叫 service。"""

from http import HTTPStatus
from uuid import UUID

from fastapi import APIRouter, Request

from secscan.api_keys.dependencies import CurrentPrincipal
from secscan.audit.schemas import AuditEventOut
from secscan.core.api import PageQuery, ok_page
from secscan.core.db import DbSession
from secscan.core.envelope import Envelope, ok
from secscan.core.request_id import request_id_of
from secscan.projects.schemas import ProjectCreate, ProjectOut
from secscan.projects.service import ProjectService

router = APIRouter(prefix="/projects", tags=["projects"])


@router.post("", status_code=HTTPStatus.CREATED)
def create_project(
    body: ProjectCreate, principal: CurrentPrincipal, session: DbSession, request: Request
) -> Envelope[ProjectOut]:
    """建立專案（只限 platform_admin）。"""
    project = ProjectService(session).create(
        principal, name=body.name, request_id=request_id_of(request)
    )
    return ok(ProjectOut.of(project))


@router.get("")
def list_projects(
    principal: CurrentPrincipal, session: DbSession, page: PageQuery
) -> Envelope[list[ProjectOut]]:
    """platform_admin 看到全部；operator、viewer 只看到自己的 project。"""
    return ok_page(ProjectService(session).list_visible(principal, page), ProjectOut.of)


@router.get("/{project_id}")
def get_project(
    project_id: UUID, principal: CurrentPrincipal, session: DbSession
) -> Envelope[ProjectOut]:
    """其他 project 與不存在的 project 一樣回 404。"""
    return ok(ProjectOut.of(ProjectService(session).get(principal, project_id)))


@router.get("/{project_id}/audit-events")
def list_audit_events(
    project_id: UUID, principal: CurrentPrincipal, session: DbSession, page: PageQuery
) -> Envelope[list[AuditEventOut]]:
    """稽核事件，由新到舊（只限 platform_admin）；內容已遮罩。"""
    events = ProjectService(session).list_audit_events(principal, project_id, page)
    return ok_page(events, AuditEventOut.of)
