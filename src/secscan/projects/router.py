"""projects 的端點（docs/API_CONTRACT.md §13）。只做輸入驗證與呼叫 service。"""

from http import HTTPStatus
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query, Request
from pydantic import AwareDatetime

from secscan.api_keys.dependencies import CurrentPrincipal
from secscan.audit.domain import AUDIT_LABEL_MAX_LENGTH, AuditFilters
from secscan.audit.schemas import AuditEventOut
from secscan.core.api import PageQuery, ok_page
from secscan.core.db import DbSession
from secscan.core.envelope import Envelope, ok
from secscan.core.request_id import request_id_of
from secscan.projects.schemas import ProjectCreate, ProjectOut
from secscan.projects.service import ProjectService

router = APIRouter(prefix="/projects", tags=["projects"])
# 全域的稽核查詢（T21）：audit 這一層在 api_keys 之下、不能有 router，所以放在 projects。
audit_router = APIRouter(tags=["audit"])


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


@audit_router.get("/audit-events")
def list_all_audit_events(
    principal: CurrentPrincipal,
    session: DbSession,
    page: PageQuery,
    project_id: Annotated[UUID | None, Query(description="只列這個 project 的事件")] = None,
    action: Annotated[str | None, Query(max_length=AUDIT_LABEL_MAX_LENGTH)] = None,
    object_type: Annotated[str | None, Query(max_length=AUDIT_LABEL_MAX_LENGTH)] = None,
    object_id: Annotated[UUID | None, Query()] = None,
    created_after: Annotated[AwareDatetime | None, Query(description="含這個時間")] = None,
    created_before: Annotated[AwareDatetime | None, Query(description="不含這個時間")] = None,
) -> Envelope[list[AuditEventOut]]:
    """全域的稽核事件（只限 platform_admin），由新到舊。

    含 project 為 NULL 的全域動作；內容已遮罩。
    """
    filters = AuditFilters(
        project_id=project_id,
        action=action,
        object_type=object_type,
        object_id=object_id,
        created_after=created_after,
        created_before=created_before,
    )
    events = ProjectService(session).list_all_audit_events(principal, filters, page)
    return ok_page(events, AuditEventOut.of)
