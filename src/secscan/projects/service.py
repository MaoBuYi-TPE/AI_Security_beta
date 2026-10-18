"""projects 的業務規則（docs/DECISIONS.md §9.2）：

- 建立 project 只限 platform_admin，並寫 audit。
- 清單：platform_admin 看到全部，其他角色只看到自己的 project。
- 單一 project 與稽核查詢：先經權限規則，其他 project 與不存在的 project 一樣回 404。
"""

from http import HTTPStatus
from uuid import UUID

from sqlalchemy.orm import Session

from secscan.api_keys.access import authorize
from secscan.api_keys.domain import Permission, Principal
from secscan.audit.domain import AuditEvent
from secscan.audit.service import AuditTrail
from secscan.core.db import ConstraintViolationError
from secscan.core.errors import AppError, ErrorCode, not_found_error
from secscan.core.pagination import Page, PageRequest
from secscan.projects.domain import NewProject, Project
from secscan.projects.repository import ProjectRepository


class ProjectService:
    def __init__(self, session: Session) -> None:
        self._projects = ProjectRepository(session)
        self._audit = AuditTrail(session)

    def create(self, principal: Principal, *, name: str, request_id: str | None) -> Project:
        authorize(principal, Permission.PLATFORM_MANAGE)
        try:
            project = self._projects.create(NewProject(name=name))
        except ConstraintViolationError as violation:
            if violation.constraint == "uq_projects_name":
                raise AppError(
                    status_code=HTTPStatus.CONFLICT,
                    code=ErrorCode.PROJECT_NAME_CONFLICT,
                    message="已有相同名稱的專案。",
                ) from None
            raise
        self._audit.record(
            action="project.create",
            object_type="project",
            object_id=project.id,
            actor_key_id=principal.key_id,
            project_id=project.id,
            request_id=request_id,
            changes={"name": project.name},
        )
        return project

    def list_visible(self, principal: Principal, page: PageRequest) -> Page[Project]:
        return self._projects.list_page(page, scope=principal.project_scope)

    def get(self, principal: Principal, project_id: UUID) -> Project:
        authorize(principal, Permission.PROJECT_READ, project_id)
        return self._existing(project_id)

    def list_audit_events(
        self, principal: Principal, project_id: UUID, page: PageRequest
    ) -> Page[AuditEvent]:
        authorize(principal, Permission.PLATFORM_MANAGE, project_id)
        self._existing(project_id)
        return self._audit.list_for_project(project_id, page)

    def _existing(self, project_id: UUID) -> Project:
        project = self._projects.get(project_id)
        if project is None:
            raise not_found_error()
        return project
