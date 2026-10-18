"""projects 的資料存取；回傳 frozen domain model。誰能看到哪些 project 由 service 決定。"""

from uuid import UUID

from sqlalchemy import ColumnElement, func, select
from sqlalchemy.orm import Session

from secscan.api_keys.domain import AllProjects, OneProject, ProjectScope
from secscan.core.db import flush_or_raise
from secscan.core.pagination import Page, PageRequest
from secscan.projects.domain import NewProject, Project
from secscan.projects.models import ProjectModel


class ProjectRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, new_project: NewProject) -> Project:
        """新增專案；名稱重複時拋出 ConstraintViolationError（uq_projects_name）。"""
        model = ProjectModel(name=new_project.name)
        self._session.add(model)
        flush_or_raise(self._session)
        return _to_domain(model)

    def get(self, project_id: UUID) -> Project | None:
        model = self._session.get(ProjectModel, project_id)
        return _to_domain(model) if model is not None else None

    def list_page(self, page: PageRequest, *, scope: ProjectScope) -> Page[Project]:
        """依建立時間由舊到新列出（同時間再依 id，順序穩定，分頁不會漏或重複）。

        scope 沒有預設值，呼叫端必須明確決定（通常是 Principal.project_scope）。
        """
        conditions = _scope_conditions(scope)
        total = (
            self._session.scalar(select(func.count()).select_from(ProjectModel).where(*conditions))
            or 0
        )
        rows = self._session.scalars(
            select(ProjectModel)
            .where(*conditions)
            .order_by(ProjectModel.created_at, ProjectModel.id)
            .offset(page.offset)
            .limit(page.limit)
        )
        return Page(items=tuple(_to_domain(row) for row in rows), total=total, request=page)


def _scope_conditions(scope: ProjectScope) -> list[ColumnElement[bool]]:
    match scope:
        case AllProjects():
            return []
        case OneProject(project_id=project_id):
            return [ProjectModel.id == project_id]
    # 型別外的值（例如 None）不能默默變成「全部」。
    raise TypeError(f"不支援的 project scope：{type(scope).__name__}")


def _to_domain(model: ProjectModel) -> Project:
    return Project(id=model.id, name=model.name, created_at=model.created_at)
