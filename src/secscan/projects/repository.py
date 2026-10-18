"""projects 的資料存取；回傳 frozen domain model。授權過濾由 service 層負責（T05）。"""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

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

    def list_page(self, page: PageRequest) -> Page[Project]:
        """依建立時間由舊到新列出（同時間再依 id，順序穩定，分頁不會漏或重複）。"""
        total = self._session.scalar(select(func.count()).select_from(ProjectModel)) or 0
        rows = self._session.scalars(
            select(ProjectModel)
            .order_by(ProjectModel.created_at, ProjectModel.id)
            .offset(page.offset)
            .limit(page.limit)
        )
        return Page(items=tuple(_to_domain(row) for row in rows), total=total, request=page)


def _to_domain(model: ProjectModel) -> Project:
    return Project(id=model.id, name=model.name, created_at=model.created_at)
