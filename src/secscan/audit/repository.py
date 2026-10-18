"""audit_events 的資料存取：只提供新增與查詢，沒有修改或刪除。"""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from secscan.audit.domain import AuditEvent, NewAuditEvent
from secscan.audit.models import AuditEventModel
from secscan.core.db import flush_or_raise
from secscan.core.pagination import Page, PageRequest


class AuditEventRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def append(self, event: NewAuditEvent) -> AuditEvent:
        model = AuditEventModel(
            actor_key_id=event.actor_key_id,
            project_id=event.project_id,
            action=event.action,
            object_type=event.object_type,
            object_id=event.object_id,
            request_id=event.request_id,
            redacted_changes=dict(event.redacted_changes),
        )
        self._session.add(model)
        flush_or_raise(self._session)
        return _to_domain(model)

    def list_by_project(self, project_id: UUID, page: PageRequest) -> Page[AuditEvent]:
        """只列出該 project 的事件，由新到舊（同時間再依 id，分頁順序穩定）。"""
        in_project = AuditEventModel.project_id == project_id
        total = (
            self._session.scalar(
                select(func.count()).select_from(AuditEventModel).where(in_project)
            )
            or 0
        )
        rows = self._session.scalars(
            select(AuditEventModel)
            .where(in_project)
            .order_by(AuditEventModel.created_at.desc(), AuditEventModel.id.desc())
            .offset(page.offset)
            .limit(page.limit)
        )
        return Page(items=tuple(_to_domain(row) for row in rows), total=total, request=page)


def _to_domain(model: AuditEventModel) -> AuditEvent:
    return AuditEvent(
        id=model.id,
        created_at=model.created_at,
        action=model.action,
        object_type=model.object_type,
        actor_key_id=model.actor_key_id,
        project_id=model.project_id,
        object_id=model.object_id,
        request_id=model.request_id,
        redacted_changes=dict(model.redacted_changes),
    )
