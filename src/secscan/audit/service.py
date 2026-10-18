"""稽核事件的寫入與查詢；changes 一律先遮罩再寫入（docs/DECISIONS.md §9）。"""

from collections.abc import Mapping
from uuid import UUID

from sqlalchemy.orm import Session

from secscan.audit.domain import AuditEvent, NewAuditEvent
from secscan.audit.repository import AuditEventRepository
from secscan.core.json_types import JsonValue
from secscan.core.pagination import Page, PageRequest
from secscan.security.redaction import redact_object


class AuditTrail:
    """與業務變更共用同一個 session：事件和變更一起 commit，或一起 rollback。"""

    def __init__(self, session: Session) -> None:
        self._events = AuditEventRepository(session)

    def record(
        self,
        *,
        action: str,
        object_type: str,
        object_id: UUID | None,
        actor_key_id: UUID | None,
        project_id: UUID | None,
        request_id: str | None,
        changes: Mapping[str, JsonValue],
    ) -> AuditEvent:
        """actor_key_id 為 None 代表本機 CLI 或系統動作；project_id 為 None 代表全域動作。"""
        return self._events.append(
            NewAuditEvent(
                action=action,
                object_type=object_type,
                actor_key_id=actor_key_id,
                project_id=project_id,
                object_id=object_id,
                request_id=request_id,
                redacted_changes=redact_object(changes),
            )
        )

    def list_for_project(self, project_id: UUID, page: PageRequest) -> Page[AuditEvent]:
        return self._events.list_by_project(project_id, page)
