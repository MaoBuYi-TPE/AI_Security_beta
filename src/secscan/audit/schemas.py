"""稽核事件的回應 schema（GET /api/v1/projects/{project_id}/audit-events）。"""

from datetime import datetime
from typing import Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from secscan.audit.domain import AuditEvent
from secscan.core.json_types import JsonObject
from secscan.security.redaction import redact_object


class AuditEventOut(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: UUID
    created_at: datetime
    action: str
    object_type: str
    object_id: UUID | None
    actor_key_id: UUID | None
    request_id: str | None
    changes: JsonObject

    @classmethod
    def of(cls, event: AuditEvent) -> Self:
        # 寫入時已遮罩；讀出時再遮罩一次，防範不是經由 audit service 寫入的資料列。
        return cls(
            id=event.id,
            created_at=event.created_at,
            action=event.action,
            object_type=event.object_type,
            object_id=event.object_id,
            actor_key_id=event.actor_key_id,
            request_id=event.request_id,
            changes=redact_object(event.redacted_changes),
        )
