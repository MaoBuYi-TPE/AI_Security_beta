"""audit_events 資料表（docs/ARCHITECTURE.md §6）。

append-only：migration 另建 trigger，拒絕 UPDATE、DELETE 與 TRUNCATE。
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import CheckConstraint, ForeignKey, Index, String, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from secscan.audit.domain import AUDIT_LABEL_MAX_LENGTH, REQUEST_ID_MAX_LENGTH
from secscan.core.db import Base, UuidPrimaryKeyMixin
from secscan.core.json_types import JsonObject


class AuditEventModel(UuidPrimaryKeyMixin, Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        # 依 project 由新到舊列出（GET /projects/{id}/audit-events）。
        Index(None, "project_id", "created_at"),
        CheckConstraint("char_length(btrim(action)) > 0", name="action_not_blank"),
        CheckConstraint("char_length(btrim(object_type)) > 0", name="object_type_not_blank"),
        CheckConstraint("jsonb_typeof(redacted_changes) = 'object'", name="changes_is_object"),
    )

    # clock_timestamp()：同一 transaction 內的多筆事件仍保有實際先後。
    created_at: Mapped[datetime] = mapped_column(server_default=func.clock_timestamp())
    actor_key_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("api_keys.id", ondelete="RESTRICT")
    )
    project_id: Mapped[UUID | None] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"))
    action: Mapped[str] = mapped_column(String(AUDIT_LABEL_MAX_LENGTH))
    object_type: Mapped[str] = mapped_column(String(AUDIT_LABEL_MAX_LENGTH))
    object_id: Mapped[UUID | None]
    request_id: Mapped[str | None] = mapped_column(String(REQUEST_ID_MAX_LENGTH))
    redacted_changes: Mapped[JsonObject] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
