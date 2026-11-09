"""reports 與 report_contents 資料表（v0018；docs/DECISIONS.md §28.5）。

狀態轉換、終止的列不可修改、內容只寫一次與雙向核對都由 migration 的 trigger 強制。跨功能的 FK
以資料表名稱引用。
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Identity,
    Index,
    LargeBinary,
    SmallInteger,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from secscan.core.db import Base, UuidPrimaryKeyMixin
from secscan.reports.domain.model import MAX_REPORT_BYTES, MAX_SEALED_REPORT_BYTES

_RESULT_NULL = (
    "data_as_of IS NULL AND generated_at IS NULL AND size_bytes IS NULL AND sha256 IS NULL "
    "AND truncated IS NULL AND omitted_findings IS NULL"
)
_LEASE_NULL = "lease_owner IS NULL AND lease_expires_at IS NULL AND heartbeat_at IS NULL"


class ReportModel(UuidPrimaryKeyMixin, Base):
    __tablename__ = "reports"
    __table_args__ = (
        UniqueConstraint("project_id", "idempotency_key"),
        ForeignKeyConstraint(
            ["scan_id", "target_id", "project_id"],
            ["scans.id", "scans.target_id", "scans.project_id"],
            ondelete="RESTRICT",
        ),
        Index(None, "scan_id"),
        Index(None, "requested_by_key_id"),
        Index(
            "ix_reports_active_queue",
            "queue_position",
            postgresql_where=text("status IN ('queued', 'generating')"),
        ),
        # 到期清除（T23a，v0022）：還保留內容、已完成的報告依期限排序。
        Index(
            "ix_reports_expiry",
            "expires_at",
            postgresql_where=text("status = 'succeeded' AND content_purged_at IS NULL"),
        ),
        CheckConstraint("format IN ('json', 'markdown')", name="format_valid"),
        CheckConstraint("schema_version = 1", name="schema_version_valid"),
        CheckConstraint(
            "status IN ('queued', 'generating', 'succeeded', 'failed')", name="status_valid"
        ),
        CheckConstraint("attempts >= 0 AND attempts <= 3", name="attempts_valid"),
        CheckConstraint(
            "idempotency_key ~ '^[A-Za-z0-9_-]{16,128}$'", name="idempotency_key_valid"
        ),
        CheckConstraint("octet_length(request_sha256) = 32", name="request_sha256_length"),
        # 單獨看不 NULL 安全；和各狀態的 shape CHECK 一起才完整（新增狀態時要補 shape）。
        CheckConstraint(
            f"size_bytes IS NULL OR (size_bytes >= 1 AND size_bytes <= {MAX_REPORT_BYTES} "
            "AND sha256 ~ '^[0-9a-f]{64}$' AND omitted_findings >= 0 "
            "AND truncated = (omitted_findings > 0))",
            name="result_valid",
        ),
        CheckConstraint(
            f"status <> 'queued' OR ({_LEASE_NULL} AND {_RESULT_NULL} "
            "AND error_code IS NULL AND finished_at IS NULL AND attempts < 3)",
            name="queued_shape",
        ),
        CheckConstraint(
            "status <> 'generating' OR (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL "
            f"AND attempts >= 1 AND {_RESULT_NULL} AND error_code IS NULL "
            "AND finished_at IS NULL)",
            name="generating_shape",
        ),
        CheckConstraint(
            f"status <> 'succeeded' OR ({_LEASE_NULL} AND data_as_of IS NOT NULL "
            "AND generated_at IS NOT NULL AND size_bytes IS NOT NULL AND sha256 IS NOT NULL "
            "AND truncated IS NOT NULL AND omitted_findings IS NOT NULL AND error_code IS NULL "
            "AND finished_at IS NOT NULL)",
            name="succeeded_shape",
        ),
        CheckConstraint(
            f"status <> 'failed' OR ({_LEASE_NULL} AND {_RESULT_NULL} "
            "AND error_code IS NOT NULL AND error_code ~ '^[A-Z][A-Z0-9_]{1,63}$' "
            "AND finished_at IS NOT NULL)",
            name="failed_shape",
        ),
        # 到期與清除（v0022；docs/DECISIONS.md §30.5）：succeeded 才有期限；清除不早於期限。
        CheckConstraint(
            "(status = 'succeeded') = (expires_at IS NOT NULL)", name="expires_matches_status"
        ),
        CheckConstraint(
            "content_purged_at IS NULL "
            "OR (status = 'succeeded' AND content_purged_at >= expires_at)",
            name="purged_after_expiry",
        ),
    )

    queue_position: Mapped[int] = mapped_column(
        BigInteger, Identity(always=True), unique=True, sort_order=-1
    )
    project_id: Mapped[UUID]
    target_id: Mapped[UUID]
    scan_id: Mapped[UUID]
    format: Mapped[str] = mapped_column(String(16))
    schema_version: Mapped[int]
    status: Mapped[str] = mapped_column(String(16))
    idempotency_key: Mapped[str] = mapped_column(String(128))
    request_sha256: Mapped[bytes] = mapped_column(LargeBinary)
    requested_by_key_id: Mapped[UUID] = mapped_column(
        ForeignKey("api_keys.id", ondelete="RESTRICT")
    )
    attempts: Mapped[int] = mapped_column(server_default=text("0"))
    lease_owner: Mapped[str | None] = mapped_column(String(128))
    lease_expires_at: Mapped[datetime | None]
    heartbeat_at: Mapped[datetime | None]
    error_code: Mapped[str | None] = mapped_column(String(64))
    data_as_of: Mapped[datetime | None]
    generated_at: Mapped[datetime | None]
    size_bytes: Mapped[int | None]
    sha256: Mapped[str | None] = mapped_column(String(64))
    truncated: Mapped[bool | None]
    omitted_findings: Mapped[int | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    finished_at: Mapped[datetime | None]
    expires_at: Mapped[datetime | None]
    content_purged_at: Mapped[datetime | None]


class ReportContentModel(Base):
    """報告的內容：CONTENT_ENCRYPTION_KEYS 加密的 Fernet token（v0022）。明文的 sha256 與大小在
    reports；換版時只能換 content，到期清除時整列刪除（v0022 的 trigger）。"""

    __tablename__ = "report_contents"
    __table_args__ = (
        CheckConstraint(
            f"octet_length(content) >= 1 AND octet_length(content) <= {MAX_SEALED_REPORT_BYTES} "
            "AND substring(content FROM 1 FOR 6) = 'gAAAAA'::bytea",
            name="content_sealed",
        ),
    )

    report_id: Mapped[UUID] = mapped_column(
        ForeignKey("reports.id", ondelete="RESTRICT"), primary_key=True
    )
    # DB 層的 fencing token：寫入時的嘗試次數與 lease 的持有者（insert guard 核對）。
    attempt: Mapped[int] = mapped_column(SmallInteger)
    lease_owner: Mapped[str] = mapped_column(String(128))
    content: Mapped[bytes] = mapped_column(LargeBinary)
