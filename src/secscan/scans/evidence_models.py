"""run_evidence 資料表（docs/DECISIONS.md §30.3）：runs volume 中每個 run 的原始證據狀態。

- 沒有紀錄就是 pending（還沒加密）；keeper 加密完成（或確認從來沒有目錄）時新增一列，保留期限到了
  再把 sealed 改成 purged。只能新增一次、只能清除一次、不能刪除（migration 的 trigger）。
- 只保存狀態、時間與數量，不保存路徑或內容。
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import BigInteger, CheckConstraint, ForeignKeyConstraint, Index, String, func, text
from sqlalchemy.orm import Mapped, mapped_column

from secscan.core.db import Base
from secscan.scans.domain.evidence import (
    PENDING_EVIDENCE,
    RECORDED_EVIDENCE_STATUSES,
    EvidenceState,
    EvidenceStatus,
)

EVIDENCE_STATUS_MAX_LENGTH = 16
_STATUSES = ", ".join(f"'{status.value}'" for status in sorted(RECORDED_EVIDENCE_STATUSES))
_NONE = EvidenceStatus.NONE.value
_SEALED = EvidenceStatus.SEALED.value
_PURGED = EvidenceStatus.PURGED.value


class RunEvidenceModel(Base):
    __tablename__ = "run_evidence"
    __table_args__ = (
        ForeignKeyConstraint(
            ["scanner_run_id", "scan_id"],
            ["scanner_runs.id", "scanner_runs.scan_id"],
            ondelete="RESTRICT",
        ),
        # 清除：找加密時間已過保留期限的目錄。
        Index(
            "ix_run_evidence_sealed",
            "sealed_at",
            postgresql_where=text(f"status = '{_SEALED}'"),
        ),
        CheckConstraint(f"status IN ({_STATUSES})", name="status_valid"),
        CheckConstraint(
            f"(status = '{_NONE}') = (sealed_at IS NULL)", name="sealed_matches_status"
        ),
        CheckConstraint(
            f"(status = '{_PURGED}') = (purged_at IS NOT NULL)", name="purged_matches_status"
        ),
        CheckConstraint("purged_at IS NULL OR purged_at >= sealed_at", name="purged_after_sealed"),
        CheckConstraint(
            "file_count >= 0 AND plaintext_bytes >= 0 "
            f"AND (status <> '{_NONE}' OR (file_count = 0 AND plaintext_bytes = 0))",
            name="counts_valid",
        ),
    )

    scanner_run_id: Mapped[UUID] = mapped_column(primary_key=True)
    scan_id: Mapped[UUID]
    status: Mapped[str] = mapped_column(String(EVIDENCE_STATUS_MAX_LENGTH))
    file_count: Mapped[int]
    plaintext_bytes: Mapped[int] = mapped_column(BigInteger)
    sealed_at: Mapped[datetime | None]
    purged_at: Mapped[datetime | None]
    recorded_at: Mapped[datetime] = mapped_column(server_default=func.clock_timestamp())


def evidence_state(model: RunEvidenceModel | None) -> EvidenceState:
    """DB 的紀錄 → API 顯示的狀態（沒有紀錄是 pending）。"""
    if model is None:
        return PENDING_EVIDENCE
    return EvidenceState(
        EvidenceStatus(model.status), sealed_at=model.sealed_at, purged_at=model.purged_at
    )
