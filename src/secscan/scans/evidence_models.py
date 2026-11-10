"""run_evidence 與 evidence_holds 資料表（docs/DECISIONS.md §30.3、§30.12）：runs volume 中每個
run 的原始證據狀態，以及需要人工處理的目錄。

- run_evidence：沒有紀錄就是 pending（還沒加密）；keeper 加密完成（或確認從來沒有目錄）時新增一列，
  保留期限到了再把 sealed 改成 purged。只能新增一次、只能清除一次、不能刪除（migration 的
  trigger）。
- evidence_holds：一個目錄連續超過上限而加密失敗時，keeper 新增一列（run 的目錄帶 run 的欄位，
  孤兒目錄沒有）；`secscan-admin retry-evidence` 加密成功之後才寫入 resolved_at（只能一次，run 必須
  已有 sealed 的 run_evidence）。不能刪除（migration 0023 的 trigger）。
- 只保存狀態、時間、數量與錯誤代碼，不保存路徑或內容。
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import BigInteger, CheckConstraint, ForeignKeyConstraint, Index, String, func, text
from sqlalchemy.orm import Mapped, mapped_column

from secscan.core.db import Base
from secscan.scans.domain.evidence import (
    PENDING_EVIDENCE,
    RECORDED_EVIDENCE_STATUSES,
    EvidenceHold,
    EvidenceHoldCode,
    EvidenceState,
    EvidenceStatus,
)

EVIDENCE_STATUS_MAX_LENGTH = 16
EVIDENCE_HOLD_CODE_MAX_LENGTH = 32
_HOLD_CODES = ", ".join(f"'{code.value}'" for code in sorted(EvidenceHoldCode))
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


class EvidenceHoldModel(Base):
    __tablename__ = "evidence_holds"
    __table_args__ = (
        ForeignKeyConstraint(
            ["scanner_run_id", "scan_id"],
            ["scanner_runs.id", "scanner_runs.scan_id"],
            ondelete="RESTRICT",
        ),
        # retention-status：還沒解除的隔離（最早的在前）。
        Index(
            "ix_evidence_holds_active",
            "held_at",
            postgresql_where=text("resolved_at IS NULL"),
        ),
        CheckConstraint("(scanner_run_id IS NULL) = (scan_id IS NULL)", name="run_columns_paired"),
        CheckConstraint(
            "scanner_run_id IS NULL OR scanner_run_id = directory", name="directory_is_run"
        ),
        CheckConstraint(f"error_code IN ({_HOLD_CODES})", name="error_code_valid"),
        CheckConstraint("attempts >= 1", name="attempts_positive"),
        CheckConstraint(
            "resolved_at IS NULL OR resolved_at >= held_at", name="resolved_after_held"
        ),
    )

    # runs volume 中的目錄名稱（run 的目錄就是 run_id）。
    directory: Mapped[UUID] = mapped_column(primary_key=True)
    scanner_run_id: Mapped[UUID | None]
    scan_id: Mapped[UUID | None]
    error_code: Mapped[str] = mapped_column(String(EVIDENCE_HOLD_CODE_MAX_LENGTH))
    attempts: Mapped[int]
    held_at: Mapped[datetime] = mapped_column(server_default=func.clock_timestamp())
    resolved_at: Mapped[datetime | None]


def evidence_hold(model: EvidenceHoldModel) -> EvidenceHold:
    return EvidenceHold(
        code=EvidenceHoldCode(model.error_code),
        attempts=model.attempts,
        held_at=model.held_at,
        resolved_at=model.resolved_at,
    )


def evidence_state(
    evidence: RunEvidenceModel | None, hold: EvidenceHoldModel | None
) -> EvidenceState:
    """DB 的紀錄 → API 顯示的狀態：還沒解除的隔離優先（fail closed 的顯示：就算出現不一致的
    run_evidence，也不顯示成已加密；安全審查 L3），再看 run_evidence，都沒有是 pending。"""
    held = None if hold is None else evidence_hold(hold)
    if held is not None and held.active:
        return EvidenceState(EvidenceStatus.MANUAL_INTERVENTION_REQUIRED, hold=held)
    if evidence is not None:
        return EvidenceState(
            EvidenceStatus(evidence.status),
            sealed_at=evidence.sealed_at,
            purged_at=evidence.purged_at,
            hold=held,
        )
    return PENDING_EVIDENCE
