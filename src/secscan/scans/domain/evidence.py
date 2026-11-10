"""原始證據的保護狀態（docs/DECISIONS.md §30.3、§30.5）。

runs volume 中每個 run 的目錄由 runner 的 keeper 在 run 結束（解析完成、失敗或逾期）、容器確認刪除
之後加密，保留期限到了再清除：

- none：從來沒有目錄（例如排隊中就取消、啟動之前就失敗）；不是失敗。
- pending：還沒加密（執行中、等待解析，或加密失敗後等待重試）。DB 沒有紀錄就是 pending。
- sealed：只剩加密檔（已驗證解得開而且內容相符，才刪除明文）。
- purged：保留期限到了，整個目錄已刪除（只是 unlink，不抹除磁碟上的資料區塊）。
- manual_intervention_required：目錄超過深度或條目數的上限，連續 HOLD_AFTER_FAILURES 次加密失敗，
  keeper 已隔離它（明文保留原狀、不再自動重試），等待 `secscan-admin retry-evidence`
  （docs/DECISIONS.md §30.12）。DB 中是 evidence_holds 的紀錄，不是 run_evidence。
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

# 加密與 context：`evidence:<run_id>`（runs volume 的目錄名稱也是 run_id）。
EVIDENCE_CONTEXT_PREFIX = "evidence:"
# 同一個目錄連續幾次因為超過上限而加密失敗，keeper 就隔離它（§30.12；刻意不做成設定）。
HOLD_AFTER_FAILURES = 3


class EvidenceStatus(StrEnum):
    NONE = "none"
    PENDING = "pending"
    SEALED = "sealed"
    PURGED = "purged"
    MANUAL_INTERVENTION_REQUIRED = "manual_intervention_required"


# DB 有紀錄的狀態（pending 沒有紀錄；需要人工處理的紀錄在 evidence_holds）。
RECORDED_EVIDENCE_STATUSES = frozenset(
    {EvidenceStatus.NONE, EvidenceStatus.SEALED, EvidenceStatus.PURGED}
)


class EvidenceHoldCode(StrEnum):
    """keeper 隔離一個目錄的原因：只有這兩種上限（其他失敗照舊退避、全域 fail closed）。"""

    TREE_TOO_DEEP = "EVIDENCE_TREE_TOO_DEEP"
    TREE_TOO_MANY_ENTRIES = "EVIDENCE_TREE_TOO_MANY_ENTRIES"


@dataclass(frozen=True, slots=True)
class EvidenceHold:
    """一個目錄的隔離紀錄：原因、隔離之前連續失敗的次數，以及人工重試加密成功的時間。"""

    code: EvidenceHoldCode
    attempts: int
    held_at: datetime
    resolved_at: datetime | None = None

    def __post_init__(self) -> None:
        if self.attempts < 1:
            raise ValueError("隔離紀錄的失敗次數至少是 1")
        if self.resolved_at is not None and self.resolved_at < self.held_at:
            raise ValueError("隔離紀錄的解除時間不可早於隔離時間")

    @property
    def active(self) -> bool:
        """還沒解除：需要人工處理。"""
        return self.resolved_at is None


@dataclass(frozen=True, slots=True)
class SealedEvidence:
    """一個目錄加密的結果：加密了幾個檔案、明文共多少 bytes。"""

    files: int
    plaintext_bytes: int

    def __post_init__(self) -> None:
        if self.files < 0 or self.plaintext_bytes < 0:
            raise ValueError("數量不可為負")


@dataclass(frozen=True, slots=True)
class EvidenceState:
    """API 顯示的狀態與時間；pending、none 沒有時間。hold 是隔離紀錄（解除之後仍保留）。"""

    status: EvidenceStatus
    sealed_at: datetime | None = None
    purged_at: datetime | None = None
    hold: EvidenceHold | None = None

    def __post_init__(self) -> None:
        if self.status is EvidenceStatus.MANUAL_INTERVENTION_REQUIRED and not (
            self.hold is not None and self.hold.active
        ):
            raise ValueError("需要人工處理的狀態必須有還沒解除的隔離紀錄")

    @property
    def encrypted(self) -> bool:
        """原始檔案只剩加密檔（已清除的也曾經只剩加密檔）。"""
        return self.status in (EvidenceStatus.SEALED, EvidenceStatus.PURGED)


PENDING_EVIDENCE = EvidenceState(EvidenceStatus.PENDING)


def evidence_context(name: str) -> str:
    """run 目錄的加密 context（name 是 run_id 的標準字串）。"""
    return f"{EVIDENCE_CONTEXT_PREFIX}{name}"
