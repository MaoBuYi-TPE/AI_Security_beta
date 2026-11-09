"""原始證據的保護狀態（docs/DECISIONS.md §30.3、§30.5）。

runs volume 中每個 run 的目錄由 runner 的 keeper 在 run 結束（解析完成、失敗或逾期）、容器確認刪除
之後加密，保留期限到了再清除：

- none：從來沒有目錄（例如排隊中就取消、啟動之前就失敗）；不是失敗。
- pending：還沒加密（執行中、等待解析，或加密失敗後等待重試）。DB 沒有紀錄就是 pending。
- sealed：只剩加密檔（已驗證解得開而且內容相符，才刪除明文）。
- purged：保留期限到了，整個目錄已刪除（只是 unlink，不抹除磁碟上的資料區塊）。
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

# 加密與 context：`evidence:<run_id>`（runs volume 的目錄名稱也是 run_id）。
EVIDENCE_CONTEXT_PREFIX = "evidence:"


class EvidenceStatus(StrEnum):
    NONE = "none"
    PENDING = "pending"
    SEALED = "sealed"
    PURGED = "purged"


# DB 有紀錄的狀態（pending 沒有紀錄）。
RECORDED_EVIDENCE_STATUSES = frozenset(
    {EvidenceStatus.NONE, EvidenceStatus.SEALED, EvidenceStatus.PURGED}
)


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
    """API 顯示的狀態與時間；pending、none 沒有時間。"""

    status: EvidenceStatus
    sealed_at: datetime | None = None
    purged_at: datetime | None = None

    @property
    def encrypted(self) -> bool:
        """原始檔案只剩加密檔（已清除的也曾經只剩加密檔）。"""
        return self.status in (EvidenceStatus.SEALED, EvidenceStatus.PURGED)


PENDING_EVIDENCE = EvidenceState(EvidenceStatus.PENDING)


def evidence_context(name: str) -> str:
    """run 目錄的加密 context（name 是 run_id 的標準字串）。"""
    return f"{EVIDENCE_CONTEXT_PREFIX}{name}"
