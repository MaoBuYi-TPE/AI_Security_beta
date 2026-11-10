"""keeper 對每個目錄的重試狀態（docs/DECISIONS.md §30.3、§30.12）：只在記憶體中，不寫 DB。

- 退避：失敗的 run 與孤兒目錄 20 秒起倍增，最多 10 分鐘；不會每一輪都重試、佔滿批次而讓其他 run
  等不到加密（安全審查 M1）。還在退避的仍算不健康。
- 連續的上限失敗（EvidenceLimitError：深度或條目數超過上限）：上限失敗加一、其他種類的失敗歸零、
  成功就清除。到了 HOLD_AFTER_FAILURES 次，keeper 就隔離這個目錄、改成需要人工處理。
- runner 重啟會重新計數：只會延後隔離，不會提早。
run 以 run_id（UUID）、孤兒目錄以目錄名稱（str）為鍵。
"""

from collections.abc import Callable, Collection
from dataclasses import dataclass
from uuid import UUID

from secscan.runner.sealed_files import EvidenceLimitError
from secscan.scans.domain.evidence import HOLD_AFTER_FAILURES, EvidenceHoldCode

MAX_BACKOFF_SECONDS = 600.0
# 限制次方（2**16 倍已遠超過 10 分鐘的上限）：長時間的故障才不會讓浮點數溢位。
_MAX_EXPONENT = 16

type BackoffKey = UUID | str


@dataclass(frozen=True, slots=True)
class Attempt:
    """一個目錄的重試狀態：失敗的次數、下一次重試的時間（monotonic）、連續的上限失敗與代碼。"""

    failures: int
    retry_at: float
    streak: int = 0
    code: EvidenceHoldCode | None = None

    def hold_code(self) -> EvidenceHoldCode | None:
        """連續的上限失敗到了隔離的次數時，回傳隔離的錯誤代碼（最後一次的上限）。"""
        if self.code is None or self.streak < HOLD_AFTER_FAILURES:
            return None
        return self.code


class Backoff:
    def __init__(self, interval_seconds: float, monotonic: Callable[[], float]) -> None:
        self._interval = interval_seconds
        self._monotonic = monotonic
        self._attempts: dict[BackoffKey, Attempt] = {}

    def __len__(self) -> int:
        return len(self._attempts)

    def keys(self) -> frozenset[BackoffKey]:
        return frozenset(self._attempts)

    def failed(self, key: BackoffKey, exc: BaseException) -> Attempt:
        previous = self._attempts.get(key)
        failures = 1 if previous is None else previous.failures + 1
        delay = min(self._interval * 2 ** min(failures, _MAX_EXPONENT), MAX_BACKOFF_SECONDS)
        if isinstance(exc, EvidenceLimitError):
            streak = 1 if previous is None else previous.streak + 1
            code: EvidenceHoldCode | None = exc.code
        else:
            streak, code = 0, None
        attempt = Attempt(failures, self._monotonic() + delay, streak, code)
        self._attempts[key] = attempt
        return attempt

    def clear(self, key: BackoffKey) -> None:
        """成功或已隔離：不再退避、不再算不健康。"""
        self._attempts.pop(key, None)

    def waiting(self) -> frozenset[BackoffKey]:
        """還在退避、這一輪不重試的 run 與孤兒。"""
        now = self._monotonic()
        return frozenset(key for key, attempt in self._attempts.items() if attempt.retry_at > now)

    def waiting_runs(self) -> frozenset[UUID]:
        return frozenset(key for key in self.waiting() if isinstance(key, UUID))

    def forget_missing_orphans(self, present: Collection[str]) -> None:
        """操作者已經刪掉的孤兒目錄不再算失敗。"""
        for key in [key for key in self._attempts if isinstance(key, str) and key not in present]:
            del self._attempts[key]
