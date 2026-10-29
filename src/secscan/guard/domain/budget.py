"""共享預算的速率與請求數（docs/DECISIONS.md §16；SEC-13）。

- RunBudget：這個 run 的速率、burst 與剩下的請求數。runner 由 scan 的預算減去之前的 run 實際轉送的
  請求數算出，所以 preflight 與每個引擎合計不會超過 scan 的上限。
- RateLimiter：GCRA（等同 burst 個 token 的 token bucket），以 scan 為 key：同一個 scan 的 run 依序
  執行，共用同一個速率。超過速率時回傳要等待的秒數（使用者的決定：讓請求等待），最多
  MAX_RATE_WAIT_SECONDS；等不到就不保留位置，請求被拒絕（RATE_LIMITED）。
- RunLedger：放行之前先保留一個名額（同時進行的請求不會一起超過上限），被拒絕就釋放；只計真的
  轉送的請求。
"""

from collections import OrderedDict
from dataclasses import dataclass
from uuid import UUID

from secscan.grants.domain.scope import MAX_REQUESTS, MAX_REQUESTS_PER_SECOND

MAX_RATE_WAIT_SECONDS = 5.0
DEFAULT_MAX_ENTRIES = 1024


class BudgetError(ValueError):
    """預算的值不合規則，或計數的用法錯誤。"""


@dataclass(frozen=True, slots=True)
class RunBudget:
    requests_per_second: int
    burst: int
    max_requests: int

    def __post_init__(self) -> None:
        if not _is_int(self.requests_per_second) or not (
            1 <= self.requests_per_second <= MAX_REQUESTS_PER_SECOND
        ):
            raise BudgetError(f"requests_per_second 必須是 1 到 {MAX_REQUESTS_PER_SECOND}")
        if not _is_int(self.burst) or not 1 <= self.burst <= self.requests_per_second:
            raise BudgetError("burst 必須是 1 到 requests_per_second")
        if not _is_int(self.max_requests) or not 0 <= self.max_requests <= MAX_REQUESTS:
            raise BudgetError(f"max_requests 必須是 0 到 {MAX_REQUESTS}")


class RateLimiter:
    """GCRA：每個 key 記下「理論上下一個請求的時間」（TAT）。guard 是單執行緒的 asyncio，保留位置
    （讀出與寫回 TAT）之間沒有 await，所以同時進行的請求會依序排隊。
    """

    def __init__(
        self,
        *,
        max_wait: float = MAX_RATE_WAIT_SECONDS,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ) -> None:
        self._max_wait = max_wait
        self._max_entries = max_entries
        self._tat: OrderedDict[UUID, float] = OrderedDict()

    @property
    def entries(self) -> int:
        return len(self._tat)

    def reserve(self, key: UUID, budget: RunBudget, *, now: float) -> float | None:
        """保留一個位置，回傳要等待的秒數；要等超過上限時回 None（不保留）。"""
        interval = 1.0 / budget.requests_per_second
        tolerance = (budget.burst - 1) * interval
        tat = max(self._tat.get(key, now), now)
        wait = max(0.0, tat - tolerance - now)
        if wait > self._max_wait:
            return None
        self._tat[key] = tat + interval
        self._tat.move_to_end(key)
        self._prune(now)
        return wait

    def _prune(self, now: float) -> None:
        """超過上限時刪掉已經過時（TAT 早於現在）的 key；不影響任何還在限速中的 scan。"""
        if len(self._tat) <= self._max_entries:
            return
        for key in [key for key, tat in self._tat.items() if tat <= now]:
            del self._tat[key]


class RunLedger:
    """一個 run 轉送的請求數；名額先保留、轉送之後才確定。guard 重啟時由 summary 接續計數。"""

    def __init__(self, *, forwarded: int = 0) -> None:
        if not _is_int(forwarded) or forwarded < 0:
            raise BudgetError("forwarded 必須是非負整數")
        self.forwarded = forwarded
        self._pending = 0

    def reserve(self, *, maximum: int) -> bool:
        if self.forwarded + self._pending >= maximum:
            return False
        self._pending += 1
        return True

    def commit(self) -> None:
        self._take()
        self.forwarded += 1

    def release(self) -> None:
        self._take()

    @property
    def pending(self) -> int:
        return self._pending

    def exhausted(self, *, maximum: int) -> bool:
        """已經轉送到上限：之後的請求都會被拒絕，runner 據此停止工具。"""
        return self.forwarded >= maximum

    def _take(self) -> None:
        if self._pending <= 0:
            raise BudgetError("沒有保留中的名額")
        self._pending -= 1


def _is_int(value: object) -> bool:
    return type(value) is int
