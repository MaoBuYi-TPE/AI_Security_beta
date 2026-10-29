"""共享預算的速率與請求數（docs/DECISIONS.md §16；SEC-13）。

- RunBudget：這個 run 的速率、burst 與剩下的請求數（runner 由 scan 的預算減去之前的 run 算出）。
- RateLimiter：以 scan 為 key 的 GCRA（同一個 scan 的 run 依序執行，共用同一個速率）；超過速率時
  回傳要等待的秒數，最多 5 秒，等不到就不保留位置。
- RunLedger：放行之前先保留一個名額，被拒絕就釋放；只計真的轉送的請求。
"""

from uuid import UUID

import pytest

from secscan.grants.domain.scope import MAX_REQUESTS, MAX_REQUESTS_PER_SECOND
from secscan.guard.domain.budget import (
    MAX_RATE_WAIT_SECONDS,
    BudgetError,
    RateLimiter,
    RunBudget,
    RunLedger,
)

SCAN = UUID(int=1)
OTHER = UUID(int=2)


def test_budget_bounds() -> None:
    RunBudget(requests_per_second=1, burst=1, max_requests=0)
    RunBudget(requests_per_second=MAX_REQUESTS_PER_SECOND, burst=2, max_requests=MAX_REQUESTS)


@pytest.mark.parametrize(
    "values",
    [
        (0, 1, 10),
        (MAX_REQUESTS_PER_SECOND + 1, 1, 10),
        (2, 0, 10),
        (2, 3, 10),  # burst 不可超過速率
        (2, 1, -1),
        (2, 1, MAX_REQUESTS + 1),
        (True, 1, 10),
        (2, 1, 1.5),
    ],
)
def test_budget_rejects_out_of_range_values(values: tuple[object, object, object]) -> None:
    rate, burst, maximum = values
    with pytest.raises(BudgetError):
        RunBudget(requests_per_second=rate, burst=burst, max_requests=maximum)  # type: ignore[arg-type]


# --- 速率 -------------------------------------------------------------------------------------

TWO_PER_SECOND = RunBudget(requests_per_second=2, burst=1, max_requests=100)


def test_the_first_request_goes_immediately() -> None:
    assert RateLimiter().reserve(SCAN, TWO_PER_SECOND, now=100.0) == 0.0


def test_requests_are_spaced_by_the_rate() -> None:
    limiter = RateLimiter()

    waits = [limiter.reserve(SCAN, TWO_PER_SECOND, now=100.0) for _ in range(4)]

    assert waits == [0.0, 0.5, 1.0, 1.5]


def test_waiting_longer_than_the_limit_is_refused_without_a_reservation() -> None:
    limiter = RateLimiter()
    slots = int(MAX_RATE_WAIT_SECONDS * 2) + 1
    waits = [limiter.reserve(SCAN, TWO_PER_SECOND, now=100.0) for _ in range(slots)]

    assert waits[-1] == MAX_RATE_WAIT_SECONDS
    assert limiter.reserve(SCAN, TWO_PER_SECOND, now=100.0) is None
    assert limiter.reserve(SCAN, TWO_PER_SECOND, now=100.0) is None  # 被拒絕的不佔位置
    assert limiter.reserve(SCAN, TWO_PER_SECOND, now=100.5) == MAX_RATE_WAIT_SECONDS


def test_idle_time_does_not_accumulate_beyond_the_burst() -> None:
    limiter = RateLimiter()
    limiter.reserve(SCAN, TWO_PER_SECOND, now=100.0)

    later = [limiter.reserve(SCAN, TWO_PER_SECOND, now=200.0) for _ in range(2)]

    assert later == [0.0, 0.5]


def test_burst_allows_back_to_back_requests() -> None:
    limiter = RateLimiter()
    budget = RunBudget(requests_per_second=2, burst=2, max_requests=100)

    waits = [limiter.reserve(SCAN, budget, now=100.0) for _ in range(3)]

    assert waits == [0.0, 0.0, 0.5]


def test_scans_have_separate_rates() -> None:
    limiter = RateLimiter()
    limiter.reserve(SCAN, TWO_PER_SECOND, now=100.0)

    assert limiter.reserve(OTHER, TWO_PER_SECOND, now=100.0) == 0.0


def test_stale_entries_are_pruned() -> None:
    limiter = RateLimiter(max_entries=2)
    for value in range(5):
        limiter.reserve(UUID(int=value + 10), TWO_PER_SECOND, now=float(value) * 100)

    assert limiter.entries <= 2
    assert limiter.reserve(UUID(int=14), TWO_PER_SECOND, now=400.0) == 0.5


# --- 請求數 -----------------------------------------------------------------------------------


def test_the_ledger_counts_only_committed_requests() -> None:
    ledger = RunLedger()

    assert ledger.reserve(maximum=2)
    assert ledger.reserve(maximum=2)
    assert not ledger.reserve(maximum=2)  # 兩個名額都保留了
    ledger.release()
    ledger.commit()

    assert ledger.forwarded == 1
    assert ledger.exhausted(maximum=2) is False
    assert ledger.reserve(maximum=2)
    ledger.commit()
    assert ledger.forwarded == 2
    assert ledger.exhausted(maximum=2) is True


def test_a_run_without_requests_left_is_exhausted_immediately() -> None:
    ledger = RunLedger()

    assert ledger.exhausted(maximum=0) is True
    assert not ledger.reserve(maximum=0)


def test_the_ledger_resumes_from_a_previous_count() -> None:
    ledger = RunLedger(forwarded=2)

    assert ledger.exhausted(maximum=2) is True
    assert not ledger.reserve(maximum=2)
    assert ledger.reserve(maximum=3)


def test_an_unrecorded_forward_can_be_undone() -> None:
    ledger = RunLedger()
    ledger.reserve(maximum=1)
    ledger.commit()

    ledger.uncommit()

    assert ledger.forwarded == 0
    assert ledger.reserve(maximum=1)


def test_ledger_misuse_is_an_error() -> None:
    with pytest.raises(BudgetError):
        RunLedger().commit()
    with pytest.raises(BudgetError):
        RunLedger().release()
    with pytest.raises(BudgetError):
        RunLedger().uncommit()
    with pytest.raises(BudgetError):
        RunLedger(forwarded=-1)
    with pytest.raises(BudgetError):
        RunLedger(forwarded=True)
