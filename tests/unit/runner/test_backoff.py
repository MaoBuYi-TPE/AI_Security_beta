"""keeper 每個目錄的重試狀態（runner/backoff.py；EVID-08；docs/DECISIONS.md §30.12）。

退避的間隔、連續的上限失敗（上限失敗加一、其他種類的失敗歸零、成功就清除），以及第幾次要隔離。
"""

from uuid import uuid4

import pytest

from secscan.runner.backoff import MAX_BACKOFF_SECONDS, Backoff
from secscan.runner.evidence import EvidenceError, EvidenceLimitError
from secscan.scans.domain.evidence import HOLD_AFTER_FAILURES, EvidenceHoldCode

INTERVAL = 10.0
DEEP = EvidenceLimitError(EvidenceHoldCode.TREE_TOO_DEEP, "目錄的深度超過上限")
MANY = EvidenceLimitError(EvidenceHoldCode.TREE_TOO_MANY_ENTRIES, "目錄的條目超過上限")
OTHER = EvidenceError("檔案系統錯誤（ENOSPC）")


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def backoff(clock: Clock) -> Backoff:
    return Backoff(INTERVAL, clock)


def test_the_delay_doubles_from_twenty_seconds_and_is_capped(
    backoff: Backoff, clock: Clock
) -> None:
    key = uuid4()

    delays = [backoff.failed(key, OTHER).retry_at - clock.now for _ in range(8)]

    assert delays[:3] == [20.0, 40.0, 80.0]
    assert delays[-1] == MAX_BACKOFF_SECONDS


def test_a_long_outage_does_not_overflow(backoff: Backoff, clock: Clock) -> None:
    key = uuid4()

    for _ in range(2_000):
        attempt = backoff.failed(key, OTHER)

    assert attempt.retry_at - clock.now == MAX_BACKOFF_SECONDS


def test_consecutive_limit_failures_are_due_for_a_hold_on_the_third(backoff: Backoff) -> None:
    key = uuid4()

    attempts = [backoff.failed(key, error) for error in (DEEP, MANY, DEEP)]

    assert [attempt.streak for attempt in attempts] == [1, 2, 3]
    assert [attempt.hold_code() for attempt in attempts] == [
        None,
        None,
        EvidenceHoldCode.TREE_TOO_DEEP,
    ]
    assert HOLD_AFTER_FAILURES == 3


def test_another_kind_of_failure_starts_the_count_again(backoff: Backoff) -> None:
    key = uuid4()

    backoff.failed(key, DEEP)
    backoff.failed(key, DEEP)
    reset = backoff.failed(key, OTHER)
    later = [backoff.failed(key, MANY) for _ in range(HOLD_AFTER_FAILURES)]

    assert (reset.streak, reset.hold_code()) == (0, None)
    assert [attempt.streak for attempt in later] == [1, 2, 3]
    assert later[-1].hold_code() is EvidenceHoldCode.TREE_TOO_MANY_ENTRIES


def test_success_clears_everything(backoff: Backoff) -> None:
    key = uuid4()
    backoff.failed(key, DEEP)
    backoff.failed(key, DEEP)

    backoff.clear(key)

    assert len(backoff) == 0
    assert backoff.failed(key, DEEP).streak == 1


def test_waiting_lists_only_keys_whose_retry_time_has_not_come(
    backoff: Backoff, clock: Clock
) -> None:
    run, orphan = uuid4(), str(uuid4())
    backoff.failed(run, OTHER)
    backoff.failed(orphan, OTHER)

    assert backoff.waiting() == {run, orphan}
    assert backoff.waiting_runs() == {run}
    clock.now += 2 * INTERVAL
    assert backoff.waiting() == frozenset()
    assert len(backoff) == 2


def test_orphans_no_longer_present_are_forgotten(backoff: Backoff) -> None:
    run, kept, removed = uuid4(), str(uuid4()), str(uuid4())
    for key in (run, kept, removed):
        backoff.failed(key, OTHER)

    backoff.forget_missing_orphans({kept})

    assert backoff.keys() == {run, kept}
