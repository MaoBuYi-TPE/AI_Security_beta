"""keeper 隔離超過上限的單一目錄（EVID-08；docs/DECISIONS.md §30.12）。

- 同一個目錄連續 3 次因為深度或條目數超過上限而加密失敗，才寫入隔離紀錄；2 次不會。
- 中間有其他種類的失敗就重新計數；成功就清除。其他種類的失敗、清除時的失敗不會隔離。
- 寫入隔離紀錄之後不再算退避中：下一輪恢復健康，之後每一輪都跳過這個目錄。
- 寫入隔離紀錄失敗時維持不健康，下一次失敗時再寫一次。
store 與 vault 是記憶體中的替身；實際的 DB 與檔案見 tests/integration/test_evidence_holds.py。
"""

import logging
from uuid import UUID, uuid4

import pytest

from secscan.runner.backoff import MAX_BACKOFF_SECONDS
from secscan.runner.evidence import DirectoryState
from secscan.runner.keeper import EvidenceKeeper, PassReport
from secscan.scans.domain.evidence import HOLD_AFTER_FAILURES, EvidenceHoldCode
from tests.unit.runner.keeper_fakes import (
    NOW,
    SETTINGS,
    Clock,
    FakeStore,
    FakeVault,
    Held,
    evidence_run,
    make_keeper,
)

DEEP = EvidenceHoldCode.TREE_TOO_DEEP
MANY = EvidenceHoldCode.TREE_TOO_MANY_ENTRIES
QUIET = SETTINGS.orphan_quiet_seconds


def _again(keeper: EvidenceKeeper, clock: Clock) -> PassReport:
    """退避結束之後的下一輪。"""
    clock.now += MAX_BACKOFF_SECONDS
    return keeper.run_pass()


def _orphan() -> DirectoryState:
    return DirectoryState(True, NOW.timestamp() - QUIET - 1, 0)


def test_three_consecutive_limit_failures_hold_the_run(caplog: pytest.LogCaptureFixture) -> None:
    clock = Clock()
    stuck = evidence_run()
    store = FakeStore(sealable_runs=[stuck])
    vault = FakeVault(over_limit={str(stuck.run_id): DEEP})
    keeper = make_keeper(store, vault, clock=clock)
    caplog.set_level(logging.ERROR)

    first = keeper.run_pass()
    second = _again(keeper, clock)
    assert store.holds == {}
    third = _again(keeper, clock)

    assert [report.failures for report in (first, second, third)] == [1, 1, 1]
    assert (third.held, third.deferred) == (1, 0)
    assert store.holds == {stuck.run_id: Held(stuck, DEEP, HOLD_AFTER_FAILURES)}
    assert keeper.healthy is False
    assert "EVIDENCE_TREE_TOO_DEEP" in caplog.text
    assert str(stuck.run_id) in caplog.text
    assert "/" not in caplog.text.replace("retry-evidence", "")


def test_the_next_pass_is_healthy_and_skips_the_held_run() -> None:
    clock = Clock()
    stuck, later = evidence_run(), evidence_run()
    store = FakeStore(sealable_runs=[stuck])
    vault = FakeVault(over_limit={str(stuck.run_id): MANY})
    keeper = make_keeper(store, vault, clock=clock)
    for _ in range(HOLD_AFTER_FAILURES):
        _again(keeper, clock)
    store.sealable_runs.append(later)

    report = keeper.run_pass()

    assert report.clean
    assert keeper.healthy is True
    assert vault.sealed == [str(later.run_id)]
    assert stuck.run_id not in store.recorded
    assert store.holds[stuck.run_id].code is MANY


def test_other_runs_are_sealed_while_one_is_failing() -> None:
    clock = Clock()
    stuck, fine = evidence_run(), evidence_run()
    store = FakeStore(sealable_runs=[stuck, fine])
    vault = FakeVault(over_limit={str(stuck.run_id): DEEP})
    keeper = make_keeper(store, vault, clock=clock)

    keeper.run_pass()

    assert vault.sealed == [str(fine.run_id)]


def test_two_limit_failures_then_success_clear_the_count() -> None:
    clock = Clock()
    run = evidence_run()
    store = FakeStore(sealable_runs=[run])
    vault = FakeVault(over_limit={str(run.run_id): DEEP})
    keeper = make_keeper(store, vault, clock=clock)
    keeper.run_pass()
    _again(keeper, clock)

    del vault.over_limit[str(run.run_id)]
    report = _again(keeper, clock)

    assert report.clean
    assert store.holds == {}
    assert run.run_id in store.recorded


def test_another_kind_of_failure_starts_the_count_again() -> None:
    clock = Clock()
    run = evidence_run()
    name = str(run.run_id)
    store = FakeStore(sealable_runs=[run])
    vault = FakeVault(over_limit={name: DEEP})
    keeper = make_keeper(store, vault, clock=clock)
    keeper.run_pass()
    _again(keeper, clock)
    vault.failing.add(name)
    _again(keeper, clock)
    vault.failing.clear()

    _again(keeper, clock)
    _again(keeper, clock)
    assert store.holds == {}
    _again(keeper, clock)

    assert store.holds[run.run_id].attempts == HOLD_AFTER_FAILURES


def test_other_failures_never_hold() -> None:
    clock = Clock()
    run = evidence_run()
    store = FakeStore(sealable_runs=[run])
    vault = FakeVault(failing={str(run.run_id)})
    keeper = make_keeper(store, vault, clock=clock)

    for _ in range(2 * HOLD_AFTER_FAILURES):
        assert _again(keeper, clock).failures == 1

    assert store.holds == {}
    assert keeper.healthy is False


def test_purge_failures_never_hold() -> None:
    """已加密的目錄在清除時超過上限，代表被改過或環境有問題：維持全域 fail closed。"""
    clock = Clock()
    run = evidence_run()
    store = FakeStore(purgeable_runs=[run])
    vault = FakeVault(over_limit={str(run.run_id): MANY})
    keeper = make_keeper(store, vault, clock=clock)

    for _ in range(2 * HOLD_AFTER_FAILURES):
        _again(keeper, clock)

    assert store.holds == {}
    assert keeper.healthy is False


def test_an_orphan_over_the_limit_is_held_and_skipped_afterwards() -> None:
    clock = Clock()
    name = str(uuid4())
    vault = FakeVault(states={name: _orphan()}, over_limit={name: DEEP})
    store = FakeStore()
    keeper = make_keeper(store, vault, clock=clock)

    for _ in range(HOLD_AFTER_FAILURES):
        _again(keeper, clock)
    assert store.holds == {UUID(name): Held(None, DEEP, HOLD_AFTER_FAILURES)}
    vault.inspected.clear()
    report = _again(keeper, clock)

    assert report.clean
    assert vault.inspected == []
    assert vault.sealed == []


def test_an_orphan_purge_over_the_limit_is_not_held() -> None:
    clock = Clock()
    name = str(uuid4())
    sealed = DirectoryState(False, NOW.timestamp() - QUIET - 1, 1)
    vault = FakeVault(states={name: sealed}, sealed_times={name: None})
    store = FakeStore()
    keeper = make_keeper(store, vault, clock=clock)
    original = vault.inspect

    def inspect_then_fail_purge(directory: str) -> DirectoryState | None:
        state = original(directory)
        vault.over_limit[directory] = DEEP
        return state

    vault.inspect = inspect_then_fail_purge  # type: ignore[method-assign,assignment]
    for _ in range(2 * HOLD_AFTER_FAILURES):
        vault.over_limit.clear()
        _again(keeper, clock)

    assert store.holds == {}
    assert keeper.healthy is False


def test_a_failed_hold_write_stays_unhealthy_and_is_retried(
    caplog: pytest.LogCaptureFixture,
) -> None:
    clock = Clock()
    stuck = evidence_run()
    store = FakeStore(sealable_runs=[stuck], broken="hold")
    vault = FakeVault(over_limit={str(stuck.run_id): DEEP})
    keeper = make_keeper(store, vault, clock=clock)
    caplog.set_level(logging.ERROR)

    for _ in range(HOLD_AFTER_FAILURES):
        report = _again(keeper, clock)
    assert (report.held, report.deferred) == (0, 1)
    assert "OperationalError" in caplog.text
    assert keeper.healthy is False

    store.broken = None
    report = _again(keeper, clock)
    assert report.held == 1
    assert store.holds[stuck.run_id].attempts == HOLD_AFTER_FAILURES + 1
    assert _again(keeper, clock).clean


def test_a_hold_committed_without_a_reply_does_not_keep_the_keeper_unhealthy() -> None:
    """寫入已 commit、回應卻遺失：DB 已隔離，這個目錄之後不會再被處理；下一輪依 DB 清掉退避，
    不會一直不健康到 runner 重啟（程式碼審查 M1、安全審查 L2；§30.12）。"""
    clock = Clock()
    stuck = evidence_run()
    store = FakeStore(sealable_runs=[stuck], hold_reply_lost=True)
    vault = FakeVault(over_limit={str(stuck.run_id): DEEP})
    keeper = make_keeper(store, vault, clock=clock)

    for _ in range(HOLD_AFTER_FAILURES):
        report = _again(keeper, clock)
    assert (report.held, report.deferred) == (0, 1)
    assert stuck.run_id in store.holds

    report = _again(keeper, clock)

    assert report.clean
    assert keeper.healthy is True


def test_the_three_limits_count_toward_the_same_streak() -> None:
    """深度、條目數與路徑總長度是三種可隔離的上限，共用連續的計數；記下的是最後一次的原因
    （使用者，2026-11-10；§30.12）。"""
    clock = Clock()
    run = evidence_run()
    name = str(run.run_id)
    store = FakeStore(sealable_runs=[run])
    vault = FakeVault()
    keeper = make_keeper(store, vault, clock=clock)

    for code in (DEEP, MANY, EvidenceHoldCode.TREE_PATHS_TOO_LONG):
        vault.over_limit[name] = code
        _again(keeper, clock)

    assert store.holds[run.run_id].code is EvidenceHoldCode.TREE_PATHS_TOO_LONG
    assert store.holds[run.run_id].attempts == HOLD_AFTER_FAILURES
