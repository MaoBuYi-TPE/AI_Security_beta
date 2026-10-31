"""run 的轉換與 scan 狀態的彙總（docs/DECISIONS.md §13.4、§19.8）；純函式，整張表都測。"""

import itertools

import pytest
from hypothesis import given
from hypothesis import strategies as st

from secscan.grants.domain.lifecycle import UnusableReason
from secscan.scans.domain.lifecycle import (
    ACTIVE_SCAN_STATUSES,
    ERROR_REQUIRED_RUN_STATUSES,
    GATE_ERROR_CODES,
    LEASED_RUN_STATUSES,
    TERMINAL_RUN_STATUSES,
    TERMINAL_SCAN_STATUSES,
    TRAFFIC_STOPPED_RUN_STATUSES,
    InvalidRunTransitionError,
    RunErrorCode,
    RunStatus,
    ScanStatus,
    aggregate,
    plan_run_transition,
)

R = RunStatus
S = ScanStatus

# 允許的轉換（docs/DECISIONS.md §13.4 的表）；表外的組合一律拒絕。
ALLOWED: dict[RunStatus, frozenset[RunStatus]] = {
    R.QUEUED: frozenset({R.PREPARING, R.CANCELLED}),
    R.PREPARING: frozenset({R.RUNNING, R.FAILED, R.CANCELLING, R.INTERRUPTED}),
    R.RUNNING: frozenset({R.COLLECTING, R.FAILED, R.TIMED_OUT, R.CANCELLING, R.INTERRUPTED}),
    R.COLLECTING: frozenset({R.COLLECTED, R.FAILED, R.CANCELLING, R.INTERRUPTED}),
    R.CANCELLING: frozenset({R.CANCELLED, R.INTERRUPTED}),
    R.COLLECTED: frozenset({R.NORMALIZING}),
    # ZAP 在 plan 的 maxDuration 自行停止：解析之後才知道（§19.2）。
    R.NORMALIZING: frozenset({R.SUCCEEDED, R.FAILED, R.TIMED_OUT, R.COLLECTED}),
    R.SUCCEEDED: frozenset(),
    R.FAILED: frozenset(),
    R.TIMED_OUT: frozenset(),
    R.CANCELLED: frozenset(),
    R.INTERRUPTED: frozenset(),
}


def _error_for(status: RunStatus) -> RunErrorCode | None:
    return RunErrorCode.ENGINE_FAILED if status in ERROR_REQUIRED_RUN_STATUSES else None


def test_the_table_covers_every_status() -> None:
    assert set(ALLOWED) == set(RunStatus)
    assert len(RunStatus) == 12


@pytest.mark.parametrize(("current", "to"), list(itertools.product(RunStatus, RunStatus)))
def test_every_transition_is_explicitly_allowed_or_rejected(
    current: RunStatus, to: RunStatus
) -> None:
    if to in ALLOWED[current]:
        plan_run_transition(current, to, error_code=_error_for(to))
        return
    with pytest.raises(InvalidRunTransitionError) as caught:
        plan_run_transition(current, to, error_code=_error_for(to))
    assert (caught.value.current, caught.value.to) == (current, to)


@pytest.mark.parametrize("to", sorted(ERROR_REQUIRED_RUN_STATUSES))
def test_failures_require_an_error_code(to: RunStatus) -> None:
    current = R.PREPARING if to is not R.TIMED_OUT else R.RUNNING
    with pytest.raises(ValueError, match="錯誤碼"):
        plan_run_transition(current, to, error_code=None)


@pytest.mark.parametrize(("current", "to"), [(R.QUEUED, R.PREPARING), (R.NORMALIZING, R.SUCCEEDED)])
def test_other_transitions_must_not_carry_an_error_code(current: RunStatus, to: RunStatus) -> None:
    with pytest.raises(ValueError, match="錯誤碼"):
        plan_run_transition(current, to, error_code=RunErrorCode.ENGINE_FAILED)


def test_status_groups() -> None:
    assert frozenset({R.SUCCEEDED, R.FAILED, R.TIMED_OUT, R.CANCELLED, R.INTERRUPTED}) == (
        TERMINAL_RUN_STATUSES
    )
    assert frozenset({R.PREPARING, R.RUNNING, R.COLLECTING, R.CANCELLING, R.NORMALIZING}) == (
        LEASED_RUN_STATUSES
    )
    assert TERMINAL_RUN_STATUSES | {R.COLLECTED, R.NORMALIZING} == TRAFFIC_STOPPED_RUN_STATUSES
    assert frozenset({R.FAILED, R.TIMED_OUT, R.INTERRUPTED}) == ERROR_REQUIRED_RUN_STATUSES
    assert frozenset(
        {S.COMPLETED, S.PARTIALLY_COMPLETED, S.FAILED, S.TIMED_OUT, S.CANCELLED, S.INTERRUPTED}
    ) == (TERMINAL_SCAN_STATUSES)
    assert frozenset(ScanStatus) - TERMINAL_SCAN_STATUSES == ACTIVE_SCAN_STATUSES
    assert len(ScanStatus) == 12


# --- 彙總 ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("runs", "cancel_requested", "expected"),
    [
        # 單一引擎走完一輪
        ([R.QUEUED], False, S.QUEUED),
        ([R.PREPARING], False, S.PREPARING),
        ([R.RUNNING], False, S.RUNNING),
        ([R.COLLECTING], False, S.COLLECTING),
        ([R.COLLECTED], False, S.COLLECTING),
        ([R.NORMALIZING], False, S.NORMALIZING),
        ([R.SUCCEEDED], False, S.COMPLETED),
        ([R.FAILED], False, S.FAILED),
        ([R.TIMED_OUT], False, S.TIMED_OUT),
        ([R.INTERRUPTED], False, S.INTERRUPTED),
        # 取消
        ([R.QUEUED], True, S.CANCELLING),
        ([R.RUNNING], True, S.CANCELLING),
        ([R.NORMALIZING], True, S.CANCELLING),
        ([R.CANCELLED], True, S.CANCELLED),
        ([R.SUCCEEDED], True, S.CANCELLED),
        ([R.CANCELLED, R.SUCCEEDED], True, S.CANCELLED),
        # runner 遺失（lease 過期）：無法證明已停止，不是 cancelled（審查發現）
        ([R.INTERRUPTED], True, S.INTERRUPTED),
        ([R.CANCELLED, R.INTERRUPTED], True, S.INTERRUPTED),
        # 沒有要求取消卻有 cancelling 的 run：DB 不允許 scan 是 cancelling（審查發現）
        ([R.CANCELLING], False, S.RUNNING),
        # 多個引擎依序執行
        ([R.PREPARING, R.QUEUED], False, S.PREPARING),
        ([R.RUNNING, R.QUEUED], False, S.RUNNING),
        ([R.COLLECTED, R.PREPARING], False, S.RUNNING),
        ([R.NORMALIZING, R.RUNNING], False, S.RUNNING),
        ([R.NORMALIZING, R.QUEUED], False, S.NORMALIZING),
        ([R.COLLECTED, R.QUEUED], False, S.COLLECTING),
        ([R.SUCCEEDED, R.QUEUED], False, S.RUNNING),
        ([R.FAILED, R.QUEUED], False, S.RUNNING),
        ([R.SUCCEEDED, R.PREPARING], False, S.RUNNING),
        # 全部終止
        ([R.SUCCEEDED, R.SUCCEEDED], False, S.COMPLETED),
        ([R.SUCCEEDED, R.FAILED], False, S.PARTIALLY_COMPLETED),
        ([R.SUCCEEDED, R.TIMED_OUT], False, S.TIMED_OUT),
        ([R.SUCCEEDED, R.INTERRUPTED], False, S.INTERRUPTED),
        ([R.TIMED_OUT, R.INTERRUPTED], False, S.INTERRUPTED),
        ([R.FAILED, R.FAILED], False, S.FAILED),
        ([R.FAILED, R.CANCELLED], False, S.FAILED),
    ],
)
def test_aggregate(runs: list[RunStatus], cancel_requested: bool, expected: ScanStatus) -> None:
    assert aggregate(runs, cancel_requested=cancel_requested) is expected


# preflight 是平台的健檢，不是結果引擎（§19.8）：checks 分開傳入。
@pytest.mark.parametrize(
    ("runs", "checks", "expected"),
    [
        ([R.SUCCEEDED], [R.SUCCEEDED], S.COMPLETED),
        ([R.SUCCEEDED], [R.FAILED], S.PARTIALLY_COMPLETED),
        ([R.SUCCEEDED], [R.TIMED_OUT], S.PARTIALLY_COMPLETED),
        # 原本是 partially_completed：preflight 成功不能讓沒有掃描結果的 scan 算部分完成
        ([R.FAILED], [R.SUCCEEDED], S.FAILED),
        ([R.CANCELLED], [R.SUCCEEDED], S.FAILED),
        ([R.FAILED], [R.FAILED], S.FAILED),
        ([R.TIMED_OUT], [R.SUCCEEDED], S.TIMED_OUT),
        ([R.SUCCEEDED, R.FAILED], [R.SUCCEEDED], S.PARTIALLY_COMPLETED),
        ([R.SUCCEEDED], [R.INTERRUPTED], S.INTERRUPTED),
        # 進行中：看所有的 run
        ([R.QUEUED], [R.RUNNING], S.RUNNING),
        ([R.QUEUED], [R.QUEUED], S.QUEUED),
        ([R.QUEUED], [R.SUCCEEDED], S.RUNNING),
        ([R.QUEUED], [R.NORMALIZING], S.NORMALIZING),
    ],
)
def test_preflight_is_not_a_result_engine(
    runs: list[RunStatus], checks: list[RunStatus], expected: ScanStatus
) -> None:
    assert aggregate(runs, cancel_requested=False, checks=checks) is expected


def test_a_cancelled_scan_with_checks_is_still_cancelled() -> None:
    assert aggregate([R.SUCCEEDED], cancel_requested=True, checks=[R.SUCCEEDED]) is S.CANCELLED
    assert aggregate([R.QUEUED], cancel_requested=True, checks=[R.RUNNING]) is S.CANCELLING


def test_aggregate_needs_a_scanning_run_besides_the_checks() -> None:
    with pytest.raises(ValueError, match="run"):
        aggregate([], cancel_requested=False, checks=[R.SUCCEEDED])


def test_aggregate_needs_at_least_one_run() -> None:
    with pytest.raises(ValueError, match="run"):
        aggregate([], cancel_requested=False)


RUN_LISTS = st.lists(st.sampled_from(list(RunStatus)), min_size=1, max_size=4)


@given(RUN_LISTS, st.booleans(), st.data())
def test_aggregate_ignores_the_order_of_runs(
    runs: list[RunStatus], cancel_requested: bool, data: st.DataObject
) -> None:
    shuffled = data.draw(st.permutations(runs))

    assert aggregate(shuffled, cancel_requested=cancel_requested) is aggregate(
        runs, cancel_requested=cancel_requested
    )


CHECK_LISTS = st.lists(st.sampled_from(list(RunStatus)), max_size=1)


@given(RUN_LISTS, CHECK_LISTS, st.booleans(), st.data())
def test_aggregate_with_checks_ignores_the_order_of_runs(
    runs: list[RunStatus], checks: list[RunStatus], cancel_requested: bool, data: st.DataObject
) -> None:
    shuffled = data.draw(st.permutations(runs))

    assert aggregate(shuffled, cancel_requested=cancel_requested, checks=checks) is aggregate(
        runs, cancel_requested=cancel_requested, checks=checks
    )


@given(RUN_LISTS, CHECK_LISTS, st.booleans())
def test_with_checks_the_scan_is_terminal_exactly_when_every_run_is(
    runs: list[RunStatus], checks: list[RunStatus], cancel_requested: bool
) -> None:
    status = aggregate(runs, cancel_requested=cancel_requested, checks=checks)

    all_terminal = all(run in TERMINAL_RUN_STATUSES for run in [*runs, *checks])
    assert (status in TERMINAL_SCAN_STATUSES) is all_terminal
    if status in {S.COMPLETED, S.PARTIALLY_COMPLETED}:
        assert R.SUCCEEDED in runs
    if status is S.COMPLETED:
        assert set(checks) <= {R.SUCCEEDED}


@given(RUN_LISTS, st.booleans())
def test_scan_is_terminal_exactly_when_every_run_is(
    runs: list[RunStatus], cancel_requested: bool
) -> None:
    status = aggregate(runs, cancel_requested=cancel_requested)

    all_terminal = all(run in TERMINAL_RUN_STATUSES for run in runs)
    assert (status in TERMINAL_SCAN_STATUSES) is all_terminal


@given(RUN_LISTS)
def test_a_cancel_request_with_unfinished_runs_is_always_cancelling(runs: list[RunStatus]) -> None:
    status = aggregate(runs, cancel_requested=True)

    if not all(run in TERMINAL_RUN_STATUSES for run in runs):
        assert status is S.CANCELLING
    elif R.INTERRUPTED in runs:
        assert status is S.INTERRUPTED
    else:
        assert status is S.CANCELLED


@given(RUN_LISTS, st.booleans())
def test_cancelling_and_cancelled_need_a_cancel_request(
    runs: list[RunStatus], cancel_requested: bool
) -> None:
    """和 DB 的 ck_scans_cancel_matches_status 一致：沒有要求取消，就不會是 cancelling
    或 cancelled。"""
    status = aggregate(runs, cancel_requested=cancel_requested)

    if status in {S.CANCELLING, S.CANCELLED}:
        assert cancel_requested


@given(RUN_LISTS, st.booleans())
def test_an_interrupted_run_is_never_reported_as_a_confirmed_stop(
    runs: list[RunStatus], cancel_requested: bool
) -> None:
    """interrupted 無法證明工作已正常停止：全部終止時優先於 cancelled 與其他結果。"""
    status = aggregate(runs, cancel_requested=cancel_requested)

    if R.INTERRUPTED in runs and all(run in TERMINAL_RUN_STATUSES for run in runs):
        assert status is S.INTERRUPTED


# --- runner 啟動前的 gate -----------------------------------------------------------------


def test_every_gate_reason_has_a_run_error_code() -> None:
    assert set(GATE_ERROR_CODES) == set(UnusableReason)
    assert GATE_ERROR_CODES[UnusableReason.REVOKED] is RunErrorCode.SCOPE_REVOKED
    assert GATE_ERROR_CODES[UnusableReason.EXPIRED] is RunErrorCode.SCOPE_EXPIRED
    assert GATE_ERROR_CODES[UnusableReason.NOT_APPROVED] is RunErrorCode.SCOPE_NOT_APPROVED
    assert GATE_ERROR_CODES[UnusableReason.NOT_YET_VALID] is RunErrorCode.SCOPE_NOT_YET_VALID
    assert GATE_ERROR_CODES[UnusableReason.TARGET_DISABLED] is RunErrorCode.TARGET_DISABLED
    assert GATE_ERROR_CODES[UnusableReason.WRONG_TARGET] is RunErrorCode.SCOPE_MISMATCH
    assert GATE_ERROR_CODES[UnusableReason.ORIGIN_NOT_GRANTED] is RunErrorCode.SCOPE_MISMATCH


def test_the_parser_outcomes_have_error_codes() -> None:
    """ZAP 的判定（§19.2、§19.11）：DB 只檢查格式，不必 migration。"""
    assert {
        RunErrorCode.OUTPUT_INVALID,
        RunErrorCode.ENGINE_REPORTED_ERRORS,
        RunErrorCode.NO_TARGET_TRAFFIC,
        RunErrorCode.ENGINE_TIMEOUT,
    } <= set(RunErrorCode)


def test_run_error_codes_are_upper_snake_case() -> None:
    """DB 只檢查格式（docs/DECISIONS.md §13.4）：清單中的錯誤碼都要符合那個格式。"""
    for code in RunErrorCode:
        assert code.value == code.name
        assert code.value.replace("_", "").isalnum()
        assert code.value.isupper()
