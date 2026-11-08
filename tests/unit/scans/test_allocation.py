"""引擎子預算（T31；docs/DECISIONS.md §29）：建立時的檢查與每個 run 的配額。

BUDGET-02（配額取較小值）、BUDGET-04（建立時的檢查）、BUDGET-09（最小時間窗和 scanners 相同）。
"""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from secscan.grants.domain.scope import Budget
from secscan.scanners.domain.nuclei import plan as nuclei_plan
from secscan.scanners.domain.zap import plan as zap_plan
from secscan.scans.domain.allocation import (
    NUCLEI_MIN_SECONDS,
    ZAP_MIN_REQUEST_SECONDS,
    ZAP_MIN_SECONDS,
    EngineBudget,
    EngineBudgetRequest,
    allowance,
    check_allocation_shape,
    resolve_engine_budgets,
)
from secscan.scans.domain.catalog import Engine, InvalidScanRequestError

ZAP, NUCLEI, FAKE = Engine.ZAP, Engine.NUCLEI, Engine.FAKE
SCAN_BUDGET = Budget(requests_per_second=2, max_requests=1_200, max_duration_seconds=600)
SPLIT = (
    EngineBudgetRequest(ZAP, max_requests=760, max_duration_seconds=380),
    EngineBudgetRequest(NUCLEI, max_requests=440, max_duration_seconds=220),
)


def _split(
    zap: tuple[int, int] = (760, 380), nuclei: tuple[int, int] = (440, 220)
) -> tuple[EngineBudgetRequest, ...]:
    return (
        EngineBudgetRequest(ZAP, max_requests=zap[0], max_duration_seconds=zap[1]),
        EngineBudgetRequest(NUCLEI, max_requests=nuclei[0], max_duration_seconds=nuclei[1]),
    )


# --- 最小時間窗和 scanners 的 plan 相同（BUDGET-09）------------------------------------------


def test_the_zap_minimum_window_matches_its_plan() -> None:
    """scans 依分層不能 import scanners：各寫一份，在這裡核對。"""
    assert ZAP_MIN_SECONDS == zap_plan.RESERVED_SECONDS + zap_plan.MIN_PLAN_SECONDS
    assert ZAP_MIN_REQUEST_SECONDS == ZAP_MIN_SECONDS


def test_the_nuclei_minimum_window_matches_its_plan() -> None:
    assert NUCLEI_MIN_SECONDS == nuclei_plan.MIN_PLAN_SECONDS


def test_the_zap_minimum_is_the_smallest_window_its_plan_accepts() -> None:
    """邊界：最小值剛好能產生 plan，少 1 秒或少 1 個請求就不行。"""
    rps = SCAN_BUDGET.requests_per_second

    def window(requests: int, seconds: int) -> int:
        return zap_plan.plan_seconds(
            zap_plan.ZapBudget(
                requests_per_second=rps,
                max_requests=requests,
                remaining_seconds=seconds,
                valid_for_seconds=86_400,
            )
        )

    assert window(ZAP_MIN_REQUEST_SECONDS * rps, ZAP_MIN_SECONDS) == zap_plan.MIN_PLAN_SECONDS
    with pytest.raises(zap_plan.PlanWindowTooSmallError):
        window(ZAP_MIN_REQUEST_SECONDS * rps, ZAP_MIN_SECONDS - 1)
    with pytest.raises(zap_plan.PlanWindowTooSmallError):
        window(ZAP_MIN_REQUEST_SECONDS * rps - 1, ZAP_MIN_SECONDS)


# --- 形狀：只用在多引擎的 scan，每個引擎恰好一次（BUDGET-04）--------------------------------


def test_no_allocation_is_always_accepted() -> None:
    check_allocation_shape((FAKE,), None)
    check_allocation_shape((ZAP, NUCLEI), None)


def test_every_engine_listed_once_is_accepted_in_any_order() -> None:
    check_allocation_shape((ZAP, NUCLEI), SPLIT)
    check_allocation_shape((NUCLEI, ZAP), tuple(reversed(SPLIT)))


@pytest.mark.parametrize(
    ("engines", "requested", "problem"),
    [
        ((ZAP,), SPLIT[:1], "兩個以上"),
        ((FAKE,), (EngineBudgetRequest(FAKE, 1, 1),), "兩個以上"),
        ((ZAP, NUCLEI), SPLIT[:1], "每個引擎"),
        ((ZAP, NUCLEI), (SPLIT[0], SPLIT[0]), "重複"),
        ((ZAP, NUCLEI), (*SPLIT, EngineBudgetRequest(FAKE, 1, 1)), "重複|每個引擎"),
        ((ZAP, NUCLEI), (SPLIT[0], EngineBudgetRequest(FAKE, 440, 220)), "每個引擎"),
        ((ZAP, NUCLEI), (), "每個引擎"),
    ],
)
def test_a_partial_or_mismatched_allocation_is_rejected(
    engines: tuple[Engine, ...], requested: tuple[EngineBudgetRequest, ...], problem: str
) -> None:
    with pytest.raises(InvalidScanRequestError, match=problem) as caught:
        check_allocation_shape(engines, requested)

    assert "engine_budgets" in str(caught.value)


# --- 數值：正整數、合計不超過總額、不低於最小時間窗（BUDGET-04）----------------------------


def test_a_valid_allocation_resolves_to_frozen_caps_per_engine() -> None:
    caps = resolve_engine_budgets(SPLIT, budget=SCAN_BUDGET)

    assert dict(caps) == {
        ZAP: EngineBudget(max_requests=760, max_duration_seconds=380),
        NUCLEI: EngineBudget(max_requests=440, max_duration_seconds=220),
    }
    with pytest.raises(TypeError):
        caps[ZAP] = EngineBudget(1, 1)  # type: ignore[index]


def test_no_allocation_resolves_to_no_caps() -> None:
    assert dict(resolve_engine_budgets(None, budget=SCAN_BUDGET)) == {}


def test_the_shares_may_add_up_to_less_than_the_total() -> None:
    """總額是上限，不是必須用完的配額。"""
    caps = resolve_engine_budgets(_split((500, 200), (100, 60)), budget=SCAN_BUDGET)

    assert caps[NUCLEI] == EngineBudget(max_requests=100, max_duration_seconds=60)


@pytest.mark.parametrize(
    ("requested", "problem"),
    [
        (_split((761, 380)), "max_requests 的合計"),
        (_split((760, 381)), "max_duration_seconds 的合計"),
        (_split((1_201, 380), (1, 220)), "max_requests"),
        (_split((760, 380), (440, 601)), "max_duration_seconds"),
        (_split((760, 380), (0, 220)), "max_requests"),
        (_split((760, 380), (-1, 220)), "max_requests"),
        (_split((760, 380), (440, 0)), "max_duration_seconds"),
    ],
)
def test_shares_must_be_positive_within_the_scan_and_add_up_to_at_most_the_total(
    requested: tuple[EngineBudgetRequest, ...], problem: str
) -> None:
    with pytest.raises(InvalidScanRequestError, match=problem):
        resolve_engine_budgets(requested, budget=SCAN_BUDGET)


@pytest.mark.parametrize(
    ("requested", "engine"),
    [
        (_split((760, ZAP_MIN_SECONDS - 1)), "zap"),
        (_split((ZAP_MIN_REQUEST_SECONDS * 2 - 1, 380)), "zap"),
        (_split((760, 380), (440, NUCLEI_MIN_SECONDS - 1)), "nuclei"),
    ],
)
def test_shares_below_the_engine_minimum_window_are_rejected(
    requested: tuple[EngineBudgetRequest, ...], engine: str
) -> None:
    """低於最小時間窗的份額註定 BUDGET_EXHAUSTED：建立時就拒絕，不白白排隊。"""
    with pytest.raises(InvalidScanRequestError, match=engine):
        resolve_engine_budgets(requested, budget=SCAN_BUDGET)


def test_the_minimum_windows_themselves_are_accepted() -> None:
    requested = _split(
        (ZAP_MIN_REQUEST_SECONDS * SCAN_BUDGET.requests_per_second, ZAP_MIN_SECONDS),
        (1, NUCLEI_MIN_SECONDS),
    )

    caps = resolve_engine_budgets(requested, budget=SCAN_BUDGET)

    assert caps[ZAP].max_duration_seconds == ZAP_MIN_SECONDS
    assert caps[NUCLEI].max_requests == 1


def test_shares_must_be_integers_not_booleans() -> None:
    requested = (SPLIT[0], EngineBudgetRequest(NUCLEI, max_requests=True, max_duration_seconds=220))

    with pytest.raises(InvalidScanRequestError, match="max_requests"):
        resolve_engine_budgets(requested, budget=SCAN_BUDGET)


def test_messages_do_not_echo_the_requested_values() -> None:
    requested = _split((760, 380), (440, 987_654))

    with pytest.raises(InvalidScanRequestError) as caught:
        resolve_engine_budgets(requested, budget=SCAN_BUDGET)

    assert "987654" not in str(caught.value)


@pytest.mark.parametrize(("requests", "seconds"), [(0, 1), (1, 0), (True, 1)])
def test_a_cap_is_positive_integers(requests: int, seconds: int) -> None:
    with pytest.raises(ValueError, match="正整數"):
        EngineBudget(max_requests=requests, max_duration_seconds=seconds)


# --- 配額：剩下的預算與上限取較小值（BUDGET-02）-------------------------------------------


def test_without_a_cap_the_run_gets_all_that_remains() -> None:
    assert allowance(1_200, 600, None) == (1_200, 600)


def test_a_cap_limits_requests_and_seconds_separately() -> None:
    cap = EngineBudget(max_requests=440, max_duration_seconds=220)

    assert allowance(1_200, 600, cap) == (440, 220)
    assert allowance(300, 600, cap) == (300, 220)
    assert allowance(1_200, 100, cap) == (440, 100)
    assert allowance(0, 0, cap) == (0, 0)


@given(
    requests=st.integers(min_value=0, max_value=10_000),
    seconds=st.integers(min_value=0, max_value=10_000),
    cap_requests=st.integers(min_value=1, max_value=10_000),
    cap_seconds=st.integers(min_value=1, max_value=10_000),
)
def test_the_allowance_never_exceeds_what_remains_or_the_cap(
    requests: int, seconds: int, cap_requests: int, cap_seconds: int
) -> None:
    """只會讓配額變小：不會超過剩下的總額，也不會超過這個引擎的上限。"""
    allotted_requests, allotted_seconds = allowance(
        requests, seconds, EngineBudget(cap_requests, cap_seconds)
    )

    assert 0 <= allotted_requests <= min(requests, cap_requests)
    assert 0 <= allotted_seconds <= min(seconds, cap_seconds)
    assert allotted_requests == min(requests, cap_requests)
    assert allotted_seconds == min(seconds, cap_seconds)
