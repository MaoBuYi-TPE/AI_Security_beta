"""scan 的用量、preflight 的狀態與 coverage 是否有量測依據（docs/DECISIONS.md §16.4 至 §16.6）。

- budget_usage：各 run 由 guard 記下的轉送與拒絕數、流量的秒數加總；有任何開始過的容器 run 轉送數
  不明，轉送數就是 None（不以 0 冒充）。
- preflight：preflight run 的結果；還沒結束是 None（pending）；結束了卻沒有結果是 not_executed。
- coverage_measured：有規格，至少一個容器 run，而且每個容器 run 的 telemetry 都已對應到 operation。
- authentication_lost：解析過的 run 的 guard 流量判定憑證失效（§20.4）；形狀不符不判定。
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

from secscan.core.json_types import JsonValue
from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.domain.model import Coverage, ScannerRun
from secscan.scans.domain.observation import RunResult
from secscan.scans.domain.preflight import PreflightResult
from secscan.scans.domain.usage import (
    BudgetUsage,
    authentication_health_unknown,
    authentication_lost,
    budget_usage,
    coverage_measured,
    preflight_status,
)

SCAN = UUID(int=1)
NOW = datetime(2026, 10, 29, tzinfo=UTC)


def _run(sequence: int = 1, engine: Engine = Engine.FAKE, **fields: Any) -> ScannerRun:
    values: dict[str, Any] = {
        "id": uuid4(),
        "scan_id": SCAN,
        "engine": engine,
        "sequence": sequence,
        "status": RunStatus.SUCCEEDED,
        "error_code": None,
        "started_at": NOW,
        "finished_at": NOW,
        "created_at": NOW,
        "container": True,
        "requests_sent": 0,
        "requests_denied": 0,
        "traffic_seconds": 0,
        "coverage_recorded": True,
    }
    values.update(fields)
    return ScannerRun(**values)


def test_usage_is_summed_over_the_runs() -> None:
    runs = (
        _run(1, Engine.PREFLIGHT, requests_sent=2, requests_denied=0, traffic_seconds=3),
        _run(2, requests_sent=40, requests_denied=5, traffic_seconds=60),
    )

    assert budget_usage(runs) == BudgetUsage(
        requests_sent=42, requests_denied=5, traffic_seconds=63
    )


def test_unknown_counts_make_the_total_unknown() -> None:
    runs = (_run(1, requests_sent=None, requests_denied=None, traffic_seconds=9), _run(2))

    assert budget_usage(runs) == BudgetUsage(
        requests_sent=None, requests_denied=None, traffic_seconds=9
    )


def test_unknown_traffic_time_makes_the_total_unknown() -> None:
    """和剩下的預算的口徑一致：不明的不以 0 冒充（審查發現）。"""
    runs = (_run(1, traffic_seconds=None), _run(2, traffic_seconds=5))

    assert budget_usage(runs).traffic_seconds is None


def test_runs_that_never_started_used_nothing() -> None:
    queued = _run(
        status=RunStatus.QUEUED,
        started_at=None,
        finished_at=None,
        container=False,
        requests_sent=None,
        requests_denied=None,
        traffic_seconds=None,
    )

    assert budget_usage((queued,)) == BudgetUsage(0, 0, 0)


def test_in_process_runs_send_nothing() -> None:
    fake = _run(container=False, requests_sent=None, requests_denied=None, traffic_seconds=None)

    assert budget_usage((fake,)) == BudgetUsage(0, 0, 0)


# --- preflight -------------------------------------------------------------------------------


def test_the_preflight_result_is_reported() -> None:
    runs = (_run(1, Engine.PREFLIGHT, preflight_result=PreflightResult.PASSED), _run(2))

    assert preflight_status(runs) is PreflightResult.PASSED


def test_an_unfinished_preflight_is_pending() -> None:
    runs = (_run(1, Engine.PREFLIGHT, status=RunStatus.RUNNING, finished_at=None), _run(2))

    assert preflight_status(runs) is None


@pytest.mark.parametrize(
    ("status", "error_code"),
    [(RunStatus.FAILED, RunErrorCode.ENGINE_FAILED), (RunStatus.CANCELLED, None)],
)
def test_a_preflight_that_ended_without_a_result_was_not_executed(
    status: RunStatus, error_code: RunErrorCode | None
) -> None:
    preflight = _run(1, Engine.PREFLIGHT, status=status, error_code=error_code)

    assert preflight_status((preflight,)) is PreflightResult.NOT_EXECUTED


def test_anonymous_scans_have_no_preflight() -> None:
    assert preflight_status((_run(),)) is None


# --- coverage --------------------------------------------------------------------------------


def test_coverage_is_measured_when_every_container_run_was_recorded() -> None:
    runs = (_run(1, Engine.PREFLIGHT), _run(2))

    assert coverage_measured(runs, has_spec=True)
    assert not coverage_measured(runs, has_spec=False)


def test_an_unrecorded_container_run_means_not_measured() -> None:
    runs = (_run(1, Engine.PREFLIGHT), _run(2, coverage_recorded=False))

    assert not coverage_measured(runs, has_spec=True)


def test_coverage_is_not_measured_while_runs_are_pending() -> None:
    """之後的引擎還沒跑完，涵蓋的數字還會變（審查建議）。"""
    runs = (
        _run(1, Engine.PREFLIGHT),
        _run(2, status=RunStatus.QUEUED, started_at=None, finished_at=None, container=False),
    )

    assert not coverage_measured(runs, has_spec=True)


def test_without_any_container_run_nothing_was_measured() -> None:
    assert not coverage_measured((_run(container=False, coverage_recorded=False),), has_spec=True)


def test_only_preflight_runs_have_a_preflight_result() -> None:
    with pytest.raises(ValueError, match="preflight"):
        _run(preflight_result=PreflightResult.PASSED)


@pytest.mark.parametrize(("observed", "authenticated"), [(2, 3), (11, 0)])
def test_coverage_counts_stay_ordered(observed: int, authenticated: int) -> None:
    with pytest.raises(ValueError, match="authenticated"):
        Coverage(
            eligible_operations=10,
            ineligible_operations=0,
            observed_operations=observed,
            authenticated_operations=authenticated,
        )


def _traffic(guard_traffic: JsonValue) -> ScannerRun:
    result = RunResult("p/1", None, 0, 0, {"guard_traffic": guard_traffic})
    return _run(engine=Engine.ZAP, result=result)


def test_a_lost_credential_is_found_in_any_run() -> None:
    lost = _traffic({"auth": {"lost": True}})

    assert authentication_lost([_run(), _traffic({"auth": {"lost": False}}), lost])


@pytest.mark.parametrize(
    "guard_traffic",
    [None, [], {"auth": None}, {"auth": []}, {"auth": {}}, {"auth": {"lost": "true"}}],
)
def test_details_without_a_lost_flag_are_not_a_loss(guard_traffic: JsonValue) -> None:
    assert not authentication_lost([_traffic(guard_traffic)])


def test_runs_without_results_are_not_a_loss() -> None:
    assert not authentication_lost([_run()])


@pytest.mark.parametrize(
    "guard_traffic", [None, [], {"auth": None}, {"auth": []}, {"forwarded": 3}]
)
def test_results_without_auth_counts_are_unknown(guard_traffic: JsonValue) -> None:
    assert authentication_health_unknown([_run(), _traffic(guard_traffic)])


def test_results_with_auth_counts_are_known() -> None:
    assert not authentication_health_unknown([_run(), _traffic({"auth": {"lost": False}})])
