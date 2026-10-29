"""scan 的用量、preflight 的狀態與 coverage 是否有量測依據（docs/DECISIONS.md §16.4 至 §16.6）。

都由各 run 的資料算出（不另外存）：
- budget_usage：guard 記下的轉送與拒絕數、流量的秒數加總。開始過的容器 run 有任何一項不明時，那一項
  的總數也是不明（None），不以 0 冒充。in-process 與沒開始的 run 沒有流量。
- preflight_status：preflight run 的結果；還沒結束是 None；結束了卻沒有結果是 not_executed。
- coverage_measured：有規格、所有 run 都結束、至少一個容器 run，而且每個容器 run 的 telemetry 都已
  對應到 operation。
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.lifecycle import TERMINAL_RUN_STATUSES
from secscan.scans.domain.model import ScannerRun
from secscan.scans.domain.preflight import PreflightResult


@dataclass(frozen=True, slots=True)
class BudgetUsage:
    requests_sent: int | None
    requests_denied: int | None
    traffic_seconds: int | None


def budget_usage(runs: Iterable[ScannerRun]) -> BudgetUsage:
    sent: int | None = 0
    denied: int | None = 0
    seconds: int | None = 0
    for run in runs:
        if not run.container or run.started_at is None:
            continue
        sent = _add(sent, run.requests_sent)
        denied = _add(denied, run.requests_denied)
        seconds = _add(seconds, run.traffic_seconds)
    return BudgetUsage(requests_sent=sent, requests_denied=denied, traffic_seconds=seconds)


def _add(total: int | None, value: int | None) -> int | None:
    """任何一個不明，總數就不明。"""
    return None if total is None or value is None else total + value


def preflight_status(runs: Sequence[ScannerRun]) -> PreflightResult | None:
    preflight = next((run for run in runs if run.engine is Engine.PREFLIGHT), None)
    if preflight is None:
        return None
    if preflight.preflight_result is not None:
        return preflight.preflight_result
    if preflight.status in TERMINAL_RUN_STATUSES:
        return PreflightResult.NOT_EXECUTED
    return None


def coverage_measured(runs: Iterable[ScannerRun], *, has_spec: bool) -> bool:
    """所有 run 都結束（之後的引擎還會改變數字，審查建議），而且每個容器 run 都已對應。"""
    runs = tuple(runs)
    containers = [run for run in runs if run.container]
    return (
        has_spec
        and bool(containers)
        and all(run.status in TERMINAL_RUN_STATUSES for run in runs)
        and all(run.coverage_recorded for run in containers)
    )
