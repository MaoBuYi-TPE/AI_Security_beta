"""scan 的用量、preflight 的狀態與 coverage 是否有量測依據（docs/DECISIONS.md §16.4 至 §16.6）。

都由各 run 的資料算出（不另外存）：
- budget_usage：guard 記下的轉送與拒絕數、流量的秒數加總。開始過的容器 run 轉送數不明時，總數
  也是不明（None），不以 0 冒充。in-process 與沒開始的 run 沒有流量。
- preflight_status：preflight run 的結果；還沒結束是 None；結束了卻沒有結果是 not_executed。
- coverage_measured：有規格、至少一個容器 run，而且每個容器 run 的 telemetry 都已對應到 operation。
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
    traffic_seconds: int


def budget_usage(runs: Iterable[ScannerRun]) -> BudgetUsage:
    sent: int | None = 0
    denied: int | None = 0
    seconds = 0
    for run in runs:
        if not run.container or run.started_at is None:
            continue
        seconds += run.traffic_seconds or 0
        sent = None if sent is None or run.requests_sent is None else sent + run.requests_sent
        denied = (
            None if denied is None or run.requests_denied is None else denied + run.requests_denied
        )
    return BudgetUsage(requests_sent=sent, requests_denied=denied, traffic_seconds=seconds)


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
    containers = [run for run in runs if run.container]
    return has_spec and bool(containers) and all(run.coverage_recorded for run in containers)
