"""一個 scan 的資源、覆蓋與去重（純函式；SECURITY_AND_TESTING.md §6、§7.2、§7.3）。

- 資源以 guard 的計數為準（不採用工具自報的數字）；任何一個 run 不明，總數就不明。
- 是否被上限截斷分開看請求數（guard 回報已轉送到上限）與時間（工具或 runner 的時間上限）。
- 去重：列表壓縮比例只是列表變短的比例，不是 precision 的改善；合併的對錯以人工標記為準。
"""

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from benchmarks.ground_truth import PairLabels
from benchmarks.metrics import Metric, NotAvailable, Ratio, ratio
from benchmarks.models import LabeledScan, RunRecord, ScanRecord, Signature

TIME_LIMIT_ERRORS = frozenset({"ENGINE_TIMEOUT", "TIME_LIMIT_EXCEEDED"})


class InconsistentScanError(ValueError):
    """收集的資料彼此矛盾（例如 finding 比觀察多）。"""


@dataclass(frozen=True, slots=True)
class RunResources:
    engine: str
    status: str
    error_code: str | None
    cap: tuple[int, int] | None
    requests_allotted: int | None
    seconds_allotted: int | None
    requests_sent: int | None
    requests_denied: int | None
    traffic_seconds: int | None
    requests_bound: bool | None
    time_bound: bool


@dataclass(frozen=True, slots=True)
class Resources:
    requests_sent: int | None
    requests_denied: int | None
    traffic_seconds: int | None
    wall_seconds: float | None
    runs: tuple[RunResources, ...]


@dataclass(frozen=True, slots=True)
class DedupScore:
    findings: int
    observations: int
    compression: Metric
    merged_findings: int
    merge_precision: Metric
    merge_recall: Metric
    false_merges: tuple[Signature, ...]
    missed_merges: int


def resources(scan: ScanRecord) -> Resources:
    started = [run for run in scan.runs if run.requests_allotted is not None]
    return Resources(
        requests_sent=_total(run.requests_sent for run in started),
        requests_denied=_total(run.requests_denied for run in started),
        traffic_seconds=_total(run.traffic_seconds for run in started),
        wall_seconds=_wall_seconds(scan),
        runs=tuple(_run_resources(run) for run in scan.runs),
    )


def _run_resources(run: RunRecord) -> RunResources:
    requests_bound: bool | None = None
    if run.guard_exhausted is True:
        requests_bound = True
    elif run.requests_sent is not None and run.requests_allotted is not None:
        requests_bound = run.requests_sent >= run.requests_allotted
    return RunResources(
        engine=run.engine,
        status=run.status,
        error_code=run.error_code,
        cap=(run.cap.max_requests, run.cap.max_duration_seconds) if run.cap is not None else None,
        requests_allotted=run.requests_allotted,
        seconds_allotted=run.seconds_allotted,
        requests_sent=run.requests_sent,
        requests_denied=run.requests_denied,
        traffic_seconds=run.traffic_seconds,
        requests_bound=requests_bound,
        time_bound=run.time_limit_reached is True or run.error_code in TIME_LIMIT_ERRORS,
    )


def _total(values: Iterable[int | None]) -> int | None:
    """任何一個不明，總數就不明（和平台的 budget_usage 相同）。"""
    total = 0
    for value in values:
        if value is None:
            return None
        total += value
    return total


def _wall_seconds(scan: ScanRecord) -> float | None:
    if scan.finished_at is None:
        return None
    started = datetime.fromisoformat(scan.created_at)
    return (datetime.fromisoformat(scan.finished_at) - started).total_seconds()


def coverage(scan: ScanRecord) -> Metric:
    if (
        not scan.coverage_measured
        or scan.eligible_operations is None
        or scan.observed_operations is None
    ):
        return NotAvailable("coverage_not_measured")
    return ratio(scan.observed_operations, scan.eligible_operations, empty="no_eligible_operations")


def score_dedup(item: LabeledScan, labels: PairLabels | None) -> DedupScore:
    """§7.2：列表壓縮比例不是 precision 的改善；合併的對錯以人工標記為準。"""
    scan = item.scan
    if len(scan.findings) > scan.observation_count:
        raise InconsistentScanError("finding 比觀察多：收集的資料不一致")
    merged = [finding.signature for finding in scan.findings if len(finding.engines) >= 2]
    marks: dict[Signature, bool] = {}
    missed = 0
    complete = False
    if labels is not None:
        marks = {
            label.finding.signature(): label.correct
            for label in labels.merged
            if label.target.value == item.target_kind
        }
        present = {finding.signature for finding in scan.findings}
        missed = sum(
            1
            for pair in labels.missed
            if pair.target.value == item.target_kind
            and {pair.first.signature(), pair.second.signature()} <= present
        )
        complete = labels.complete
    correct = sum(1 for signature in merged if marks.get(signature) is True)
    if not merged:
        precision: Metric = NotAvailable("no_merges")
    elif any(signature not in marks for signature in merged):
        precision = NotAvailable("unlabeled_merges")
    else:
        precision = Ratio(correct, len(merged))
    recall = (
        ratio(correct, correct + missed, empty="nothing_to_merge")
        if complete and all(signature in marks for signature in merged)
        else NotAvailable("pair_labels_incomplete")
    )
    return DedupScore(
        findings=len(scan.findings),
        observations=scan.observation_count,
        compression=ratio(
            scan.observation_count - len(scan.findings),
            scan.observation_count,
            empty="no_observations",
        ),
        merged_findings=len(merged),
        merge_precision=precision,
        merge_recall=recall,
        false_merges=tuple(signature for signature in merged if marks.get(signature) is False),
        missed_merges=missed,
    )
