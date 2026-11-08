"""複掃的指標（純函式；SECURITY_AND_TESTING.md §7.4）：以比較快照與 ground truth 核對。"""

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass

from benchmarks.ground_truth import GroundTruth
from benchmarks.matching import match_case
from benchmarks.metrics import NotAvailable
from benchmarks.models import ComparisonRecord, FindingRecord, LabeledScan, ScanRecord


class ComparisonMismatchError(ValueError):
    """比較快照和 scan 對不上。"""


@dataclass(frozen=True, slots=True)
class RescanScore:
    comparison_id: str
    block: str | None
    comparability: str
    counts: Mapping[str, int]
    manual_review: int
    false_repair: int | NotAvailable
    false_repair_cases: tuple[str, ...]
    unmatched_not_observed: int
    persistent_on_patched: tuple[str, ...]


def score_comparison(
    record: ComparisonRecord,
    baseline: LabeledScan,
    current: LabeledScan,
    truth: GroundTruth | None,
    *,
    block: str | None = None,
) -> RescanScore:
    """「誤判已修補」是 ground truth 在 current 的版本仍存在，卻被判 not_observed（必須是 0）。

    inconclusive 不算驗證修補；修補版上仍 persistent 的案例另外列出。
    """
    if (record.baseline_scan_id, record.current_scan_id) != (baseline.scan.id, current.scan.id):
        raise ComparisonMismatchError("比較快照和 scan 對不上")
    if (baseline.group, baseline.target) != (current.group, current.target):
        raise ComparisonMismatchError("比較的兩個 scan 必須是同一個組別與靶場")
    counts: dict[str, int] = defaultdict(int)
    false_repair: list[str] = []
    patched: list[str] = []
    unmatched = 0
    for entry in record.items:
        counts[entry.classification] += 1
        if truth is None or entry.classification not in {"not_observed", "persistent"}:
            continue
        source = baseline if entry.classification == "not_observed" else current
        case = match_case(truth, _finding(source.scan, entry.finding_id).signature)
        present = case is not None and current.variant in {v.value for v in case.present_in}
        if entry.classification == "not_observed":
            if case is None:
                unmatched += 1
            elif present:
                false_repair.append(case.id)
        elif case is not None and not present:
            patched.append(case.id)
    return RescanScore(
        comparison_id=record.id,
        block=block,
        comparability=record.comparability,
        counts=dict(sorted(counts.items())),
        manual_review=sum(1 for entry in record.items if entry.manual_review_required),
        false_repair=NotAvailable("no_ground_truth") if truth is None else len(false_repair),
        false_repair_cases=tuple(sorted(set(false_repair))),
        unmatched_not_observed=unmatched,
        persistent_on_patched=tuple(sorted(set(patched))),
    )


def _finding(scan: ScanRecord, finding_id: str) -> FindingRecord:
    for finding in scan.findings:
        if finding.id == finding_id:
            return finding
    raise ComparisonMismatchError("比較快照引用了 scan 中沒有的 finding")
