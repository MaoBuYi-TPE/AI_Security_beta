"""評估（純函式；SECURITY_AND_TESTING.md §7、docs/DECISIONS.md §29）。

輸入是正規化之後的 scan、比較快照、ground truth 與人工標記；不讀檔、不連網。

- recall 以案例計：列入評估的是 security、supported、適用這個 scan 的 auth role、存在於這個版本
  的案例；holdout 預設排除（include_holdout 只能用在凍結之後的 ground truth）。
- precision 以議題計（§7.1：同一個真實問題由多個 finding 或兩個工具命中只算一次）：TP 是偵測到的
  案例與裁定為真的另一個議題；FP 是修補版上對上案例的 finding 與裁定為誤報的議題。finding 層級的
  precision 另列為次要數字。還有未裁定的 finding 時 precision 是 N/A。
- 環境故障（interrupted、cancelled，或 run 的錯誤碼屬於環境）讓整批作廢：拒絕評估，不挑掉樣本。
"""

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from benchmarks.ground_truth import (
    Adjudications,
    Case,
    CaseKind,
    GroundTruth,
    Label,
    PairLabels,
    Support,
    TruthStatus,
)
from benchmarks.matching import adjudication_for, match_case
from benchmarks.metrics import Derived, Metric, NotAvailable, f1, ratio
from benchmarks.models import ComparisonRecord, FindingRecord, LabeledScan, ScanRecord, Signature
from benchmarks.rescan import RescanScore, score_comparison
from benchmarks.scoring import DedupScore, Resources, coverage, resources, score_dedup

SECURITY = "security"
# 環境故障：不是工具或預算的結果，樣本不能用（整批作廢、以新的名稱重跑）。
ENVIRONMENT_ERRORS = frozenset(
    {
        "LEASE_EXPIRED",
        "RUNTIME_UNAVAILABLE",
        "GUARD_UNAVAILABLE",
        "RUNNER_STOPPED",
        "WORKSPACE_UNAVAILABLE",
        "SECRET_UNAVAILABLE",
        "PARSE_ATTEMPTS_EXHAUSTED",
    }
)
INVALID_SCAN_STATUSES = frozenset({"interrupted", "cancelled"})


class EvaluationError(ValueError):
    """輸入不能評估（fake 的 scan、環境故障、重複的 scan、對不上的比較）。"""


@dataclass(frozen=True, slots=True)
class EngineAttribution:
    detected: int
    unique: int


@dataclass(frozen=True, slots=True)
class Detection:
    evaluated_cases: tuple[str, ...]
    detected_cases: tuple[str, ...]
    missed_cases: tuple[str, ...]
    excluded_cases: Mapping[str, tuple[str, ...]]
    true_positive_units: tuple[str, ...]
    false_positive_units: tuple[str, ...]
    recall: Metric
    precision: Metric
    finding_precision: Metric
    f1: Derived
    unadjudicated: tuple[Signature, ...]
    excluded_findings: Mapping[str, int]
    anomalies: tuple[str, ...]
    engines: Mapping[str, EngineAttribution]
    multi_engine_precision: Metric
    single_engine_precision: Metric


@dataclass(frozen=True, slots=True)
class ScanScore:
    position: int
    scan_id: str
    group: str
    target: str
    variant: str
    repetition: int | None
    status: str
    detection: Detection | None
    resources: Resources
    coverage: Metric
    dedup: DedupScore


@dataclass(frozen=True, slots=True)
class Evaluation:
    scans: tuple[ScanScore, ...]
    rescans: tuple[RescanScore, ...]
    ground_truth: Mapping[str, str] = field(default_factory=dict)
    include_holdout: bool = False


def evaluate(
    scans: Sequence[LabeledScan],
    *,
    truths: Sequence[GroundTruth] = (),
    adjudications: Adjudications | None = None,
    pair_labels: PairLabels | None = None,
    comparisons: Sequence[tuple[str | None, ComparisonRecord]] = (),
    include_holdout: bool = False,
) -> Evaluation:
    _check_batch(scans)
    by_target = {truth.target.value: truth for truth in truths}
    if len(by_target) != len(truths):
        raise EvaluationError("每個靶場只能有一份 ground truth")
    if include_holdout and any(truth.status is not TruthStatus.FROZEN for truth in truths):
        raise EvaluationError("holdout 只能用凍結之後的 ground truth 評估")
    by_id = {item.scan.id: item for item in scans}
    return Evaluation(
        scans=tuple(
            score_scan(
                item,
                by_target.get(item.target_kind),
                adjudications=adjudications,
                pair_labels=pair_labels,
                include_holdout=include_holdout,
            )
            for item in scans
        ),
        rescans=tuple(
            _score_block(block, record, by_id, by_target) for block, record in comparisons
        ),
        ground_truth={target: truth.status.value for target, truth in sorted(by_target.items())},
        include_holdout=include_holdout,
    )


def score_scan(
    item: LabeledScan,
    truth: GroundTruth | None,
    *,
    adjudications: Adjudications | None = None,
    pair_labels: PairLabels | None = None,
    include_holdout: bool = False,
) -> ScanScore:
    _check_scan(item.scan)
    return ScanScore(
        position=item.position,
        scan_id=item.scan.id,
        group=item.group,
        target=item.target,
        variant=item.variant,
        repetition=item.repetition,
        status=item.scan.status,
        detection=(
            None
            if truth is None
            else score_detection(item, truth, adjudications, include_holdout=include_holdout)
        ),
        resources=resources(item.scan),
        coverage=coverage(item.scan),
        dedup=score_dedup(item, pair_labels),
    )


# --- 偵測 --------------------------------------------------------------------------------------


@dataclass
class _Tally:
    tp_units: set[str] = field(default_factory=set)
    fp_units: set[str] = field(default_factory=set)
    tp_findings: list[FindingRecord] = field(default_factory=list)
    fp_findings: list[FindingRecord] = field(default_factory=list)
    unadjudicated: list[Signature] = field(default_factory=list)
    excluded: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    anomalies: set[str] = field(default_factory=set)
    case_engines: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))


def score_detection(
    item: LabeledScan,
    truth: GroundTruth,
    adjudications: Adjudications | None,
    *,
    include_holdout: bool = False,
) -> Detection:
    if truth.target.value != item.target_kind:
        raise EvaluationError("ground truth 的靶場和 scan 不同")
    tally = _Tally()
    for finding in item.scan.findings:
        _classify(finding, item, truth, adjudications, tally, include_holdout=include_holdout)
    evaluated, excluded_cases = _evaluated_cases(truth, item, include_holdout=include_holdout)
    detected = tuple(case for case in evaluated if case in tally.case_engines)
    unadjudicated = tuple(tally.unadjudicated)
    precision = _precision(len(tally.tp_units), len(tally.fp_units), unadjudicated)
    recall = ratio(len(detected), len(evaluated), empty="no_positive_cases")
    return Detection(
        evaluated_cases=evaluated,
        detected_cases=detected,
        missed_cases=tuple(case for case in evaluated if case not in detected),
        excluded_cases=excluded_cases,
        true_positive_units=tuple(sorted(tally.tp_units)),
        false_positive_units=tuple(sorted(tally.fp_units)),
        recall=recall,
        precision=precision,
        finding_precision=_precision(len(tally.tp_findings), len(tally.fp_findings), unadjudicated),
        f1=f1(precision, recall),
        unadjudicated=unadjudicated,
        excluded_findings=dict(sorted(tally.excluded.items())),
        anomalies=tuple(sorted(tally.anomalies)),
        engines=_attribution(detected, tally.case_engines),
        multi_engine_precision=_split_precision(tally, unadjudicated, multi=True),
        single_engine_precision=_split_precision(tally, unadjudicated, multi=False),
    )


def _classify(
    finding: FindingRecord,
    item: LabeledScan,
    truth: GroundTruth,
    adjudications: Adjudications | None,
    tally: _Tally,
    *,
    include_holdout: bool,
) -> None:
    if finding.kind != SECURITY:
        tally.excluded["not_security_finding"] += 1
        return
    case = match_case(truth, finding.signature)
    if case is None:
        _adjudicated(finding, item, adjudications, tally)
        return
    reason = _case_exclusion(case, item.scan.auth_role, include_holdout=include_holdout)
    if reason is not None:
        tally.excluded[reason] += 1
        if case.support is Support.PLATFORM_BLOCKED:
            tally.anomalies.add(f"platform_blocked_case_matched:{case.id}")
        return
    if item.variant in {variant.value for variant in case.present_in}:
        tally.tp_units.add(f"case:{case.id}")
        tally.tp_findings.append(finding)
        tally.case_engines[case.id].update(finding.engines)
    else:
        tally.fp_units.add(f"patched:{case.id}")
        tally.fp_findings.append(finding)


def _adjudicated(
    finding: FindingRecord, item: LabeledScan, adjudications: Adjudications | None, tally: _Tally
) -> None:
    label = adjudication_for(
        adjudications, target=item.target_kind, variant=item.variant, signature=finding.signature
    )
    if label is None:
        tally.unadjudicated.append(finding.signature)
    elif label.label is Label.TRUE_EXTRA:
        tally.tp_units.add(f"extra:{label.issue}")
        tally.tp_findings.append(finding)
    elif label.label is Label.FALSE_POSITIVE:
        tally.fp_units.add(f"false_positive:{label.issue}")
        tally.fp_findings.append(finding)
    else:
        tally.excluded["adjudicated_not_security"] += 1


def _case_exclusion(case: Case, auth_role: str, *, include_holdout: bool) -> str | None:
    if case.support is Support.PLATFORM_BLOCKED:
        return "platform_blocked"
    if case.support is Support.UNSUPPORTED:
        return "unsupported"
    if case.kind is not CaseKind.SECURITY:
        return "not_security_case"
    if case.holdout and not include_holdout:
        return "holdout"
    if case.auth_role != auth_role:
        return "auth_role"
    return None


def _evaluated_cases(
    truth: GroundTruth, item: LabeledScan, *, include_holdout: bool
) -> tuple[tuple[str, ...], Mapping[str, tuple[str, ...]]]:
    evaluated: list[str] = []
    excluded: dict[str, list[str]] = defaultdict(list)
    for case in truth.cases:
        reason = _case_exclusion(case, item.scan.auth_role, include_holdout=include_holdout)
        if reason is None and item.variant not in {v.value for v in case.present_in}:
            reason = "not_present_in_variant"
        if reason is None:
            evaluated.append(case.id)
        else:
            excluded[reason].append(case.id)
    return tuple(evaluated), {reason: tuple(ids) for reason, ids in sorted(excluded.items())}


def _precision(tp: int, fp: int, unadjudicated: Sequence[Signature]) -> Metric:
    if unadjudicated:
        return NotAvailable(f"unadjudicated_findings:{len(unadjudicated)}")
    return ratio(tp, tp + fp, empty="no_findings")


def _split_precision(tally: _Tally, unadjudicated: Sequence[Signature], *, multi: bool) -> Metric:
    """§7.1 的探索性分組：2 個以上引擎命中 vs 1 個（finding 層級；不作為合併或升級的規則）。"""

    def chosen(finding: FindingRecord) -> bool:
        return (len(finding.engines) >= 2) is multi

    if unadjudicated:
        return NotAvailable(f"unadjudicated_findings:{len(unadjudicated)}")
    tp = sum(1 for finding in tally.tp_findings if chosen(finding))
    fp = sum(1 for finding in tally.fp_findings if chosen(finding))
    return ratio(tp, tp + fp, empty="no_findings")


def _attribution(
    detected: Sequence[str], case_engines: Mapping[str, set[str]]
) -> Mapping[str, EngineAttribution]:
    engines = sorted({engine for case in detected for engine in case_engines[case]})
    return {
        engine: EngineAttribution(
            detected=sum(1 for case in detected if engine in case_engines[case]),
            unique=sum(1 for case in detected if case_engines[case] == {engine}),
        )
        for engine in engines
    }


def _score_block(
    block: str | None,
    record: ComparisonRecord,
    by_id: Mapping[str, LabeledScan],
    by_target: Mapping[str, GroundTruth],
) -> RescanScore:
    baseline = by_id.get(record.baseline_scan_id)
    current = by_id.get(record.current_scan_id)
    if baseline is None or current is None:
        raise EvaluationError("比較快照引用了不在這一批的 scan")
    truth = by_target.get(current.target_kind)
    return score_comparison(record, baseline, current, truth, block=block)


# --- 批次的檢查 ---------------------------------------------------------------------------------


def _check_batch(scans: Sequence[LabeledScan]) -> None:
    ids = [item.scan.id for item in scans]
    if len(set(ids)) != len(ids):
        raise EvaluationError("同一個 scan 出現兩次")
    for item in scans:
        _check_scan(item.scan)


def _check_scan(scan: ScanRecord) -> None:
    if scan.fixture:
        raise EvaluationError("fake 引擎的 scan 不能評估")
    environment = [run.error_code for run in scan.runs if run.error_code in ENVIRONMENT_ERRORS]
    if scan.status in INVALID_SCAN_STATUSES or environment:
        raise EvaluationError("有環境故障或被中斷、取消的 scan：整批作廢，以新的名稱重跑")
