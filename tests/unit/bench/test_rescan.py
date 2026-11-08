"""複掃的指標（BENCH-09；SECURITY_AND_TESTING.md §7.4）：誤判已修補必須是 0。"""

import pytest

from benchmarks.evaluate import EvaluationError, evaluate
from benchmarks.metrics import NotAvailable
from benchmarks.models import ComparisonItem, ComparisonRecord, LabeledScan
from benchmarks.rescan import ComparisonMismatchError, score_comparison
from tests.unit.bench.records import NOISE, SQLI, XCTO, finding, labeled, scan, truth


def _pair(current_variant: str) -> tuple[LabeledScan, LabeledScan]:
    baseline = labeled(
        scan(
            finding(SQLI, finding_id="f-sqli"),
            finding(XCTO, finding_id="f-hdr"),
            finding(NOISE, finding_id="f-noise"),
            id="base",
        )
    )
    current = labeled(
        scan(finding(XCTO, finding_id="f-hdr"), id="curr"), variant=current_variant, position=2
    )
    return baseline, current


def _record(items: list[tuple[str, str]], *, review: bool = False) -> ComparisonRecord:
    return ComparisonRecord(
        id="cmp-1",
        baseline_scan_id="base",
        current_scan_id="curr",
        comparability="comparable",
        manual_review_required=review,
        items=tuple(ComparisonItem(fid, classification, review) for fid, classification in items),
    )


def test_a_present_case_judged_not_observed_is_a_false_repair() -> None:
    """弱點→弱點：SQLI-1 仍存在卻被判 not_observed，誤判已修補 1。"""
    baseline, current = _pair("insecure")
    record = _record(
        [("f-sqli", "not_observed"), ("f-hdr", "persistent"), ("f-noise", "not_observed")]
    )

    score = score_comparison(record, baseline, current, truth())

    assert score.false_repair == 1
    assert score.false_repair_cases == ("SQLI-1",)
    assert score.unmatched_not_observed == 1
    assert score.counts == {"not_observed": 2, "persistent": 1}
    assert score.persistent_on_patched == ()


def test_inconclusive_is_never_a_verified_repair() -> None:
    baseline, current = _pair("insecure")
    record = _record(
        [("f-sqli", "inconclusive"), ("f-hdr", "persistent"), ("f-noise", "inconclusive")]
    )

    score = score_comparison(record, baseline, current, truth())

    assert score.false_repair == 0
    assert score.counts == {"inconclusive": 2, "persistent": 1}


def test_a_patched_case_not_observed_is_not_a_false_repair_and_persistent_ones_are_flagged() -> (
    None
):
    baseline, current = _pair("secure")
    record = _record([("f-sqli", "not_observed"), ("f-hdr", "persistent")], review=True)

    score = score_comparison(record, baseline, current, truth(), block="c1")

    assert score.false_repair == 0
    assert score.persistent_on_patched == ("HDR-1",)
    assert (score.manual_review, score.block) == (2, "c1")


def test_without_ground_truth_the_false_repair_count_is_not_available() -> None:
    baseline, current = _pair("insecure")

    score = score_comparison(_record([("f-sqli", "not_observed")]), baseline, current, None)

    assert score.false_repair == NotAvailable("no_ground_truth")


def test_a_comparison_of_other_scans_is_refused() -> None:
    baseline, current = _pair("insecure")

    with pytest.raises(ComparisonMismatchError, match="對不上"):
        score_comparison(_record([]), current, baseline, truth())


def test_both_scans_must_share_the_group_and_target() -> None:
    baseline, current = _pair("insecure")
    other = labeled(current.scan, group="A", variant="insecure")

    with pytest.raises(ComparisonMismatchError, match="同一個組別"):
        score_comparison(_record([]), baseline, other, truth())


def test_an_unknown_finding_is_refused() -> None:
    baseline, current = _pair("insecure")

    with pytest.raises(ComparisonMismatchError, match="沒有的 finding"):
        score_comparison(_record([("missing", "not_observed")]), baseline, current, truth())


def test_evaluate_scores_comparisons_of_scans_in_the_batch() -> None:
    baseline, current = _pair("insecure")

    result = evaluate(
        [baseline, current],
        truths=[truth()],
        comparisons=[("c1", _record([("f-sqli", "not_observed")]))],
    )

    assert result.rescans[0].false_repair == 1
    assert result.rescans[0].block == "c1"


def test_evaluate_refuses_comparisons_outside_the_batch() -> None:
    baseline, _ = _pair("insecure")

    with pytest.raises(EvaluationError, match="不在這一批"):
        evaluate([baseline], comparisons=[(None, _record([]))])
