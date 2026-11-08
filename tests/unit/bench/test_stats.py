"""跨重複的統計與評估的 JSON（BENCH-10）：IQR 只在 n ≥ 4 時才算，N/A 不當成 0。"""

import json

import pytest
from hypothesis import given
from hypothesis import strategies as st

from benchmarks.evaluate import evaluate
from benchmarks.metrics import NotAvailable, Ratio, Score, f1, metric_json, ratio, value_of
from benchmarks.stats import DRAFT_NOTICE, SMOKE_NOTICE, Summary, cells, evaluation_json, summarize
from tests.unit.bench.records import NOISE, SQLI, XSS, finding, labeled, scan, truth


def test_small_samples_have_a_median_and_range_but_no_iqr() -> None:
    assert summarize([0.5, None, 1.0, 0.0]) == Summary(4, 3, 0.5, 0.0, 1.0, None)


def test_four_values_have_an_iqr() -> None:
    summary = summarize([1.0, 2.0, 3.0, 4.0, None])

    assert (summary.n, summary.available, summary.median) == (5, 4, 2.5)
    assert summary.iqr == (1.75, 3.25)


def test_no_values_are_all_none() -> None:
    assert summarize([None, None]) == Summary(2, 0, None, None, None, None)
    assert summarize([]) == Summary(0, 0, None, None, None, None)


@given(st.lists(st.one_of(st.none(), st.floats(min_value=0, max_value=1)), max_size=12))
def test_summaries_stay_within_the_range(values: list[float | None]) -> None:
    summary = summarize(values)

    if summary.median is not None:
        assert summary.minimum is not None
        assert summary.maximum is not None
        assert summary.minimum <= summary.median <= summary.maximum
        if summary.iqr is not None:
            assert summary.minimum <= summary.iqr[0] <= summary.iqr[1] <= summary.maximum
    assert summary.available == sum(value is not None for value in values)


def _evaluation() -> object:
    return evaluate(
        [
            labeled(scan(finding(SQLI), id="s1"), position=1, repetition=1),
            labeled(scan(finding(SQLI), finding(XSS), id="s2"), position=2, repetition=2),
            labeled(scan(finding(NOISE), id="s3"), position=3, repetition=3),
            labeled(scan(id="s4", status="failed"), position=4, group="A", repetition=1),
        ],
        truths=[truth()],
    )


def test_cells_group_repetitions_and_count_detection_frequency() -> None:
    [first, second] = cells(_evaluation())  # type: ignore[arg-type]

    assert (first["group"], first["n"], first["statuses"]) == ("A", 1, {"failed": 1})
    assert (second["group"], second["n"]) == ("C", 3)
    assert second["detection_frequency"]["SQLI-1"] == {"detected": 2, "n": 3}
    assert second["detection_frequency"]["XSS-1"] == {"detected": 1, "n": 3}
    recall = second["metrics"]["recall"]
    assert (recall["n"], recall["available"], recall["iqr"]) == (3, 3, None)
    precision = second["metrics"]["precision"]
    # s3 有未裁定的 finding：precision 是 N/A，不當成 0。
    assert precision["available"] == 2


def test_the_json_marks_smoke_and_draft_results() -> None:
    document = evaluation_json(_evaluation(), purpose="smoke")  # type: ignore[arg-type]

    assert document["notices"] == [SMOKE_NOTICE, DRAFT_NOTICE]
    assert document["ground_truth"] == {"fixture": "draft"}
    detection = document["scans"][2]["detection"]
    assert detection["precision"] == {"value": None, "not_available": "unadjudicated_findings:1"}
    assert detection["recall"]["denominator"] == 3
    assert detection["unadjudicated"][0]["rule_group"] == NOISE.rule_group
    json.dumps(document)


def test_an_experiment_with_a_frozen_truth_has_no_notice() -> None:
    result = evaluate([labeled(scan(finding(SQLI)))], truths=[truth(status="frozen")])

    assert evaluation_json(result, purpose="experiment")["notices"] == []


def test_resources_only_without_ground_truth() -> None:
    document = evaluation_json(evaluate([labeled(scan())]), purpose="smoke")

    assert document["scans"][0]["detection"] is None
    assert document["cells"][0]["metrics"]["requests_sent"]["median"] == 200.0
    assert document["cells"][0]["detection_frequency"] == {}


# --- 指標的值 -----------------------------------------------------------------------------------


def test_ratios_are_bounded_and_zero_denominators_are_not_available() -> None:
    assert ratio(0, 0, empty="none") == NotAvailable("none")
    assert ratio(1, 4, empty="none") == Ratio(1, 4)
    with pytest.raises(ValueError, match="分母"):
        Ratio(5, 4)
    with pytest.raises(ValueError, match="分母"):
        Ratio(0, 0)


def test_metric_json_and_values() -> None:
    assert metric_json(Ratio(1, 4)) == {"value": 0.25, "numerator": 1, "denominator": 4}
    assert metric_json(Score(0.5)) == {"value": 0.5}
    assert metric_json(NotAvailable("x")) == {"value": None, "not_available": "x"}
    assert value_of(NotAvailable("x")) is None
    assert value_of(f1(Ratio(1, 1), Ratio(1, 1))) == 1.0
