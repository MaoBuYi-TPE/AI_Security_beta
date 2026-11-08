"""偵測指標與 N/A 規則（BENCH-05、06；SECURITY_AND_TESTING.md §7.1）。"""

import json
from dataclasses import replace

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from benchmarks.evaluate import (
    EvaluationError,
    evaluate,
    score_detection,
    score_scan,
)
from benchmarks.ground_truth import Adjudications
from benchmarks.matching import AmbiguousMatchError
from benchmarks.metrics import NotAvailable, Ratio, Score
from benchmarks.models import Signature
from tests.unit.bench.records import (
    BLOCKED,
    CSP,
    ERROR,
    EXTRA,
    NOISE,
    SQLI,
    TRUTH,
    XCTO,
    XSS,
    finding,
    labeled,
    run,
    scan,
    truth,
)


def _adjudications(*items: dict[str, object]) -> Adjudications:
    return Adjudications.model_validate({"version": 1, "items": list(items)})


def _label(
    signature: Signature, label: str, issue: str | None, variant: str = "insecure"
) -> dict[str, object]:
    return {
        "target": "fixture",
        "variant": variant,
        "finding": {
            "rule_group": signature.rule_group,
            "method": signature.method,
            "route": signature.route,
            "parameter_location": signature.parameter_location,
            "parameter_name": signature.parameter_name,
        },
        "label": label,
        "issue": issue,
    }


def test_recall_counts_cases_and_precision_counts_issues() -> None:
    """HDR-1 由兩個 finding、兩個引擎命中：只算一次（§7.1）。"""
    record = scan(finding(SQLI, "zap"), finding(XCTO, "zap", "nuclei"), finding(CSP, "zap"))

    detection = score_detection(labeled(record), truth(), None)

    assert detection.evaluated_cases == ("SQLI-1", "XSS-1", "HDR-1")
    assert detection.detected_cases == ("SQLI-1", "HDR-1")
    assert detection.missed_cases == ("XSS-1",)
    assert detection.recall == Ratio(2, 3)
    assert detection.precision == Ratio(2, 2)
    assert detection.finding_precision == Ratio(3, 3)
    assert detection.true_positive_units == ("case:HDR-1", "case:SQLI-1")
    assert isinstance(detection.f1, Score)
    assert detection.f1.value == pytest.approx(0.8)


def test_cases_outside_the_evaluation_are_listed_with_their_reason() -> None:
    detection = score_detection(labeled(scan()), truth(), None)

    assert detection.excluded_cases == {
        "auth_role": ("IDOR-1",),
        "holdout": ("ERR-1",),
        "not_security_case": ("C-1",),
        "platform_blocked": ("PB-1",),
        "unsupported": ("BOLA-1",),
    }


def test_an_unadjudicated_finding_makes_precision_not_available() -> None:
    record = scan(finding(SQLI), finding(NOISE))

    detection = score_detection(labeled(record), truth(), None)

    assert detection.precision == NotAvailable("unadjudicated_findings:1")
    assert detection.finding_precision == NotAvailable("unadjudicated_findings:1")
    assert detection.unadjudicated == (NOISE,)
    assert detection.recall == Ratio(1, 3)
    assert detection.f1 == NotAvailable("precision: unadjudicated_findings:1")


def test_adjudicated_findings_count_once_per_issue() -> None:
    other = Signature("crlf-injection", "GET", "/other", "query", "y")
    labels = _adjudications(
        _label(EXTRA, "true_extra", "CRLF"),
        _label(other, "true_extra", "CRLF"),
        _label(NOISE, "false_positive", "CSRF-TOKEN"),
        _label(Signature("zap:10096", "GET", "/", None, None), "not_security", None),
    )
    record = scan(
        finding(SQLI),
        finding(EXTRA),
        finding(other),
        finding(NOISE),
        finding(Signature("zap:10096", "GET", "/", None, None)),
    )

    detection = score_detection(labeled(record), truth(), labels)

    assert detection.true_positive_units == ("case:SQLI-1", "extra:CRLF")
    assert detection.false_positive_units == ("false_positive:CSRF-TOKEN",)
    assert detection.precision == Ratio(2, 3)
    assert detection.finding_precision == Ratio(3, 4)
    assert detection.excluded_findings == {"adjudicated_not_security": 1}
    # 另一個議題不進 recall 的分母。
    assert detection.recall == Ratio(1, 3)


def test_adjudications_apply_to_their_variant_only() -> None:
    labels = _adjudications(_label(NOISE, "false_positive", "X", variant="secure"))

    detection = score_detection(labeled(scan(finding(NOISE))), truth(), labels)

    assert detection.unadjudicated == (NOISE,)


def test_a_finding_on_the_patched_variant_that_matches_a_case_is_a_false_positive() -> None:
    record = scan(finding(SQLI), finding(XCTO))

    detection = score_detection(labeled(record, variant="secure"), truth(), None)

    assert detection.false_positive_units == ("patched:HDR-1", "patched:SQLI-1")
    assert detection.precision == Ratio(0, 2)
    assert detection.recall == NotAvailable("no_positive_cases")
    assert detection.excluded_cases["not_present_in_variant"] == ("SQLI-1", "XSS-1", "HDR-1")
    assert detection.f1 == NotAvailable("recall: no_positive_cases")


def test_no_findings_is_not_a_perfect_precision() -> None:
    detection = score_detection(labeled(scan()), truth(), None)

    assert detection.precision == NotAvailable("no_findings")
    assert detection.recall == Ratio(0, 3)


def test_zero_precision_and_recall_has_no_f1() -> None:
    labels = _adjudications(_label(NOISE, "false_positive", "X"))

    detection = score_detection(labeled(scan(finding(NOISE))), truth(), labels)

    assert detection.f1 == NotAvailable("precision_and_recall_zero")


def test_holdout_and_unsupported_findings_stay_out_of_precision() -> None:
    record = scan(finding(SQLI), finding(ERROR))

    detection = score_detection(labeled(record), truth(), None)

    assert detection.excluded_findings == {"holdout": 1}
    assert detection.precision == Ratio(1, 1)


def test_a_match_on_a_platform_blocked_case_is_an_anomaly() -> None:
    detection = score_detection(labeled(scan(finding(BLOCKED))), truth(), None)

    assert detection.anomalies == ("platform_blocked_case_matched:PB-1",)
    assert detection.excluded_findings == {"platform_blocked": 1}
    assert "PB-1" not in detection.evaluated_cases


def test_non_security_findings_are_not_security_false_positives() -> None:
    record = scan(finding(SQLI), finding(NOISE, kind="robustness"))

    detection = score_detection(labeled(record), truth(), None)

    assert detection.excluded_findings == {"not_security_finding": 1}
    assert detection.precision == Ratio(1, 1)


def test_holdout_needs_a_frozen_ground_truth() -> None:
    record = labeled(scan(finding(ERROR)))

    with pytest.raises(EvaluationError, match="凍結"):
        evaluate([record], truths=[truth()], include_holdout=True)

    result = evaluate([record], truths=[truth(status="frozen")], include_holdout=True)
    detection = result.scans[0].detection
    assert detection is not None
    assert "ERR-1" in detection.detected_cases
    assert result.include_holdout is True


def test_an_ambiguous_match_stops_the_evaluation() -> None:
    document = json.loads(json.dumps(TRUTH))
    document["cases"][1]["matchers"] = [{"rule_group": "sql-injection"}]

    with pytest.raises(AmbiguousMatchError, match="SQLI-1"):
        score_detection(labeled(scan(finding(SQLI))), truth(cases=document["cases"]), None)


def test_the_case_auth_role_must_match_the_scan() -> None:
    idor = Signature("idor", "GET", "/api/orders/{id}", "path", "id")

    anonymous = score_detection(labeled(scan(finding(idor))), truth(), None)
    signed_in = score_detection(
        labeled(scan(finding(idor), auth_role="standard_user")), truth(), None
    )

    assert anonymous.excluded_findings == {"auth_role": 1}
    assert signed_in.detected_cases == ("IDOR-1",)


# --- 引擎歸屬（BENCH-06）-----------------------------------------------------------------------


def test_engine_attribution_counts_detected_unique_and_the_union() -> None:
    record = scan(finding(SQLI, "zap"), finding(XCTO, "zap", "nuclei"), finding(XSS, "nuclei"))

    detection = score_detection(labeled(record), truth(), None)

    assert {name: (e.detected, e.unique) for name, e in detection.engines.items()} == {
        "nuclei": (2, 1),
        "zap": (2, 1),
    }
    assert len(detection.detected_cases) == 3


def test_findings_hit_by_two_engines_are_compared_separately() -> None:
    """§7.1 的探索性分組：不作為合併或升級的規則。"""
    labels = _adjudications(_label(NOISE, "false_positive", "X"))
    record = scan(finding(XCTO, "zap", "nuclei"), finding(SQLI, "zap"), finding(NOISE, "zap"))

    detection = score_detection(labeled(record), truth(), labels)

    assert detection.multi_engine_precision == Ratio(1, 1)
    assert detection.single_engine_precision == Ratio(1, 2)


def test_the_split_is_not_available_while_findings_are_unadjudicated() -> None:
    detection = score_detection(labeled(scan(finding(NOISE))), truth(), None)

    assert detection.multi_engine_precision == NotAvailable("unadjudicated_findings:1")
    assert detection.single_engine_precision == NotAvailable("unadjudicated_findings:1")


# --- 批次的檢查 ---------------------------------------------------------------------------------


def test_a_fixture_scan_is_rejected() -> None:
    with pytest.raises(EvaluationError, match="fake"):
        score_scan(labeled(scan(fixture=True)), None)


@pytest.mark.parametrize(
    "record",
    [
        scan(status="interrupted"),
        scan(status="cancelled"),
        scan(status="failed", runs=(run("zap", status="failed", error_code="GUARD_UNAVAILABLE"),)),
        scan(runs=(run("zap", status="interrupted", error_code="LEASE_EXPIRED"),)),
    ],
)
def test_an_environment_failure_voids_the_batch(record: object) -> None:
    with pytest.raises(EvaluationError, match="整批作廢"):
        evaluate([labeled(record)])  # type: ignore[arg-type]


def test_budget_and_engine_outcomes_are_valid_results() -> None:
    record = scan(
        status="partially_completed",
        runs=(
            run("zap", status="timed_out", error_code="ENGINE_TIMEOUT"),
            run("nuclei", status="failed", error_code="ENGINE_REPORTED_ERRORS"),
        ),
    )

    assert evaluate([labeled(record)]).scans[0].status == "partially_completed"


def test_the_same_scan_twice_is_rejected() -> None:
    with pytest.raises(EvaluationError, match="兩次"):
        evaluate([labeled(scan()), labeled(scan(), position=2)])


def test_one_ground_truth_per_target() -> None:
    with pytest.raises(EvaluationError, match="一份"):
        evaluate([labeled(scan())], truths=[truth(), truth()])


def test_scans_without_a_ground_truth_have_resources_but_no_detection() -> None:
    result = evaluate(
        [labeled(scan(finding(SQLI)), target="vampi", target_kind="vampi")], truths=[truth()]
    )

    assert result.scans[0].detection is None
    assert result.scans[0].resources.requests_sent == 200


def test_a_ground_truth_for_another_target_is_refused() -> None:
    with pytest.raises(EvaluationError, match="靶場"):
        score_detection(labeled(scan(), target_kind="vampi"), truth(), None)


# --- 性質 --------------------------------------------------------------------------------------

SIGNATURES = (SQLI, XSS, XCTO, CSP, ERROR, EXTRA, BLOCKED)


@settings(max_examples=60)
@given(
    st.lists(st.sampled_from(SIGNATURES), max_size=12),
    st.sampled_from(["insecure", "secure"]),
    st.randoms(use_true_random=False),
)
def test_detection_invariants(signatures: list[Signature], variant: str, rng: object) -> None:
    labels = _adjudications(_label(EXTRA, "true_extra", "CRLF", variant=variant))
    findings = [finding(sig, finding_id=f"f{index}") for index, sig in enumerate(signatures)]
    shuffled = list(findings)
    rng.shuffle(shuffled)  # type: ignore[attr-defined]

    first = score_detection(labeled(scan(*findings), variant=variant), truth(), labels)
    second = score_detection(labeled(scan(*shuffled), variant=variant), truth(), labels)

    assert first == second
    assert len(first.detected_cases) + len(first.missed_cases) == len(first.evaluated_cases)
    for metric in (first.recall, first.precision, first.finding_precision):
        if isinstance(metric, Ratio):
            assert 0 <= metric.value <= 1


@settings(max_examples=40)
@given(st.lists(st.sampled_from((SQLI, XSS, XCTO, CSP)), min_size=1, max_size=6))
def test_a_duplicated_matched_finding_does_not_change_the_issue_counts(
    signatures: list[Signature],
) -> None:
    findings = [finding(sig, finding_id=f"f{index}") for index, sig in enumerate(signatures)]
    duplicated = [*findings, replace(findings[0], id="duplicate")]

    once = score_detection(labeled(scan(*findings)), truth(), None)
    twice = score_detection(labeled(scan(*duplicated)), truth(), None)

    assert (once.recall, once.precision) == (twice.recall, twice.precision)


@settings(max_examples=40)
@given(st.lists(st.sampled_from((SQLI, XSS, XCTO)), max_size=6))
def test_an_extra_unadjudicated_finding_always_makes_precision_not_available(
    signatures: list[Signature],
) -> None:
    findings = [finding(sig, finding_id=f"f{index}") for index, sig in enumerate(signatures)]

    detection = score_detection(labeled(scan(*findings, finding(NOISE))), truth(), None)

    assert isinstance(detection.precision, NotAvailable)
