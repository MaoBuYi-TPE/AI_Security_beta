"""修補案例必須逐 finding 驗證；未命中的案例與未對應告警不能被隱藏。"""

from typing import Any

import pytest

from tests.live.rescan_assertions import (
    CALIBRATED_STRUCTURE,
    assert_calibrated_structure,
    assert_conservative_comparison,
    check_patched_cases,
)


def _finding(
    group: str, *, route: str = "/", method: str = "GET", parameter: str | None = None
) -> dict[str, Any]:
    return {
        "id": f"{group}:{method}:{route}:{parameter}",
        "rule_group": group,
        "location": {
            "method": method,
            "route": route,
            "parameter_location": "query" if parameter else None,
            "parameter_name": parameter,
        },
    }


def _comparison(item: dict[str, Any], classification: str) -> dict[str, Any]:
    return {"finding_id": item["id"], "classification": classification}


@pytest.mark.parametrize(
    "group",
    [
        "csp-header-missing",
        "x-content-type-options-missing",
        "anti-clickjacking-header-missing",
        "nuclei-csp-header-missing",
        "nuclei-x-content-type-options-missing",
        "nuclei-x-frame-options-missing",
        "nuclei-referrer-policy-missing",
        "zap-cors-wildcard-origin",
        "nuclei-cors-arbitrary-origin-with-credentials",
    ],
)
@pytest.mark.parametrize("classification", ["persistent", "new", "not_comparable"])
def test_each_global_patch_is_checked_even_beside_a_passing_sqli_case(
    group: str, classification: str
) -> None:
    sql = _finding("zap-sql-injection", route="/search", parameter="q")
    header = _finding(group, route="/greet")
    with pytest.raises(AssertionError, match="修補案例"):
        check_patched_cases(
            [sql, header], [_comparison(sql, "inconclusive"), _comparison(header, classification)]
        )


def test_missing_comparison_row_cannot_silently_skip_a_patch() -> None:
    with pytest.raises(AssertionError, match="比較缺少"):
        check_patched_cases([_finding("csp-header-missing")], [])


def test_parameter_cases_require_the_actual_method_route_and_parameter() -> None:
    valid = _finding("zap-sql-injection", route="/search", parameter="q")
    other = _finding("zap-sql-injection", route="/unrelated", parameter="q")
    wrong_parameter = _finding("zap-sql-injection", route="/search", parameter="other")
    wrong_method = _finding("zap-sql-injection", route="/search", method="POST", parameter="q")
    findings = [valid, other, wrong_parameter, wrong_method]
    manifest = check_patched_cases(findings, [_comparison(f, "inconclusive") for f in findings])
    case = next(c for c in manifest["cases"] if c["case_id"] == "T30-FX-01")
    assert case["finding_ids"] == [valid["id"]]
    assert set(manifest["unmapped_finding_ids"]) == {f["id"] for f in findings[1:]}


def test_all_cases_and_unobserved_checks_are_recorded() -> None:
    item = _finding("csp-header-missing")
    manifest = check_patched_cases([item], [_comparison(item, "inconclusive")])
    cases = {c["case_id"]: c for c in manifest["cases"]}
    assert cases["T30-FX-05"]["finding_ids"] == [item["id"]]
    assert cases["T30-FX-01"]["status"] == "baseline_not_observed"
    assert cases["T30-FX-10"]["status"] == "no_automatic_mapping"
    assert manifest["unmapped_finding_ids"] == []


@pytest.mark.parametrize("classification", ["inconclusive", "not_observed"])
def test_each_matching_finding_is_recorded_and_checked(classification: str) -> None:
    findings = [_finding("x-content-type-options-missing", route=p) for p in ("/", "/greet")]
    manifest = check_patched_cases(findings, [_comparison(f, classification) for f in findings])
    case = next(c for c in manifest["cases"] if c["case_id"] == "T30-FX-05")
    assert set(case["finding_ids"]) == {f["id"] for f in findings}


def test_empty_baseline_is_not_a_successful_patch_check() -> None:
    with pytest.raises(AssertionError, match="baseline"):
        check_patched_cases([], [])


def _snapshot(**counts: int) -> dict[str, Any]:
    return {"algorithm_version": 1, "counts": {"new": 0, "not_observed": 0, **counts}}


def _evidence(classification: str, completed: bool) -> dict[str, Any]:
    return {
        "classification": classification,
        "evidence": {"other_scan_coverage": {"sources": [{"rule_completed": completed}]}},
    }


@pytest.mark.parametrize("classification", ["new", "not_observed"])
def test_even_unmapped_findings_cannot_have_a_negative_conclusion(classification: str) -> None:
    with pytest.raises(AssertionError):
        assert_conservative_comparison(_snapshot(), [_evidence(classification, False)])
    with pytest.raises(AssertionError):
        assert_conservative_comparison(_snapshot(**{classification: 1}), [])


def test_current_producers_cannot_claim_completed_rules() -> None:
    with pytest.raises(AssertionError):
        assert_conservative_comparison(_snapshot(), [_evidence("inconclusive", True)])


def test_fallback_accepts_positive_or_incomplete_evidence_without_inventing_coverage() -> None:
    assert_conservative_comparison(
        _snapshot(),
        [
            _evidence("inconclusive", False),
            {"classification": "persistent", "evidence": {"other_scan_coverage": None}},
        ],
    )


def test_algorithm_changes_require_explicit_review_of_live_assertions() -> None:
    with pytest.raises(AssertionError):
        assert_conservative_comparison({**_snapshot(), "algorithm_version": 2}, [])


_CALIBRATED = {
    "unchanged": ("comparable", False, []),
    "patched": ("comparable", False, []),
    "partial-comparison": ("different", True, ["fingerprint_version_mismatch_or_unknown"]),
}


def _structure(label: str, **changes: Any) -> dict[str, Any]:
    comparability, manual, reasons = _CALIBRATED[label]
    counts = {
        "new": 0,
        "persistent": 3,
        "not_observed": 0,
        "inconclusive": 5,
        "not_comparable": changes.pop("not_comparable", 0),
    }
    snapshot = {
        "comparability": comparability,
        "manual_review_required": manual,
        "reasons": reasons,
        "counts": counts,
    }
    return {**snapshot, **changes}


def test_calibrated_structure_covers_exactly_the_three_live_comparisons() -> None:
    assert set(CALIBRATED_STRUCTURE) == set(_CALIBRATED)


@pytest.mark.parametrize("label", list(_CALIBRATED))
def test_calibrated_structure_accepts_the_three_calibration_results(label: str) -> None:
    assert_calibrated_structure(label, _structure(label))


@pytest.mark.parametrize(
    ("label", "changes"),
    [
        ("unchanged", {"comparability": "different"}),
        ("patched", {"comparability": "not_comparable"}),
        ("partial-comparison", {"comparability": "comparable"}),
        ("unchanged", {"manual_review_required": True}),
        ("partial-comparison", {"manual_review_required": False}),
        ("patched", {"not_comparable": 1}),
        ("partial-comparison", {"not_comparable": 2}),
        ("unchanged", {"reasons": ["mapping_version_mismatch_or_unknown"]}),
        ("partial-comparison", {"reasons": []}),
    ],
)
def test_calibrated_structure_rejects_any_drift(label: str, changes: dict[str, Any]) -> None:
    with pytest.raises(AssertionError, match=label):
        assert_calibrated_structure(label, _structure(label, **changes))


def test_uncalibrated_comparisons_are_not_silently_accepted() -> None:
    with pytest.raises(AssertionError, match="未校準"):
        assert_calibrated_structure("other", _structure("unchanged"))
