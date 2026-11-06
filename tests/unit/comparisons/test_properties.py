"""複掃分類的不變式：移除證據不能產生負面結論，非 persistent 必須解釋理由。"""

from dataclasses import replace

from hypothesis import given
from hypothesis import strategies as st
from tests.unit.comparisons.test_classification import BASELINE_ONLY, COVERED, SOURCE

from secscan.comparisons.domain.classification import (
    Classification,
    CoverageEvidence,
    RuleEvidence,
    classify,
)

LAYERS = (
    "scope",
    "role",
    "identity",
    "spec",
    "telemetry",
    "engine",
    "time_limit",
    "definition",
    "response",
    "rule",
    "parameter",
    "fingerprint",
    "mapping",
    "original_identity",
)


@given(st.sets(st.sampled_from(LAYERS), min_size=1))
def test_removing_any_combination_of_required_evidence_cannot_remain_not_observed(
    missing: set[str],
) -> None:
    assert classify(BASELINE_ONLY).classification is Classification.NOT_OBSERVED
    rule = RuleEvidence(
        source=SOURCE,
        engine_succeeded="engine" not in missing,
        time_limit_reached="time_limit" in missing,
        definition_comparable="definition" not in missing,
        has_location_response="response" not in missing,
        rule_completed="rule" not in missing,
        parameter_comparable="parameter" not in missing,
    )
    coverage = CoverageEvidence(
        in_scope="scope" not in missing,
        role_comparable="role" not in missing,
        identity_verified="identity" not in missing,
        spec_comparable="spec" not in missing,
        telemetry_complete="telemetry" not in missing,
        required_sources=(SOURCE,),
        sources=(rule,),
    )
    result = classify(
        replace(
            BASELINE_ONLY,
            fingerprint_comparable="fingerprint" not in missing,
            mapping_comparable="mapping" not in missing,
            finding_identity_verified="original_identity" not in missing,
            other_scan_coverage=coverage,
        )
    )
    assert result.classification is not Classification.NOT_OBSERVED
    assert result.reasons


@given(st.booleans(), st.one_of(st.none(), st.just(COVERED)))
def test_both_observed_with_comparable_versions_is_persistent(
    identity: bool, coverage: CoverageEvidence | None
) -> None:
    result = classify(
        replace(
            BASELINE_ONLY,
            current_observed=True,
            finding_identity_verified=identity,
            other_scan_coverage=coverage,
        )
    )
    assert result.classification is Classification.PERSISTENT


@given(st.booleans(), st.booleans(), st.booleans(), st.one_of(st.none(), st.just(COVERED)))
def test_every_one_sided_result_explains_its_classification(
    baseline: bool, fingerprint: bool, mapping: bool, coverage: CoverageEvidence | None
) -> None:
    result = classify(
        replace(
            BASELINE_ONLY,
            baseline_observed=baseline,
            current_observed=not baseline,
            fingerprint_comparable=fingerprint,
            mapping_comparable=mapping,
            other_scan_coverage=coverage,
        )
    )
    assert result.classification is not Classification.PERSISTENT
    assert result.reasons
