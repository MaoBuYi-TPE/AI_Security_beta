"""T22：複掃分類只接受逐層成立的證據；缺少證據不得推論弱點已消失。"""

from dataclasses import replace
from typing import cast

import pytest
from hypothesis import given
from hypothesis import strategies as st

from secscan.comparisons.domain.classification import (
    Classification,
    ComparisonFacts,
    CoverageEvidence,
    RuleEvidence,
    SourceRef,
    classify,
)

SOURCE = SourceRef(engine="zap", rule_id="40018", variant=None)
RULE = RuleEvidence(
    source=SOURCE,
    engine_succeeded=True,
    time_limit_reached=False,
    definition_comparable=True,
    has_location_response=True,
    rule_completed=True,
    parameter_comparable=True,
)
COVERED = CoverageEvidence(
    in_scope=True,
    role_comparable=True,
    identity_verified=True,
    spec_comparable=True,
    telemetry_complete=True,
    required_sources=(SOURCE,),
    sources=(RULE,),
)
BASELINE_ONLY = ComparisonFacts(
    baseline_observed=True,
    current_observed=False,
    fingerprint_comparable=True,
    mapping_comparable=True,
    finding_identity_verified=True,
    other_scan_coverage=COVERED,
    reidentified=False,
)


def test_all_evidence_is_required_for_not_observed() -> None:
    result = classify(BASELINE_ONLY)
    assert result.classification is Classification.NOT_OBSERVED
    assert result.reasons


@pytest.mark.parametrize(
    "evidence",
    [
        replace(COVERED, identity_verified=False),
        replace(COVERED, spec_comparable=False),
        replace(COVERED, telemetry_complete=False),
    ],
)
def test_missing_comparison_evidence_is_inconclusive(evidence: CoverageEvidence) -> None:
    result = classify(replace(BASELINE_ONLY, other_scan_coverage=evidence))
    assert result.classification is Classification.INCONCLUSIVE
    assert result.reasons


@pytest.mark.parametrize(
    "rule",
    [
        replace(RULE, engine_succeeded=False),
        replace(RULE, definition_comparable=False),
        replace(RULE, has_location_response=False),
        replace(RULE, rule_completed=False),
        replace(RULE, parameter_comparable=False),
    ],
)
def test_missing_rule_evidence_is_inconclusive(rule: RuleEvidence) -> None:
    evidence = replace(COVERED, sources=(rule,))
    result = classify(replace(BASELINE_ONLY, other_scan_coverage=evidence))
    assert result.classification is Classification.INCONCLUSIVE
    assert result.reasons


@pytest.mark.parametrize(
    "evidence", [replace(COVERED, in_scope=False), replace(COVERED, role_comparable=False)]
)
def test_scope_and_role_mismatches_are_not_comparable(evidence: CoverageEvidence) -> None:
    result = classify(replace(BASELINE_ONLY, other_scan_coverage=evidence))
    assert result.classification is Classification.NOT_COMPARABLE
    assert result.reasons


@pytest.mark.parametrize(
    "facts",
    [
        replace(BASELINE_ONLY, fingerprint_comparable=False),
        replace(BASELINE_ONLY, mapping_comparable=False),
    ],
)
def test_incompatible_versions_require_manual_review(facts: ComparisonFacts) -> None:
    result = classify(facts)
    assert result.classification is Classification.INCONCLUSIVE
    assert result.manual_review_required


def test_a_reached_time_limit_cannot_prove_a_negative() -> None:
    evidence = replace(COVERED, sources=(replace(RULE, time_limit_reached=True),))
    assert classify(replace(BASELINE_ONLY, other_scan_coverage=evidence)).classification is (
        Classification.INCONCLUSIVE
    )


def test_an_unverified_original_finding_cannot_prove_a_negative() -> None:
    result = classify(replace(BASELINE_ONLY, finding_identity_verified=False))
    assert result.classification is Classification.INCONCLUSIVE
    assert result.reasons


def test_no_sources_cannot_prove_a_negative() -> None:
    result = classify(replace(BASELINE_ONLY, other_scan_coverage=replace(COVERED, sources=())))
    assert result.classification is Classification.INCONCLUSIVE
    assert result.reasons


def test_one_unverified_source_prevents_a_negative() -> None:
    other = SourceRef(engine="nuclei", rule_id="sqli", variant=None)
    evidence = replace(
        COVERED,
        required_sources=(SOURCE, other),
        sources=(RULE, replace(RULE, source=other, engine_succeeded=False)),
    )
    assert classify(replace(BASELINE_ONLY, other_scan_coverage=evidence)).classification is (
        Classification.INCONCLUSIVE
    )


def test_coverage_of_an_unrelated_rule_cannot_prove_a_negative() -> None:
    other = SourceRef(engine="zap", rule_id="10020", variant=None)
    evidence = replace(COVERED, sources=(replace(RULE, source=other),))
    result = classify(replace(BASELINE_ONLY, other_scan_coverage=evidence))
    assert result.classification is Classification.INCONCLUSIVE
    assert result.reasons


def test_duplicate_source_cannot_hide_a_missing_source() -> None:
    other = SourceRef(engine="nuclei", rule_id="sqli", variant=None)
    evidence = replace(COVERED, required_sources=(SOURCE, other), sources=(RULE, RULE))
    assert classify(replace(BASELINE_ONLY, other_scan_coverage=evidence)).classification is (
        Classification.INCONCLUSIVE
    )


def test_both_observed_is_persistent_even_when_other_coverage_is_missing() -> None:
    facts = replace(BASELINE_ONLY, current_observed=True, other_scan_coverage=None)
    assert classify(facts).classification is Classification.PERSISTENT


def test_current_only_requires_baseline_coverage_to_be_new() -> None:
    facts = replace(BASELINE_ONLY, baseline_observed=False, current_observed=True)
    result = classify(facts)
    assert result.classification is Classification.NEW
    assert result.reasons
    assert classify(replace(facts, other_scan_coverage=None)).classification is (
        Classification.INCONCLUSIVE
    )


def test_reidentified_finding_requires_review() -> None:
    result = classify(replace(BASELINE_ONLY, reidentified=True))
    assert result.classification is Classification.INCONCLUSIVE
    assert result.manual_review_required


def test_reidentified_unverified_finding_still_requests_manual_review() -> None:
    facts = replace(BASELINE_ONLY, reidentified=True, finding_identity_verified=False)
    result = classify(facts)
    assert result.classification is Classification.INCONCLUSIVE
    assert result.manual_review_required


def test_absent_from_both_scans_is_invalid_input() -> None:
    with pytest.raises(ValueError, match="至少出現在一次"):
        classify(replace(BASELINE_ONLY, baseline_observed=False))


@given(
    st.booleans(),
    st.booleans(),
    st.booleans(),
    st.booleans(),
    st.booleans(),
    st.booleans(),
    st.booleans(),
    st.booleans(),
    st.booleans(),
    st.booleans(),
)
def test_not_observed_implies_every_evidence_layer(
    scope: bool,
    role: bool,
    identity: bool,
    spec: bool,
    telemetry: bool,
    engine: bool,
    definition: bool,
    response: bool,
    rule: bool,
    parameter: bool,
) -> None:
    coverage = CoverageEvidence(
        in_scope=scope,
        role_comparable=role,
        identity_verified=identity,
        spec_comparable=spec,
        telemetry_complete=telemetry,
        required_sources=(SOURCE,),
        sources=(RuleEvidence(SOURCE, engine, False, definition, response, rule, parameter),),
    )
    result = classify(replace(BASELINE_ONLY, other_scan_coverage=coverage))
    if result.classification is Classification.NOT_OBSERVED:
        assert all(
            (scope, role, identity, spec, telemetry, engine, definition, response, rule, parameter)
        )
    else:
        assert result.reasons


@pytest.mark.parametrize(
    "rule",
    [
        replace(RULE, engine_succeeded=cast(bool, None)),
        replace(RULE, definition_comparable=cast(bool, None)),
        replace(RULE, has_location_response=cast(bool, None)),
        replace(RULE, rule_completed=cast(bool, None)),
        replace(RULE, parameter_comparable=cast(bool, None)),
    ],
)
def test_unknown_source_evidence_cannot_be_treated_as_true(rule: RuleEvidence) -> None:
    evidence = replace(COVERED, sources=(rule,))
    assert classify(replace(BASELINE_ONLY, other_scan_coverage=evidence)).classification is not (
        Classification.NOT_OBSERVED
    )


def test_unknown_time_limit_is_not_assumed_clear() -> None:
    evidence = replace(COVERED, sources=(replace(RULE, time_limit_reached=None),))
    assert classify(replace(BASELINE_ONLY, other_scan_coverage=evidence)).classification is not (
        Classification.NOT_OBSERVED
    )


def test_truthy_non_boolean_coverage_is_not_proof() -> None:
    evidence = replace(COVERED, telemetry_complete=1)  # type: ignore[arg-type]
    result = classify(replace(BASELINE_ONLY, other_scan_coverage=evidence))
    assert result.classification is Classification.INCONCLUSIVE


def test_unknown_observation_state_is_not_assumed_absent() -> None:
    facts = replace(BASELINE_ONLY, current_observed=None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="觀察狀態"):
        classify(facts)


def test_unknown_reidentification_state_is_not_assumed_clear() -> None:
    facts = replace(BASELINE_ONLY, reidentified=None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="重新識別"):
        classify(facts)


def test_empty_source_identifier_cannot_prove_a_negative() -> None:
    bad = SourceRef(engine="", rule_id="", variant=None)
    evidence = replace(COVERED, required_sources=(bad,), sources=(replace(RULE, source=bad),))
    assert classify(replace(BASELINE_ONLY, other_scan_coverage=evidence)).classification is (
        Classification.INCONCLUSIVE
    )


@pytest.mark.parametrize(
    "evidence",
    [replace(COVERED, in_scope=None), replace(COVERED, role_comparable=None)],
)
def test_unknown_scope_or_role_is_inconclusive_not_a_confirmed_mismatch(
    evidence: CoverageEvidence,
) -> None:
    result = classify(replace(BASELINE_ONLY, other_scan_coverage=evidence))
    assert result.classification is Classification.INCONCLUSIVE
    assert result.reasons
