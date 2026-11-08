"""resolved 的雙軌證據資格：每個拒絕原因各有一個反例；inconclusive／not_observed 不會自動成立。"""

from dataclasses import replace

import pytest

from secscan.comparisons.domain.classification import (
    Classification,
    ComparisonFacts,
    CoverageEvidence,
    Reason,
    RuleEvidence,
    SourceRef,
)
from secscan.comparisons.domain.comparability import Comparability
from secscan.findings.domain.triage import ResolutionBasis
from secscan.triage.domain.evidence import (
    CitedComparison,
    ComparisonRow,
    EvidenceProblem,
    evidence_problems,
)

P = EvidenceProblem
MANUAL, RESCAN = ResolutionBasis.MANUAL_RETEST, ResolutionBasis.RESCAN_NOT_OBSERVED
SOURCE = SourceRef("zap", "40018", "40018")
RULE = RuleEvidence(
    source=SOURCE,
    engine_succeeded=True,
    time_limit_reached=False,
    definition_comparable=True,
    has_location_response=True,
    rule_completed=False,
    parameter_comparable=False,
)
COVERAGE = CoverageEvidence(
    in_scope=True,
    role_comparable=True,
    identity_verified=True,
    spec_comparable=True,
    telemetry_complete=True,
    required_sources=(SOURCE,),
    sources=(RULE,),
)
FACTS = ComparisonFacts(
    baseline_observed=True,
    current_observed=False,
    fingerprint_comparable=True,
    mapping_comparable=True,
    finding_identity_verified=True,
    other_scan_coverage=COVERAGE,
    reidentified=False,
)
ELIGIBLE = ComparisonRow(
    Classification.INCONCLUSIVE,
    (Reason.RULE_INCOMPLETE.value, Reason.PARAMETER_UNVERIFIED.value),
    False,
    FACTS,
)


def cited(row: ComparisonRow | None = ELIGIBLE, **changes: object) -> CitedComparison:
    base = CitedComparison(1, Comparability.COMPARABLE, row)
    return replace(base, **changes)  # type: ignore[arg-type]


def problems(
    basis: ResolutionBasis = MANUAL, comparison: CitedComparison | None = None, **kwargs: bool
) -> tuple[EvidenceProblem, ...]:
    return evidence_problems(
        basis, comparison or cited(), observed_after=kwargs.get("observed_after", False)
    )


def test_manual_retest_track_accepts_only_the_two_unverifiable_reasons() -> None:
    assert problems() == ()
    for reasons in ((Reason.RULE_INCOMPLETE.value,), (Reason.PARAMETER_UNVERIFIED.value,)):
        assert problems(comparison=cited(replace(ELIGIBLE, reasons=reasons))) == ()
    for extra in (Reason.LOCATION_UNANSWERED, Reason.ENGINE_INCOMPLETE, Reason.TIME_LIMIT_REACHED):
        row = replace(ELIGIBLE, reasons=(*ELIGIBLE.reasons, extra.value))
        assert P.REASONS_NOT_ELIGIBLE in problems(comparison=cited(row))
    assert P.REASONS_NOT_ELIGIBLE in problems(comparison=cited(replace(ELIGIBLE, reasons=())))


@pytest.mark.parametrize(
    "classification",
    [
        Classification.PERSISTENT,
        Classification.NEW,
        Classification.NOT_OBSERVED,
        Classification.NOT_COMPARABLE,
    ],
)
def test_manual_retest_requires_an_inconclusive_row(classification: Classification) -> None:
    row = replace(ELIGIBLE, classification=classification)
    assert P.INCONCLUSIVE_REQUIRED in problems(comparison=cited(row))


def test_rescan_track_requires_not_observed_and_is_unusable_with_v1_rows() -> None:
    # v1 的實際 producer 不會產生 not_observed：典型的 inconclusive 列在平台複掃這一軌被拒絕。
    assert problems(RESCAN) == (P.NOT_OBSERVED_REQUIRED,)
    not_observed = replace(
        ELIGIBLE, classification=Classification.NOT_OBSERVED, reasons=("coverage_verified",)
    )
    assert problems(RESCAN, cited(not_observed)) == ()
    assert problems(RESCAN, cited(not_observed), observed_after=True) == (
        P.OBSERVED_AFTER_COMPARISON,
    )


@pytest.mark.parametrize("basis", [MANUAL, RESCAN])
def test_common_conditions_apply_to_both_tracks(basis: ResolutionBasis) -> None:
    assert P.ALGORITHM_UNSUPPORTED in problems(basis, cited(algorithm_version=2))
    for comparability in (Comparability.DIFFERENT, Comparability.NOT_COMPARABLE):
        assert P.SCANS_NOT_COMPARABLE in problems(basis, cited(comparability=comparability))
    assert P.OBSERVED_AFTER_COMPARISON in problems(basis, observed_after=True)
    manual = cited(replace(ELIGIBLE, manual_review_required=True))
    assert P.MANUAL_REVIEW_REQUIRED in problems(basis, manual)
    assert problems(basis, cited(None)) == (P.FINDING_NOT_IN_COMPARISON,)


def _with_facts(**changes: object) -> CitedComparison:
    return cited(replace(ELIGIBLE, facts=replace(FACTS, **changes)))  # type: ignore[arg-type]


def _with_coverage(**changes: object) -> CitedComparison:
    return _with_facts(other_scan_coverage=replace(COVERAGE, **changes))  # type: ignore[arg-type]


def _with_rule(**changes: object) -> CitedComparison:
    return _with_coverage(sources=(replace(RULE, **changes),))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("comparison", "expected"),
    [
        (_with_facts(baseline_observed=False), P.BASELINE_NOT_OBSERVED),
        (_with_facts(current_observed=True), P.CURRENT_OBSERVED),
        (_with_facts(fingerprint_comparable=False), P.VERSION_INCOMPARABLE),
        (_with_facts(mapping_comparable=False), P.VERSION_INCOMPARABLE),
        (_with_facts(finding_identity_verified=False), P.FINDING_IDENTITY_UNVERIFIED),
        (_with_facts(reidentified=True), P.FINDING_IDENTITY_UNVERIFIED),
        (_with_facts(other_scan_coverage=None), P.COVERAGE_MISSING),
        (_with_coverage(in_scope=None), P.SCOPE_UNVERIFIED),
        (_with_coverage(in_scope=False), P.SCOPE_UNVERIFIED),
        (_with_coverage(role_comparable=None), P.ROLE_NOT_COMPARABLE),
        (_with_coverage(identity_verified=False), P.IDENTITY_UNVERIFIED),
        (_with_coverage(spec_comparable=False), P.SPEC_NOT_COMPARABLE),
        (_with_coverage(telemetry_complete=False), P.TELEMETRY_INCOMPLETE),
        (_with_coverage(sources=()), P.SOURCES_MISSING),
        (_with_coverage(required_sources=()), P.SOURCES_MISSING),
        (_with_coverage(required_sources=(SourceRef("zap", "1", None),)), P.SOURCES_MISSING),
        (_with_rule(engine_succeeded=False), P.ENGINE_INCOMPLETE),
        (_with_rule(time_limit_reached=True), P.TIME_LIMIT_REACHED),
        (_with_rule(time_limit_reached=None), P.TIME_LIMIT_REACHED),
        (_with_rule(definition_comparable=False), P.DEFINITION_NOT_COMPARABLE),
        (_with_rule(has_location_response=False), P.LOCATION_UNANSWERED),
    ],
)
def test_each_platform_fact_is_required_for_manual_retest(
    comparison: CitedComparison, expected: EvidenceProblem
) -> None:
    assert expected in problems(MANUAL, comparison)


def test_all_problems_are_listed_once_in_a_stable_order() -> None:
    broken = _with_rule(engine_succeeded=False, has_location_response=False)
    first = problems(MANUAL, replace(broken, comparability=Comparability.DIFFERENT))
    assert first == (P.SCANS_NOT_COMPARABLE, P.ENGINE_INCOMPLETE, P.LOCATION_UNANSWERED)
    assert len(set(first)) == len(first)
