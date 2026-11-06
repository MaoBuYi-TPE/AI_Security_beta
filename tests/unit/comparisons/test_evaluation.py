"""由凍結事實建立比較：端點回應、歸屬訊號不能證明規則已完成。"""

import hashlib
from dataclasses import replace
from uuid import uuid4

import pytest

from secscan.comparisons.domain.classification import Classification, SourceRef
from secscan.comparisons.domain.comparability import ScanFacts
from secscan.comparisons.domain.evaluation import evaluate
from secscan.comparisons.domain.facts import (
    FindingFacts,
    FindingPresence,
    LocationFact,
    RunFacts,
    ScanEvidence,
    SourcePresence,
)
from secscan.findings.domain.fingerprint import RouteSource
from secscan.grants.domain.matching import ScopeRules
from secscan.scans.domain.lifecycle import RunStatus, ScanStatus

PROJECT, TARGET, FINDING = uuid4(), uuid4(), uuid4()
MAPPING = "rules-2+owasp2025-0123456789ab+norm-1+fp-2"
SOURCE = SourceRef("zap", "40018", "40018")


def scan(position: int) -> ScanEvidence:
    run = RunFacts(
        run_id=uuid4(),
        engine="zap",
        status=RunStatus.SUCCEEDED,
        definition_sha256="a" * 64,
        mapping_version=MAPPING,
        taxonomy_sha256="b" * 64,
        identity_verified=True,
        time_limit_reached=False,
        locations_recorded=True,
        locations=(LocationFact("GET", hashlib.sha256(b"/search").hexdigest(), True, False),),
    )
    return ScanEvidence(
        scan=ScanFacts(
            scan_id=uuid4(),
            project_id=PROJECT,
            target_id=TARGET,
            queue_position=position,
            status=ScanStatus.COMPLETED,
            fixture=False,
            profile="web_active_lab",
            scope_sha256="c" * 64,
            has_spec=False,
            spec_sha256=None,
            auth_role="anonymous",
            definitions=(("zap", "a" * 64),),
            fingerprint_version="2",
            mapping_version=MAPPING,
            taxonomy_sha256="b" * 64,
        ),
        origin="http://fixture:8000",
        scope=ScopeRules((), True, (), frozenset({"GET"})),
        runs=(run,),
    )


def finding(baseline: ScanEvidence, current: ScanEvidence | None = None) -> FindingFacts:
    def presence(scan: ScanEvidence) -> FindingPresence:
        return FindingPresence(
            scan.scan.scan_id,
            (SourcePresence(SOURCE, scan.runs[0].run_id, ("/search",), ("b" * 64,)),),
        )

    return FindingFacts(
        finding_id=FINDING,
        rule_group="zap-sql-injection",
        method="GET",
        route="/search",
        route_source=RouteSource.LITERAL,
        resource=None,
        auth_role="anonymous",
        auth_verified=True,
        has_parameter=True,
        mapping_version=MAPPING,
        taxonomy_sha256="b" * 64,
        appearances=(presence(baseline),) + ((presence(current),) if current else ()),
    )


def test_answered_endpoint_and_successful_engine_are_not_completion_proof() -> None:
    baseline, current = scan(1), scan(2)
    result = evaluate(baseline, current, (finding(baseline),), related={})
    [item] = result.findings
    assert item.classification is Classification.INCONCLUSIVE
    assert "rule_incomplete" in item.reasons
    assert "parameter_unverified" in item.reasons
    assert item.evidence.other_scan_coverage is not None
    assert item.evidence.other_scan_coverage.sources[0].has_location_response
    assert not item.evidence.other_scan_coverage.sources[0].rule_completed


def test_both_observations_are_persistent_without_negative_coverage() -> None:
    baseline, current = scan(1), scan(2)
    current = replace(current, runs=(replace(current.runs[0], locations_recorded=False),))
    [item] = evaluate(baseline, current, (finding(baseline, current),), related={}).findings
    assert item.classification is Classification.PERSISTENT


def test_one_missing_source_cannot_be_hidden_by_another_source() -> None:
    baseline, current = scan(1), scan(2)
    item = finding(baseline)
    original = replace(baseline.runs[0], run_id=uuid4(), engine="nuclei")
    baseline = replace(baseline, runs=(*baseline.runs, original))
    extra = SourcePresence(
        SourceRef("nuclei", "sqli", None), original.run_id, ("/search",), ("b" * 64,)
    )
    item = replace(
        item,
        appearances=(replace(item.appearances[0], sources=(*item.appearances[0].sources, extra)),),
    )
    [result] = evaluate(baseline, current, (item,), related={}).findings
    assert result.classification is Classification.INCONCLUSIVE
    assert "engine_incomplete" in result.reasons


def test_scope_reduction_is_not_comparable() -> None:
    baseline, current = scan(1), scan(2)
    current = replace(current, scope=ScopeRules((), True, (), frozenset({"POST"})))
    [item] = evaluate(baseline, current, (finding(baseline),), related={}).findings
    assert item.classification is Classification.NOT_COMPARABLE
    assert "out_of_scope" in item.reasons


def test_link_mapping_mismatch_requires_review_even_when_both_observed() -> None:
    baseline, current = scan(1), scan(2)
    item = finding(baseline, current)
    source = replace(item.appearances[1].sources[0], link_taxonomy_sha256=("d" * 64,))
    item = replace(
        item, appearances=(item.appearances[0], replace(item.appearances[1], sources=(source,)))
    )
    [result] = evaluate(baseline, current, (item,), related={}).findings
    assert result.classification is Classification.INCONCLUSIVE
    assert result.manual_review_required


def test_related_one_sided_findings_at_same_location_require_review() -> None:
    baseline, current = scan(1), scan(2)
    before = finding(baseline)
    after = replace(finding(current), finding_id=uuid4(), rule_group="nuclei-sqli")
    result = evaluate(
        baseline,
        current,
        (before, after),
        related={"zap-sql-injection": frozenset({"nuclei-sqli"})},
    )
    assert all(item.manual_review_required for item in result.findings)
    assert all("reidentified" in item.reasons for item in result.findings)


def test_locations_are_indexed_once_instead_of_scanned_for_every_finding() -> None:
    from collections.abc import Iterator

    class CountedLocations(tuple[LocationFact, ...]):
        iterations = 0

        def __iter__(self) -> Iterator[LocationFact]:
            type(self).iterations += 1
            return super().__iter__()

    baseline, current = scan(1), scan(2)
    current = replace(
        current,
        runs=(replace(current.runs[0], locations=CountedLocations(current.runs[0].locations)),),
    )
    findings = tuple(replace(finding(baseline), finding_id=uuid4()) for _ in range(64))
    evaluate(baseline, current, findings, related={})
    assert CountedLocations.iterations <= 2


@pytest.mark.parametrize("field", ["fixture", "profile"])
def test_incompatible_scan_profiles_override_finding_presence(field: str) -> None:
    baseline, current = scan(1), scan(2)
    changed = (
        replace(current.scan, fixture=True)
        if field == "fixture"
        else replace(current.scan, profile="api_active_lab")
    )
    current = replace(current, scan=changed)
    [item] = evaluate(baseline, current, (finding(baseline, current),), related={}).findings
    assert item.classification is Classification.NOT_COMPARABLE
    assert item.reasons


@pytest.mark.parametrize(
    ("status", "limit", "complete", "reason"),
    [
        (RunStatus.FAILED, False, True, "engine_incomplete"),
        (RunStatus.TIMED_OUT, True, True, "time_limit_reached"),
        (RunStatus.SUCCEEDED, None, True, "time_limit_reached"),
        (RunStatus.SUCCEEDED, False, False, "engine_incomplete"),
    ],
)
def test_failed_or_incomplete_runs_never_prove_absence(
    status: RunStatus,
    limit: bool | None,
    complete: bool,
    reason: str,
) -> None:
    baseline, current = scan(1), scan(2)
    current = replace(
        current,
        runs=(
            replace(
                current.runs[0],
                status=status,
                time_limit_reached=limit,
                observations_complete=complete,
            ),
        ),
    )
    [item] = evaluate(baseline, current, (finding(baseline),), related={}).findings
    assert item.classification is Classification.INCONCLUSIVE
    assert reason in item.reasons


def test_a_different_object_under_the_same_template_is_not_location_coverage() -> None:
    baseline, current = scan(1), scan(2)
    item = finding(baseline)
    source = replace(item.appearances[0].sources[0], paths=("/items/1", "/items/2"))
    item = replace(
        item,
        route="/items/{id}",
        route_source=RouteSource.OPENAPI,
        appearances=(replace(item.appearances[0], sources=(source,)),),
    )
    location = LocationFact("GET", hashlib.sha256(b"/items/1").hexdigest(), True, False)
    current = replace(current, runs=(replace(current.runs[0], locations=(location,)),))
    [result] = evaluate(baseline, current, (item,), related={}).findings
    assert "location_unanswered" in result.reasons
    assert result.classification is Classification.INCONCLUSIVE


@pytest.mark.parametrize("authenticated", [True, False])
def test_authenticated_findings_require_an_authenticated_location_response(
    authenticated: bool,
) -> None:
    baseline, current = scan(1), scan(2)
    baseline = replace(baseline, scan=replace(baseline.scan, auth_role="standard_user"))
    current = replace(
        current,
        scan=replace(current.scan, auth_role="standard_user"),
        runs=(
            replace(
                current.runs[0],
                locations=(replace(current.runs[0].locations[0], authenticated=authenticated),),
            ),
        ),
    )
    item = replace(finding(baseline), auth_role="standard_user")
    [result] = evaluate(baseline, current, (item,), related={}).findings
    assert ("location_unanswered" not in result.reasons) is authenticated
    assert result.classification is Classification.INCONCLUSIVE


@pytest.mark.parametrize(
    ("paths", "reason"), [((), "scope_unknown"), (("invalid-path",), "scope_unknown")]
)
def test_unknown_original_paths_are_not_claimed_out_of_scope(
    paths: tuple[str, ...], reason: str
) -> None:
    baseline, current = scan(1), scan(2)
    item = finding(baseline)
    source = replace(item.appearances[0].sources[0], paths=paths)
    item = replace(item, appearances=(replace(item.appearances[0], sources=(source,)),))
    [result] = evaluate(baseline, current, (item,), related={}).findings
    assert result.classification is Classification.INCONCLUSIVE
    assert reason in result.reasons


def test_different_origins_are_outside_the_comparison_scope() -> None:
    baseline, current = scan(1), scan(2)
    current = replace(current, origin="http://different:8000")
    [result] = evaluate(baseline, current, (finding(baseline),), related={}).findings
    assert "out_of_scope" in result.reasons


def test_missing_mapping_cannot_prove_persistent_or_not_observed() -> None:
    baseline, current = scan(1), scan(2)
    current = replace(current, scan=replace(current.scan, taxonomy_sha256=None))
    [result] = evaluate(baseline, current, (finding(baseline, current),), related={}).findings
    assert result.manual_review_required
    assert result.classification is Classification.INCONCLUSIVE


def test_no_appearance_is_invalid_not_new() -> None:
    baseline, current = scan(1), scan(2)
    with pytest.raises(ValueError, match="至少出現在一次"):
        evaluate(baseline, current, (replace(finding(baseline), appearances=()),), related={})


@pytest.mark.parametrize("digest", [None, "d" * 64])
@pytest.mark.parametrize("has_finding", [False, True])
def test_scan_summary_includes_unknown_or_changed_taxonomy_even_without_findings(
    digest: str | None, has_finding: bool
) -> None:
    from secscan.comparisons.domain.comparability import Comparability, ScanReason

    baseline, current = scan(1), scan(2)
    current = replace(current, scan=replace(current.scan, taxonomy_sha256=digest))
    findings = (finding(baseline, current),) if has_finding else ()
    result = evaluate(baseline, current, findings, related={})
    assert result.scans.comparability is Comparability.DIFFERENT
    assert result.scans.reasons == (ScanReason.MAPPING,)
    assert result.scans.manual_review_required
    for item in result.findings:
        assert item.classification is Classification.INCONCLUSIVE
        assert item.manual_review_required
        assert item.reasons == ("mapping_version_mismatch",)
