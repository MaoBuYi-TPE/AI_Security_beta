"""從實際保存的事實形成逐 finding 證據；沒有完成證明就不推論負面結論。"""

import hashlib
from collections.abc import Mapping, Sequence
from uuid import UUID

from secscan.comparisons.domain.classification import (
    Classification,
    ComparisonFacts,
    CoverageEvidence,
    RuleEvidence,
    classify,
)
from secscan.comparisons.domain.comparability import (
    Comparability,
    ScanComparison,
    ScanReason,
    compare_scans,
)
from secscan.comparisons.domain.facts import (
    Evaluation,
    FindingComparison,
    FindingFacts,
    FindingPresence,
    RunFacts,
    ScanEvidence,
    SourcePresence,
)
from secscan.comparisons.domain.reidentification import reidentified as find_reidentified
from secscan.grants.domain.scope import InvalidScopeError
from secscan.scans.domain.lifecycle import RunStatus

type AnswerIndex = Mapping[UUID, frozenset[tuple[str, str, bool]]]


def evaluate(
    baseline: ScanEvidence,
    current: ScanEvidence,
    findings: Sequence[FindingFacts],
    *,
    related: Mapping[str, frozenset[str]],
) -> Evaluation:
    comparison = compare_scans(baseline.scan, current.scan)
    reidentified = find_reidentified(baseline.scan.scan_id, current.scan.scan_id, findings, related)
    answers = {
        run.run_id: frozenset(
            (item.method, item.path_sha256, item.authenticated)
            for item in run.locations
            if item.answered
        )
        for scan in (baseline, current)
        for run in scan.runs
    }
    items = []
    for finding in findings:
        facts = _facts(baseline, current, finding, reidentified, comparison, answers)
        result = classify(facts)
        if comparison.comparability is Comparability.NOT_COMPARABLE:
            items.append(
                FindingComparison(
                    finding.finding_id,
                    Classification.NOT_COMPARABLE,
                    tuple(reason.value for reason in comparison.reasons),
                    comparison.manual_review_required,
                    facts,
                )
            )
        else:
            items.append(
                FindingComparison(
                    finding.finding_id,
                    result.classification,
                    tuple(reason.value for reason in result.reasons),
                    result.manual_review_required,
                    facts,
                )
            )
    return Evaluation(comparison, tuple(items))


def _facts(
    baseline: ScanEvidence,
    current: ScanEvidence,
    finding: FindingFacts,
    reidentified: frozenset[UUID],
    comparison: ScanComparison,
    answers: AnswerIndex,
) -> ComparisonFacts:
    before, after = _presence(finding, baseline), _presence(finding, current)
    coverage = None
    if before is None or after is None:
        observed, other = (baseline, current) if before is not None else (current, baseline)
        presence = before if before is not None else after
        if presence is not None:
            coverage = _coverage(finding, presence, observed, other, comparison, answers)
    return ComparisonFacts(
        baseline_observed=before is not None,
        current_observed=after is not None,
        fingerprint_comparable=ScanReason.FINGERPRINT not in comparison.reasons,
        mapping_comparable=(
            ScanReason.MAPPING not in comparison.reasons
            and _mapping_matches(finding, baseline, current)
        ),
        finding_identity_verified=finding.auth_verified,
        other_scan_coverage=coverage,
        reidentified=finding.finding_id in reidentified,
    )


def _mapping_matches(finding: FindingFacts, *scans: ScanEvidence) -> bool:
    for scan in scans:
        if (finding.mapping_version, finding.taxonomy_sha256) != (
            scan.scan.mapping_version,
            scan.scan.taxonomy_sha256,
        ):
            return False
        presence = _presence(finding, scan)
        if presence is None:
            continue
        runs = {run.run_id: run for run in scan.runs}
        for source in presence.sources:
            run = runs.get(source.run_id)
            if (
                run is None
                or (run.mapping_version, run.taxonomy_sha256)
                != (finding.mapping_version, finding.taxonomy_sha256)
                or source.link_taxonomy_sha256 != (finding.taxonomy_sha256,)
            ):
                return False
    return True


def _coverage(
    finding: FindingFacts,
    presence: FindingPresence,
    observed: ScanEvidence,
    other: ScanEvidence,
    comparison: ScanComparison,
    answers: AnswerIndex,
) -> CoverageEvidence:
    sources = tuple(
        _rule_evidence(finding, source, observed, other, answers) for source in presence.sources
    )
    runs = {run.engine: run for run in other.runs}
    relevant = tuple(runs.get(source.source.engine) for source in presence.sources)
    return CoverageEvidence(
        in_scope=_in_scope(finding, presence, observed, other),
        role_comparable=finding.auth_role == other.scan.auth_role,
        identity_verified=bool(relevant)
        and all(run is not None and run.identity_verified for run in relevant),
        spec_comparable=ScanReason.SPEC not in comparison.reasons,
        telemetry_complete=bool(relevant)
        and all(run is not None and run.locations_recorded for run in relevant),
        required_sources=tuple(source.source for source in presence.sources),
        sources=sources,
    )


def _rule_evidence(
    finding: FindingFacts,
    source: SourcePresence,
    observed: ScanEvidence,
    other: ScanEvidence,
    answers: AnswerIndex,
) -> RuleEvidence:
    original = next((run for run in observed.runs if run.run_id == source.run_id), None)
    counterpart = next((run for run in other.runs if run.engine == source.source.engine), None)
    return RuleEvidence(
        source=source.source,
        engine_succeeded=(
            counterpart is not None
            and counterpart.status is RunStatus.SUCCEEDED
            and counterpart.observations_complete
        ),
        time_limit_reached=counterpart.time_limit_reached if counterpart else None,
        definition_comparable=(
            original is not None
            and counterpart is not None
            and bool(original.definition_sha256)
            and original.definition_sha256 == counterpart.definition_sha256
        ),
        has_location_response=_answered(finding, source, counterpart, answers),
        # S1-S3 實測：單一 ZAP 規則請求、passive job 完成或 Nuclei false 事件都不足以證明完成。
        rule_completed=False,
        parameter_comparable=not finding.has_parameter,
    )


def _answered(
    finding: FindingFacts,
    source: SourcePresence,
    run: RunFacts | None,
    answers: AnswerIndex,
) -> bool:
    if run is None or not run.locations_recorded or not source.paths:
        return False
    responses = answers.get(run.run_id, frozenset())
    # 逐一核對原 scan 中實際觀察的物件，不拿同樣板另一個物件的回應代替。
    for path in source.paths:
        digest = hashlib.sha256(path.encode("utf-8")).hexdigest()
        if (finding.method, digest, True) in responses:
            continue
        if finding.auth_role != "anonymous" or (finding.method, digest, False) not in responses:
            return False
    return True


def _in_scope(
    finding: FindingFacts,
    presence: FindingPresence,
    observed: ScanEvidence,
    other: ScanEvidence,
) -> bool | None:
    if observed.origin != other.origin:
        return False
    paths = {path for source in presence.sources for path in source.paths}
    if not paths:
        return None
    try:
        return all(other.scope.classify(method=finding.method, path=path) is None for path in paths)
    except InvalidScopeError:
        return None


def _presence(finding: FindingFacts, scan: ScanEvidence) -> FindingPresence | None:
    return next((item for item in finding.appearances if item.scan_id == scan.scan.scan_id), None)
