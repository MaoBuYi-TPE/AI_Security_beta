"""報告的投影（docs/DECISIONS.md §28.5）。純函式。

快照（frozen dataclass）→ 固定鍵順序的白名單文件；每個不可信的字串在這裡再遮罩一次（L2：
redact_url／redact_text、display_text，長度上限 MAX_TEXT_LENGTH）。摘要的計數一律以全部 finding
計算；需要人工確認的 resolved 另外計數、不算 resolved。渲染與大小上限在 render.py。
"""

from collections import Counter
from collections.abc import Sequence
from datetime import datetime

from secscan.core.json_types import JsonObject, JsonValue
from secscan.core.text import display_text
from secscan.findings.domain.model import LifecycleState, TriageState
from secscan.findings.domain.normalization import Severity
from secscan.findings.domain.taxonomy import FindingKind
from secscan.findings.domain.triage import EvidenceProvenance
from secscan.reports.domain import wording
from secscan.reports.domain.model import (
    MAX_TEXT_LENGTH,
    SCHEMA_VERSION,
    FindingSection,
    ReportSnapshot,
    ResolutionSection,
)
from secscan.security.redaction import redact_text, redact_url

_TERMINAL_COMPLETE = "completed"
REVIEW_BUCKET = "resolved_review_required"


def clean(value: str | None) -> str | None:
    """不可信的文字：換掉控制字元、遮罩已知的秘密樣式、最後才限制長度。

    先遮罩再截斷（安全審查 L7）：先截斷會切開秘密，剩下的半截不再符合遮罩的樣式。輸入來自 DB，
    各欄位本身有長度上限。
    """
    if value is None:
        return None
    return _shorten(redact_text(_displayable(value)))


def clean_path(value: str) -> str:
    return _shorten(redact_url(_displayable(value)))


def _displayable(value: str) -> str:
    return display_text(value, max_length=len(value))[0]


def _shorten(masked: str) -> str:
    return masked if len(masked) <= MAX_TEXT_LENGTH else masked[:MAX_TEXT_LENGTH] + "…"


def project_findings(snapshot: ReportSnapshot) -> tuple[JsonObject, ...]:
    """每個 finding 的投影（遮罩、清理）；render 只做一次，截斷時重複使用。"""
    return tuple(_finding(item) for item in snapshot.findings)


def document(
    snapshot: ReportSnapshot,
    generated_at: datetime,
    count: int,
    *,
    projected: Sequence[JsonObject] | None = None,
) -> JsonObject:
    """JSON 的文件（鍵的順序固定；只有白名單的欄位）。projected 是 project_findings 的結果。"""
    omitted = len(snapshot.findings) - count
    findings: list[JsonValue] = (
        list(projected[:count])
        if projected is not None
        else [_finding(item) for item in snapshot.findings[:count]]
    )
    scan = snapshot.scan
    return {
        "schema_version": SCHEMA_VERSION,
        "report_id": str(snapshot.report_id),
        "format": snapshot.format.value,
        "generated_at": generated_at.isoformat(),
        "data_as_of": snapshot.data_as_of.isoformat(),
        "notices": list(_notices(snapshot, omitted)),
        "scan": {
            "id": str(scan.id),
            "status": scan.status,
            "results_complete": scan.results_complete,
            "fixture": scan.fixture,
            "profile": scan.profile,
            "auth_role": clean(scan.auth_role),
            "created_at": scan.created_at.isoformat(),
            "finished_at": _iso(scan.finished_at),
            "target_name": clean(scan.target_name),
            "target_origin": clean_path(scan.target_origin),
            "budget_usage": {
                "requests_sent": scan.requests_sent,
                "requests_denied": scan.requests_denied,
                "traffic_duration_seconds": scan.traffic_duration_seconds,
            },
        },
        "authorization": _authorization(snapshot),
        "spec": _spec(snapshot),
        "authentication": {
            "role": clean(snapshot.auth.role),
            "profile_version": snapshot.auth.profile_version,
            "preflight": snapshot.auth.preflight,
        },
        "engines": [
            {
                "engine": run.engine,
                "status": run.status,
                "error_code": run.error_code,
                "started_at": _iso(run.started_at),
                "finished_at": _iso(run.finished_at),
            }
            for run in scan.engines
        ],
        "coverage": {
            "coverage_measured": scan.coverage_measured,
            "eligible_operations": scan.eligible_operations,
            "ineligible_operations": scan.ineligible_operations,
            "observed_operations": scan.observed_operations,
            "authenticated_operations": scan.authenticated_operations,
            "limitations": list(scan.coverage_limitations),
        },
        "summary": summary(snapshot.findings),
        "findings": findings,
        "comparisons": [
            {
                "id": str(item.id),
                "role": item.role,
                "other_scan_id": str(item.other_scan_id),
                "comparability": item.comparability,
                "counts": dict(item.counts),
                "notice": wording.COMPARISON_NOTICE,
            }
            for item in snapshot.comparisons
        ],
        "truncation": {
            "truncated": omitted > 0,
            "omitted_findings": omitted,
            "notice": wording.TRUNCATED_NOTICE.format(omitted=omitted) if omitted else None,
            "comparisons_omitted": snapshot.comparisons_omitted,
        },
    }


def summary(findings: Sequence[FindingSection]) -> JsonObject:
    """全部 finding 的計數（不因截斷而變少）；resolved 依依據分開，需要人工確認的不算 resolved。"""
    review = [item for item in findings if item.review_reasons]
    resolved = [
        item
        for item in findings
        if item.lifecycle_state == LifecycleState.RESOLVED.value and not item.review_reasons
    ]
    provenance = Counter(item.resolution.provenance for item in resolved if item.resolution)
    return {
        "findings_total": len(findings),
        "by_severity": _counts(findings, "severity", [s.value for s in reversed(Severity)]),
        "by_kind": _counts(findings, "kind", [kind.value for kind in FindingKind]),
        "by_triage": _counts(findings, "triage_state", [state.value for state in TriageState]),
        "by_lifecycle": _lifecycle_counts(findings),
        "resolved_operator_supplied": provenance[EvidenceProvenance.OPERATOR_SUPPLIED.value],
        "resolved_platform_comparison": provenance[EvidenceProvenance.PLATFORM_COMPARISON.value],
        "resolved_review_required": len(review),
    }


def _lifecycle_counts(findings: Sequence[FindingSection]) -> JsonObject:
    """需要人工確認的 resolved 另列一桶，不算進 resolved（wording.REVIEW_LABEL）。"""
    counted = Counter(
        REVIEW_BUCKET
        if item.lifecycle_state == LifecycleState.RESOLVED.value and item.review_reasons
        else item.lifecycle_state
        for item in findings
    )
    keys = [state.value for state in LifecycleState] + [REVIEW_BUCKET]
    return {key: counted[key] for key in keys}


def _counts(findings: Sequence[FindingSection], field: str, keys: list[str]) -> JsonObject:
    counted = Counter(getattr(item, field) for item in findings)
    return {key: counted[key] for key in keys}


def _notices(snapshot: ReportSnapshot, omitted: int) -> tuple[str, ...]:
    notices = list(wording.NOTICES)
    if snapshot.scan.fixture:
        notices.append(wording.FIXTURE_NOTICE)
    if snapshot.scan.status != _TERMINAL_COMPLETE or not snapshot.scan.results_complete:
        notices.append(wording.INCOMPLETE_NOTICE.format(status=snapshot.scan.status))
    else:
        notices.append(wording.COMPLETION_NOTICE)
    if not snapshot.scan.coverage_measured:
        notices.append(wording.COVERAGE_UNMEASURED_NOTICE)
    if omitted:
        notices.append(wording.TRUNCATED_NOTICE.format(omitted=omitted))
    notices.append(wording.UNTRUSTED_NOTICE)
    return tuple(notices)


def _authorization(snapshot: ReportSnapshot) -> JsonObject:
    grant = snapshot.authorization
    return {
        "grant_id": str(grant.grant_id),
        "grant_version": grant.grant_version,
        "approved_at": _iso(grant.approved_at),
        "valid_from": grant.valid_from.isoformat(),
        "valid_until": grant.valid_until.isoformat(),
        "authorization_reference": clean(grant.authorization_reference),
    }


def _spec(snapshot: ReportSnapshot) -> JsonObject | None:
    spec = snapshot.spec
    if spec is None:
        return None
    return {
        "id": str(spec.id),
        "version": spec.version,
        "openapi_version": clean(spec.openapi_version),
        "operation_count": spec.operation_count,
    }


def _finding(item: FindingSection) -> JsonObject:
    return {
        "id": str(item.id),
        "title": clean(item.title),
        "kind": item.kind,
        "category": item.category,
        "rule_group": clean(item.rule_group),
        "severity": item.severity,
        "location": {
            "method": item.method,
            "route": clean_path(item.route),
            "parameter_location": item.parameter_location,
            "parameter_name": clean(item.parameter_name),
        },
        "auth_role": clean(item.auth_role),
        "auth_verified": item.auth_verified,
        "triage_state": item.triage_state,
        "triage_label": wording.TRIAGE_LABELS[item.triage_state],
        "lifecycle_state": item.lifecycle_state,
        "lifecycle_label": wording.LIFECYCLE_LABELS[item.lifecycle_state],
        "triage_version": item.triage_version,
        "resolution": _resolution(item.resolution) if item.resolution is not None else None,
        "resolution_review_required": bool(item.review_reasons),
        "resolution_review_reasons": list(item.review_reasons),
        "review_label": wording.REVIEW_LABEL if item.review_reasons else None,
        "sources": [
            {
                "engine": source.engine,
                "rule": clean(source.rule),
                "severity_label": clean(source.severity_label),
                "normalized_severity": source.normalized_severity,
                "confidence_label": clean(source.confidence_label),
                "observations": source.observations,
            }
            for source in item.sources
        ],
        "multiple_sources_note": (
            wording.MULTIPLE_SOURCES_LABEL if len({s.engine for s in item.sources}) > 1 else None
        ),
        "distinct_paths": item.distinct_paths,
        "samples": [
            {
                "path": clean_path(sample.path),
                "parameter": clean(sample.parameter),
                "evidence": clean(sample.evidence),
            }
            for sample in item.samples
        ],
    }


def _resolution(resolution: ResolutionSection) -> JsonObject:
    attestation: JsonValue = None
    if resolution.request_excerpt_sha256 is not None:
        attestation = {
            "performed_at": resolution.performed_at,
            "performed_by": clean(resolution.performed_by),
            "procedure": clean(resolution.procedure),
            "request_excerpt_sha256": resolution.request_excerpt_sha256,
            "request_excerpt_bytes": resolution.request_excerpt_bytes,
            "response_excerpt_sha256": resolution.response_excerpt_sha256,
            "response_excerpt_bytes": resolution.response_excerpt_bytes,
            "checks_version": resolution.checks_version,
            "platform_checks": list(resolution.platform_checks),
        }
    return {
        "basis": resolution.basis,
        "basis_label": wording.BASIS_LABELS[resolution.basis],
        "evidence_provenance": resolution.provenance,
        "decided_at": resolution.decided_at.isoformat(),
        "decided_by_role": resolution.decided_by_role,
        "comparison_id": str(resolution.comparison_id),
        "attestation": attestation,
    }


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None
