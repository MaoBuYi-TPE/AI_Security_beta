"""報告單元測試的快照工廠：預設值是一個 fixture 掃描與一個 SQLi finding。"""

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from secscan.reports.domain.model import (
    AuthorizationSection,
    AuthSection,
    ComparisonSection,
    EngineRow,
    FindingSection,
    ReportFormat,
    ReportSnapshot,
    ResolutionSection,
    Sample,
    ScanSection,
    SourceRow,
)

NOW = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)
SCAN = ScanSection(
    id=UUID(int=1),
    status="partially_completed",
    profile="web_active_lab",
    fixture=True,
    results_complete=False,
    auth_role="anonymous",
    created_at=NOW,
    finished_at=NOW,
    target_name="fixture",
    target_origin="http://lab-fixture:8080",
    engines=(
        EngineRow("zap", "succeeded", None, NOW, NOW),
        EngineRow("nuclei", "failed", "ENGINE_REPORTED_ERRORS", NOW, NOW),
    ),
    requests_sent=120,
    requests_denied=3,
    traffic_duration_seconds=60,
    coverage_measured=False,
    eligible_operations=None,
    ineligible_operations=None,
    observed_operations=None,
    authenticated_operations=None,
    coverage_limitations=("no_spec",),
)
FINDING = FindingSection(
    id=UUID(int=2),
    title="SQL Injection",
    kind="security",
    category="vulnerability",
    rule_group="zap-sql-injection",
    severity="high",
    method="GET",
    route="/search",
    parameter_location="query",
    parameter_name="q",
    auth_role="anonymous",
    auth_verified=True,
    triage_state="unreviewed",
    lifecycle_state="open",
    triage_version=0,
    resolution=None,
    review_reasons=(),
    sources=(SourceRow("zap", "40018", "High", "high", "Medium", 2),),
    distinct_paths=1,
    samples=(Sample("/search?q=1", "q", "error near ' at line 1"),),
)
MANUAL = ResolutionSection(
    basis="manual_retest",
    provenance="operator_supplied",
    decided_at=NOW,
    decided_by_role="operator",
    comparison_id=UUID(int=9),
    performed_at=NOW.isoformat(),
    performed_by="lab operator",
    procedure="以單引號送出 q",
    request_excerpt_sha256="a" * 64,
    request_excerpt_bytes=40,
    response_excerpt_sha256="b" * 64,
    response_excerpt_bytes=20,
    checks_version=1,
    platform_checks=("request_line_matches_route",),
)


def snapshot(
    findings: tuple[FindingSection, ...] = (FINDING,),
    report_format: ReportFormat = ReportFormat.MARKDOWN,
    **changes: Any,
) -> ReportSnapshot:
    base = ReportSnapshot(
        report_id=UUID(int=3),
        format=report_format,
        data_as_of=NOW,
        scan=SCAN,
        authorization=AuthorizationSection(UUID(int=4), 2, NOW, NOW, NOW, "AUTH-2026-001"),
        spec=None,
        auth=AuthSection("anonymous", None, None),
        findings=findings,
        comparisons=(
            ComparisonSection(
                UUID(int=5), "baseline", UUID(int=6), "comparable", (("inconclusive", 1),)
            ),
        ),
    )
    return replace(base, **changes)


def finding(**changes: Any) -> FindingSection:
    return replace(FINDING, id=uuid4(), **changes)
