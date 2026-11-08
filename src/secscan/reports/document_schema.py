"""JSON 報告的 schema（schema_version 1；docs/DECISIONS.md §28.5）。

每一層都是 extra="forbid"：投影多出任何欄位（例如 key id、storage_key、複測摘錄）都會失敗。worker
儲存 JSON 報告前以它驗證；tests/contract 以它產生的 JSON Schema 和 golden 快照比對，schema 改變
必須經過審查，不擅自更新。
"""

from pydantic import BaseModel, ConfigDict


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class BudgetUsageDoc(_Strict):
    requests_sent: int | None
    requests_denied: int | None
    traffic_duration_seconds: int | None


class ScanDoc(_Strict):
    id: str
    status: str
    results_complete: bool
    fixture: bool
    profile: str
    auth_role: str | None
    created_at: str
    finished_at: str | None
    target_name: str | None
    target_origin: str
    budget_usage: BudgetUsageDoc


class AuthorizationDoc(_Strict):
    grant_id: str
    grant_version: int
    approved_at: str | None
    valid_from: str
    valid_until: str
    authorization_reference: str | None


class SpecDoc(_Strict):
    id: str
    version: int
    openapi_version: str | None
    operation_count: int


class AuthenticationDoc(_Strict):
    role: str | None
    profile_version: int | None
    preflight: str | None


class EngineDoc(_Strict):
    engine: str
    status: str
    error_code: str | None
    started_at: str | None
    finished_at: str | None


class CoverageDoc(_Strict):
    coverage_measured: bool
    eligible_operations: int | None
    ineligible_operations: int | None
    observed_operations: int | None
    authenticated_operations: int | None
    limitations: list[str]


class SummaryDoc(_Strict):
    findings_total: int
    by_severity: dict[str, int]
    by_kind: dict[str, int]
    by_triage: dict[str, int]
    by_lifecycle: dict[str, int]
    resolved_operator_supplied: int
    resolved_platform_comparison: int
    resolved_review_required: int


class LocationDoc(_Strict):
    method: str
    route: str
    parameter_location: str | None
    parameter_name: str | None


class AttestationDoc(_Strict):
    performed_at: str | None
    performed_by: str | None
    procedure: str | None
    request_excerpt_sha256: str | None
    request_excerpt_bytes: int | None
    response_excerpt_sha256: str | None
    response_excerpt_bytes: int | None
    checks_version: int | None
    platform_checks: list[str]


class ResolutionDoc(_Strict):
    basis: str
    basis_label: str
    evidence_provenance: str
    decided_at: str
    decided_by_role: str | None
    comparison_id: str
    attestation: AttestationDoc | None


class SourceDoc(_Strict):
    engine: str
    rule: str | None
    severity_label: str | None
    normalized_severity: str
    confidence_label: str | None
    observations: int


class SampleDoc(_Strict):
    path: str
    parameter: str | None
    evidence: str | None


class FindingDoc(_Strict):
    id: str
    title: str | None
    kind: str
    category: str
    rule_group: str | None
    severity: str
    location: LocationDoc
    auth_role: str | None
    auth_verified: bool
    triage_state: str
    triage_label: str
    lifecycle_state: str
    lifecycle_label: str
    triage_version: int
    resolution: ResolutionDoc | None
    resolution_review_required: bool
    resolution_review_reasons: list[str]
    review_label: str | None
    sources: list[SourceDoc]
    multiple_sources_note: str | None
    distinct_paths: int
    samples: list[SampleDoc]


class ComparisonDoc(_Strict):
    id: str
    role: str
    other_scan_id: str
    comparability: str
    counts: dict[str, int]
    notice: str


class TruncationDoc(_Strict):
    truncated: bool
    omitted_findings: int
    notice: str | None
    # 最多列出最新的 10 份比較快照；省略的較舊份數。
    comparisons_omitted: int


class ReportDocumentV1(_Strict):
    schema_version: int
    report_id: str
    format: str
    generated_at: str
    data_as_of: str
    notices: list[str]
    scan: ScanDoc
    authorization: AuthorizationDoc
    spec: SpecDoc | None
    authentication: AuthenticationDoc
    engines: list[EngineDoc]
    coverage: CoverageDoc
    summary: SummaryDoc
    findings: list[FindingDoc]
    comparisons: list[ComparisonDoc]
    truncation: TruncationDoc
