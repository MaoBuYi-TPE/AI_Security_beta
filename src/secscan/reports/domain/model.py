"""報告的快照模型（docs/DECISIONS.md §28.5）：worker 在 REPEATABLE READ READ ONLY transaction 中
讀出的值。只放白名單的欄位（不含 key id、storage_key、密文、lease、idempotency key 與複測摘錄）。

不可信的字串（target 名稱、finding 標題、規則、path、參數、樣本、人工輸入）在建立快照時已遮罩並
限制長度（document.py 的 clean），渲染時再依格式安全編碼（markdown.py、jsonfmt.py）。
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID

# 每份報告的內容上限（以 UTF-8 編碼後的位元組計；DB 的 CHECK 相同）。
MAX_REPORT_BYTES = 8_388_608
SCHEMA_VERSION = 1
# 每個 finding 最多的樣本數、報告中最多的比較快照數、每個不可信字串的長度上限。
MAX_SAMPLES = 3
MAX_COMPARISONS = 10
MAX_TEXT_LENGTH = 1000
MAX_ATTEMPTS = 3


class ReportFormat(StrEnum):
    JSON = "json"
    MARKDOWN = "markdown"


class ReportStatus(StrEnum):
    QUEUED = "queued"
    GENERATING = "generating"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


TERMINAL_REPORT_STATUSES = frozenset({ReportStatus.SUCCEEDED, ReportStatus.FAILED})
ACTIVE_REPORT_STATUSES = frozenset({ReportStatus.QUEUED, ReportStatus.GENERATING})


class ReportErrorCode(StrEnum):
    ATTEMPTS_EXHAUSTED = "REPORT_ATTEMPTS_EXHAUSTED"


@dataclass(frozen=True, slots=True)
class EngineRow:
    engine: str
    status: str
    error_code: str | None
    started_at: datetime | None
    finished_at: datetime | None


@dataclass(frozen=True, slots=True)
class ScanSection:
    id: UUID
    status: str
    profile: str
    fixture: bool
    results_complete: bool
    auth_role: str
    created_at: datetime
    finished_at: datetime | None
    target_name: str
    target_origin: str
    engines: tuple[EngineRow, ...]
    requests_sent: int | None
    requests_denied: int | None
    traffic_duration_seconds: int | None
    coverage_measured: bool
    eligible_operations: int | None
    ineligible_operations: int | None
    observed_operations: int | None
    authenticated_operations: int | None
    coverage_limitations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AuthorizationSection:
    grant_id: UUID
    grant_version: int
    approved_at: datetime | None
    valid_from: datetime
    valid_until: datetime
    authorization_reference: str


@dataclass(frozen=True, slots=True)
class SpecSection:
    id: UUID
    version: int
    openapi_version: str
    operation_count: int


@dataclass(frozen=True, slots=True)
class AuthSection:
    role: str
    profile_version: int | None
    preflight: str | None


@dataclass(frozen=True, slots=True)
class SourceRow:
    engine: str
    rule: str
    severity_label: str
    normalized_severity: str
    confidence_label: str
    observations: int


@dataclass(frozen=True, slots=True)
class Sample:
    path: str
    parameter: str | None
    evidence: str | None


@dataclass(frozen=True, slots=True)
class ResolutionSection:
    """resolved 的依據（一律是人工判定）；人工複測只有 metadata 與摘錄的雜湊。"""

    basis: str
    provenance: str
    decided_at: datetime
    decided_by_role: str | None
    comparison_id: UUID
    performed_at: str | None = None
    performed_by: str | None = None
    procedure: str | None = None
    request_excerpt_sha256: str | None = None
    request_excerpt_bytes: int | None = None
    response_excerpt_sha256: str | None = None
    response_excerpt_bytes: int | None = None
    checks_version: int | None = None
    platform_checks: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class FindingSection:
    id: UUID
    title: str
    kind: str
    category: str
    rule_group: str
    severity: str
    method: str
    route: str
    parameter_location: str | None
    parameter_name: str | None
    auth_role: str
    auth_verified: bool
    triage_state: str
    lifecycle_state: str
    triage_version: int
    resolution: ResolutionSection | None
    review_reasons: tuple[str, ...]
    sources: tuple[SourceRow, ...]
    distinct_paths: int
    samples: tuple[Sample, ...]


@dataclass(frozen=True, slots=True)
class ComparisonSection:
    id: UUID
    role: str
    other_scan_id: UUID
    comparability: str
    counts: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class ReportSnapshot:
    report_id: UUID
    format: ReportFormat
    data_as_of: datetime
    scan: ScanSection
    authorization: AuthorizationSection
    spec: SpecSection | None
    auth: AuthSection
    findings: tuple[FindingSection, ...]
    comparisons: tuple[ComparisonSection, ...]
