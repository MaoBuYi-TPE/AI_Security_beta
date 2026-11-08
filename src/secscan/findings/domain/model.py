"""finding 的 domain model（docs/DECISIONS.md §25.8；ARCHITECTURE.md §10）。

finding 是 target 層級、跨掃描的議題；observation 是不可變的單次觀察，兩者不互相取代。人工 triage
與生命週期和工具的等級、信心分開（T21 才能修改，這裡只有初始值）。
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from secscan.findings.domain.fingerprint import RouteSource
from secscan.findings.domain.normalization import Confidence, Severity
from secscan.findings.domain.taxonomy import CweSource, FindingCategory, FindingKind
from secscan.scans.domain.catalog import Engine


class TriageState(StrEnum):
    UNREVIEWED = "unreviewed"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class LifecycleState(StrEnum):
    OPEN = "open"
    RESOLVED = "resolved"
    REOPENED = "reopened"


class UnmappedReason(StrEnum):
    """OWASP 沒有對應的原因（使用者簽核：明確交代未對應的項目，§25.14）。"""

    # 群組或工具都沒有 CWE。
    NO_CWE = "no_cwe"
    # 有 CWE，但官方的 Top 10:2025 清單沒有它（例如 CWE-264 是分類節點）。
    CWE_NOT_LISTED = "cwe_not_listed"
    # API Security Top 10:2023 只來自審查過的 curated 對應；這個群組（或 fallback）沒有。
    NOT_CURATED = "not_curated"


def top10_unmapped_reason(cwe_id: int | None, category: str | None) -> UnmappedReason | None:
    if category is not None:
        return None
    return UnmappedReason.NO_CWE if cwe_id is None else UnmappedReason.CWE_NOT_LISTED


def api_unmapped_reason(category: str | None) -> UnmappedReason | None:
    return None if category is not None else UnmappedReason.NOT_CURATED


class MappingSource(StrEnum):
    """OWASP 對應的來源：Top 10:2025 是官方 CWE 清單，API 2023 是 curated 表，none 是沒有對應。"""

    OFFICIAL = "official"
    CURATED = "curated"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class FindingSource:
    """這個 scan 中同一個來源（引擎、規則、variant 與原值都相同）的觀察數。"""

    engine: Engine
    source_rule: str
    rule_variant: str | None
    raw_severity: str
    severity_label: str
    normalized_severity: Severity
    raw_confidence: str
    confidence_label: str
    normalized_confidence: Confidence
    cwe_id: int | None
    observations: int


@dataclass(frozen=True, slots=True)
class Finding:
    id: UUID
    target_id: UUID
    kind: FindingKind
    category: FindingCategory
    rule_group: str
    title: str
    method: str
    route: str
    route_source: RouteSource
    parameter_location: str | None
    parameter_name: str | None
    resource: str | None
    auth_role: str
    auth_verified: bool
    normalized_severity: Severity
    severity_conflict: bool
    needs_review: bool
    cwe_id: int | None
    cwe_source: CweSource | None
    owasp_top10_2025: str | None
    owasp_top10_2025_source: MappingSource
    owasp_api_2023: str | None
    owasp_api_2023_source: MappingSource
    mapping_version: str
    triage_state: TriageState
    lifecycle_state: LifecycleState
    first_seen_scan_id: UUID
    last_seen_scan_id: UUID
    created_at: datetime
    last_seen_at: datetime
    # 只有查詢的那個 scan 中的來源（GET /scans/{id}/findings）。
    sources: tuple[FindingSource, ...] = ()
    # 同一次 scan、同一個位置、taxonomy 標示為相關的 finding（只標示，不合併）。
    related_finding_ids: tuple[UUID, ...] = ()
    # T21：每次 triage 或 lifecycle 變更 +1（PATCH 的 expected_version）。
    triage_version: int = 0
    # resolved 之後平台無法自動判斷是否復發的原因（triage.ReviewReason 的值）；空的代表不需要。
    resolution_review: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class FindingFilters:
    kind: FindingKind | None = None
    severity: Severity | None = None
    engine: Engine | None = None
    triage_state: TriageState | None = None
    category: FindingCategory | None = None
    needs_review: bool | None = None
    lifecycle_state: LifecycleState | None = None
