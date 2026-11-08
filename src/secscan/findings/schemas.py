"""finding 的回應 schema（docs/API_CONTRACT.md §9、§17.9）。

- finding 是 target 層級、跨掃描的議題：normalized_severity 是所有掃描的來源正規化之後的最高值
  （來源數不加分，只會往上），來源不一致時 severity_conflict；needs_review 表示要人工確認對應
  （不是人工 triage 的結果）。
- sources 只有查詢的那個 scan 中的來源：同一個引擎、規則、variant 與原值的觀察數，並列工具的原值；
  scan_severity 是這些來源的最高值（同一個 finding 在別的 scan 可能更高）。
- 沒有 CVE／CVSS 的資料來源：不輸出這些欄位，不捏造。OWASP 對應帶來源（official、curated、none）與
  沒有對應的原因；tool_cwe_ids 保留這個 scan 的來源工具回報的原始 CWE。
- category 區分 vulnerability／misconfiguration（security）、technology／detection／hardening
  （informational）與 unclassified（fallback，人工確認前分開統計）；人工 triage 之前都不是已驗證的
  漏洞。
"""

from datetime import datetime
from typing import Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from secscan.findings.domain.fingerprint import RouteSource
from secscan.findings.domain.model import (
    Finding,
    FindingSource,
    LifecycleState,
    MappingSource,
    TriageState,
    UnmappedReason,
    api_unmapped_reason,
    top10_unmapped_reason,
)
from secscan.findings.domain.normalization import Confidence, Severity, highest
from secscan.findings.domain.taxonomy import CweSource, FindingCategory, FindingKind
from secscan.scans.domain.catalog import Engine


class FindingLocationOut(BaseModel):
    """route 是規格的樣板（openapi，剛好一個最具體的 operation）或字面的 path（literal）。"""

    model_config = ConfigDict(frozen=True)

    method: str
    route: str
    route_source: RouteSource
    parameter_location: str | None
    parameter_name: str | None
    resource: str | None


class OwaspMappingOut(BaseModel):
    """Top 10:2025 依官方的 CWE 清單；API Security Top 10:2023 依 curated 表。"""

    model_config = ConfigDict(frozen=True)

    top10_2025: str | None
    top10_2025_source: MappingSource
    top10_2025_unmapped_reason: UnmappedReason | None
    api_2023: str | None
    api_2023_source: MappingSource
    api_2023_unmapped_reason: UnmappedReason | None


class FindingSourceOut(BaseModel):
    model_config = ConfigDict(frozen=True)

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

    @classmethod
    def of(cls, source: FindingSource) -> Self:
        return cls(**{name: getattr(source, name) for name in cls.model_fields})


class FindingCoreOut(BaseModel):
    """finding 本身的欄位（scan 的清單與明細共用）。"""

    model_config = ConfigDict(frozen=True)

    id: UUID
    target_id: UUID
    kind: FindingKind
    category: FindingCategory
    rule_group: str
    title: str
    normalized_severity: Severity
    severity_conflict: bool
    needs_review: bool
    cwe_ids: list[str]
    cwe_source: CweSource | None
    location: FindingLocationOut
    auth_role: str
    # 身分在觀察的 run 中確實有效（anonymous 一律 true）；false 的不會併入已驗證身分的 finding。
    auth_verified: bool
    owasp: OwaspMappingOut
    mapping_version: str
    triage_state: TriageState
    lifecycle_state: LifecycleState
    # T21：PATCH /findings/{id}/triage 的 expected_version。
    triage_version: int
    # resolved 之後平台無法自動判斷是否復發（又被觀察到但 mapping 不同，或規則已換版）：不算已修補。
    resolution_review_required: bool
    resolution_review_reasons: list[str]
    first_seen_scan_id: UUID
    last_seen_scan_id: UUID
    created_at: datetime
    last_seen_at: datetime


def finding_fields(finding: Finding) -> dict[str, object]:
    """FindingCoreOut 的欄位值（清單與明細共用）。"""
    return {
        "id": finding.id,
        "target_id": finding.target_id,
        "kind": finding.kind,
        "category": finding.category,
        "rule_group": finding.rule_group,
        "title": finding.title,
        "normalized_severity": finding.normalized_severity,
        "severity_conflict": finding.severity_conflict,
        "needs_review": finding.needs_review,
        "cwe_ids": [f"CWE-{finding.cwe_id}"] if finding.cwe_id is not None else [],
        "cwe_source": finding.cwe_source,
        "location": FindingLocationOut(
            method=finding.method,
            route=finding.route,
            route_source=finding.route_source,
            parameter_location=finding.parameter_location,
            parameter_name=finding.parameter_name,
            resource=finding.resource,
        ),
        "auth_role": finding.auth_role,
        "auth_verified": finding.auth_verified,
        "owasp": OwaspMappingOut(
            top10_2025=finding.owasp_top10_2025,
            top10_2025_source=finding.owasp_top10_2025_source,
            top10_2025_unmapped_reason=top10_unmapped_reason(
                finding.cwe_id, finding.owasp_top10_2025
            ),
            api_2023=finding.owasp_api_2023,
            api_2023_source=finding.owasp_api_2023_source,
            api_2023_unmapped_reason=api_unmapped_reason(finding.owasp_api_2023),
        ),
        "mapping_version": finding.mapping_version,
        "triage_state": finding.triage_state,
        "lifecycle_state": finding.lifecycle_state,
        "triage_version": finding.triage_version,
        "resolution_review_required": bool(finding.resolution_review),
        "resolution_review_reasons": list(finding.resolution_review),
        "first_seen_scan_id": finding.first_seen_scan_id,
        "last_seen_scan_id": finding.last_seen_scan_id,
        "created_at": finding.created_at,
        "last_seen_at": finding.last_seen_at,
    }


class FindingOut(FindingCoreOut):
    """GET /scans/{id}/findings 的一項：sources、scan_severity 與 tool_cwe_ids 只看這個 scan。"""

    scan_severity: Severity
    # 這個 scan 的來源工具回報的原始 CWE（cwe_ids 是群組審查後的值）。
    tool_cwe_ids: list[str]
    sources: list[FindingSourceOut]
    # 同一次 scan、同一個位置、taxonomy 標示為相關的 finding（例如偵測行為不同的兩個 CORS 告警）。
    related_finding_ids: list[UUID]

    @classmethod
    def of(cls, finding: Finding) -> Self:
        return cls.model_validate(
            {
                **finding_fields(finding),
                # 列出的 finding 在這個 scan 一定有來源（查詢條件）。
                "scan_severity": highest(source.normalized_severity for source in finding.sources),
                "tool_cwe_ids": [
                    f"CWE-{cwe}"
                    for cwe in sorted({s.cwe_id for s in finding.sources if s.cwe_id is not None})
                ],
                "sources": [FindingSourceOut.of(source) for source in finding.sources],
                "related_finding_ids": list(finding.related_finding_ids),
            }
        )
