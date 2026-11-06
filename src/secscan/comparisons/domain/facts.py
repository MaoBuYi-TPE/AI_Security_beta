"""比較使用的凍結事實；不攜帶原始請求、secret 或證據內容。"""

from dataclasses import dataclass
from uuid import UUID

from secscan.comparisons.domain.classification import Classification, ComparisonFacts, SourceRef
from secscan.comparisons.domain.comparability import ScanComparison, ScanFacts
from secscan.findings.domain.fingerprint import RouteSource
from secscan.grants.domain.matching import ScopeRules
from secscan.scans.domain.lifecycle import RunStatus


@dataclass(frozen=True, slots=True)
class LocationFact:
    method: str
    path_sha256: str
    answered: bool
    authenticated: bool


@dataclass(frozen=True, slots=True)
class RunFacts:
    run_id: UUID
    engine: str
    status: RunStatus
    definition_sha256: str | None
    mapping_version: str | None
    taxonomy_sha256: str | None
    identity_verified: bool
    time_limit_reached: bool | None
    locations_recorded: bool
    locations: tuple[LocationFact, ...]
    observations_complete: bool = True


@dataclass(frozen=True, slots=True)
class ScanEvidence:
    scan: ScanFacts
    origin: str
    scope: ScopeRules
    runs: tuple[RunFacts, ...]


@dataclass(frozen=True, slots=True)
class SourcePresence:
    source: SourceRef
    run_id: UUID
    # 既有遮罩 observation 的 path；只在記憶體比對，不複製到比較快照。
    paths: tuple[str, ...]
    link_taxonomy_sha256: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FindingPresence:
    scan_id: UUID
    sources: tuple[SourcePresence, ...]


@dataclass(frozen=True, slots=True)
class FindingFacts:
    finding_id: UUID
    rule_group: str
    method: str
    route: str
    route_source: RouteSource
    resource: str | None
    auth_role: str
    auth_verified: bool
    has_parameter: bool
    mapping_version: str
    taxonomy_sha256: str
    appearances: tuple[FindingPresence, ...]


@dataclass(frozen=True, slots=True)
class FindingComparison:
    finding_id: UUID
    classification: Classification
    reasons: tuple[str, ...]
    manual_review_required: bool
    evidence: ComparisonFacts


@dataclass(frozen=True, slots=True)
class Evaluation:
    scans: ScanComparison
    findings: tuple[FindingComparison, ...]
