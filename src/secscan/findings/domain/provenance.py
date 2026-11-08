"""finding 的來源追溯（T20；docs/DECISIONS.md §26、API_CONTRACT.md §17.10）。

追溯鏈：finding → 連結（連結當時的正規化值與 taxonomy_sha256）→ 遮罩後的觀察 → 報告 artifact 的
metadata → run（映像、plan_hash、工具與 parser 的版本）。連結、觀察與 artifact 不可修改，所以回傳
的是寫入當時的值，不以目前的 taxonomy 重算。

快照：`as_of` 是讀取當時 finding 的 observations_linked。序號 <= as_of 的連結都已提交、之後提交的
序號一定更大（v0015 的 trigger），同一個 as_of 翻頁的集合因此固定，不重複也不遺漏。scan 與 run 的
狀態是讀取時的現值（不凍結）。
"""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from secscan.findings.domain.model import Finding
from secscan.findings.domain.normalization import Confidence, Severity
from secscan.findings.domain.triage import Resolution
from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.observation import ArtifactClassification, ArtifactKind, Observation

# 明細中的近期 scan 數（完整的歷史另外分頁）。
RECENT_SCANS = 5


@dataclass(frozen=True, slots=True)
class FindingHead:
    """追溯的起點：finding、它的 fingerprint、建立時的 taxonomy 與目前的連結數。"""

    finding: Finding
    fingerprint: str
    taxonomy_sha256: str
    observations_linked: int


@dataclass(frozen=True, slots=True)
class Snapshot:
    """這個 finding 在 as_of 時的連結集合（序號 1..as_of）。"""

    finding_id: UUID
    as_of: int


@dataclass(frozen=True, slots=True)
class RunAppearance:
    """scan 的一個 run 與它在快照中連結到這個 finding 的觀察數（0 也列出：失敗的引擎看得到）。"""

    run_id: UUID
    engine: Engine
    sequence: int
    status: str
    error_code: str | None
    observations: int


@dataclass(frozen=True, slots=True)
class ScanAppearance:
    scan_id: UUID
    created_at: datetime
    status: str
    observations: int
    # 這個 scan 中連結當時的正規化等級的最高值。
    severity: Severity
    runs: tuple[RunAppearance, ...]


@dataclass(frozen=True, slots=True)
class EngineCount:
    engine: Engine
    observations: int
    scans: int


@dataclass(frozen=True, slots=True)
class SeenSummary:
    scans: int
    observations: int
    first_seen_scan_id: UUID
    first_seen_run_id: UUID
    last_seen_scan_id: UUID
    last_seen_run_id: UUID


@dataclass(frozen=True, slots=True)
class FindingDetail:
    finding: Finding
    fingerprint: str
    # finding 建立時的 taxonomy（每個連結另外記自己的）。
    taxonomy_sha256: str
    as_of: int
    seen: SeenSummary
    engines: tuple[EngineCount, ...]
    recent_scans: tuple[ScanAppearance, ...]
    # T21：快照中不同 path 的數量（triage 一個 finding 涵蓋它所有的物件）與目前 resolved 的依據。
    distinct_paths: int = 0
    resolution: Resolution | None = None


@dataclass(frozen=True, slots=True)
class LinkRecord:
    sequence: int
    normalized_severity: Severity
    normalized_confidence: Confidence
    needs_review: bool
    taxonomy_sha256: str
    linked_at: datetime


@dataclass(frozen=True, slots=True)
class ArtifactRecord:
    """報告 artifact 的 metadata：不含 storage_key 與內容（下載在 T21）。"""

    id: UUID
    kind: ArtifactKind
    path: str
    sha256: str
    size: int
    redactions: int
    classification: ArtifactClassification
    encrypted: bool


@dataclass(frozen=True, slots=True)
class RunRecord:
    id: UUID
    engine: Engine
    sequence: int
    status: str
    error_code: str | None
    image_ref: str | None
    plan_hash: str | None
    profile_definition_sha256: str | None
    engine_version: str | None
    parser_version: str | None
    started_at: datetime | None
    finished_at: datetime | None


@dataclass(frozen=True, slots=True)
class TracedObservation:
    observation: Observation
    link: LinkRecord
    # 舊的觀察可能沒有引用報告（null，如實回傳，不補造）。
    artifact: ArtifactRecord | None
    run: RunRecord
