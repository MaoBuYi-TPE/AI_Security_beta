"""finding 的明細與來源追溯的回應 schema（T20；docs/API_CONTRACT.md §17.10）。

- observations_as_of 是這次讀取的快照（finding 的連結數）：翻頁時帶回 `as_of`，集合不變。
- 連結的值（正規化等級、信心、needs_review、taxonomy_sha256）是連結當時寫入的，不以目前的 taxonomy
  重算；觀察是遮罩、截斷之後的不可信內容，顯示時要編碼。
- artifact 只有 metadata（sha256 是遮罩後檔案的雜湊）；不輸出 storage_key 與內容。舊的觀察沒有
  引用報告時是 null（如實回傳，不補造）。
- scan 與 run 的狀態是讀取時的現值；plan_hash 是準備執行的 ExecutionPlan 的雜湊，不代表執行成功。
"""

from datetime import datetime
from typing import Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from secscan.findings.domain.normalization import Confidence, Severity
from secscan.findings.domain.provenance import (
    ArtifactRecord,
    EngineCount,
    FindingDetail,
    LinkRecord,
    RunAppearance,
    RunRecord,
    ScanAppearance,
    SeenSummary,
    TracedObservation,
)
from secscan.findings.schemas import FindingCoreOut, finding_fields
from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.lifecycle import RunStatus, ScanStatus
from secscan.scans.domain.observation import ArtifactClassification, ArtifactKind
from secscan.scans.schemas import ObservationOut


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True)


class SeenOut(_Frozen):
    """快照中的 scan 數、觀察數，以及第一個與最後一個連結的 scan 與 run。"""

    scans: int
    observations: int
    first_seen_scan_id: UUID
    first_seen_run_id: UUID
    last_seen_scan_id: UUID
    last_seen_run_id: UUID

    @classmethod
    def of(cls, seen: SeenSummary) -> Self:
        return cls(**{name: getattr(seen, name) for name in cls.model_fields})


class EngineCountOut(_Frozen):
    engine: Engine
    observations: int
    scans: int

    @classmethod
    def of(cls, count: EngineCount) -> Self:
        return cls(engine=count.engine, observations=count.observations, scans=count.scans)


class RunAppearanceOut(_Frozen):
    """scan 的一個 run：observations 是它連結到這個 finding 的觀察數（失敗的引擎是 0）。"""

    id: UUID
    engine: Engine
    sequence: int
    status: RunStatus
    error_code: str | None
    observations: int

    @classmethod
    def of(cls, run: RunAppearance) -> Self:
        return cls(
            id=run.run_id,
            engine=run.engine,
            sequence=run.sequence,
            status=RunStatus(run.status),
            error_code=run.error_code,
            observations=run.observations,
        )


class ScanAppearanceOut(_Frozen):
    scan_id: UUID
    created_at: datetime
    status: ScanStatus
    observations: int
    # 這個 scan 的連結當時的正規化等級的最高值。
    scan_severity: Severity
    runs: list[RunAppearanceOut]

    @classmethod
    def of(cls, scan: ScanAppearance) -> Self:
        return cls(
            scan_id=scan.scan_id,
            created_at=scan.created_at,
            status=ScanStatus(scan.status),
            observations=scan.observations,
            scan_severity=scan.severity,
            runs=[RunAppearanceOut.of(run) for run in scan.runs],
        )


class FindingDetailOut(FindingCoreOut):
    """GET /findings/{id}：有上限的摘要（近期 5 次 scan）；完整的歷史與觀察另外分頁。"""

    fingerprint: str
    taxonomy_sha256: str
    observations_as_of: int
    seen: SeenOut
    engines: list[EngineCountOut]
    recent_scans: list[ScanAppearanceOut]

    @classmethod
    def of(cls, detail: FindingDetail) -> Self:
        return cls.model_validate(
            {
                **finding_fields(detail.finding),
                "fingerprint": detail.fingerprint,
                "taxonomy_sha256": detail.taxonomy_sha256,
                "observations_as_of": detail.as_of,
                "seen": SeenOut.of(detail.seen),
                "engines": [EngineCountOut.of(count) for count in detail.engines],
                "recent_scans": [ScanAppearanceOut.of(scan) for scan in detail.recent_scans],
            }
        )


class LinkOut(_Frozen):
    sequence: int
    normalized_severity: Severity
    normalized_confidence: Confidence
    needs_review: bool
    taxonomy_sha256: str
    linked_at: datetime

    @classmethod
    def of(cls, link: LinkRecord) -> Self:
        return cls(
            sequence=link.sequence,
            normalized_severity=link.normalized_severity,
            normalized_confidence=link.normalized_confidence,
            needs_review=link.needs_review,
            taxonomy_sha256=link.taxonomy_sha256,
            linked_at=link.linked_at,
        )


class ArtifactMetadataOut(_Frozen):
    id: UUID
    kind: ArtifactKind
    path: str
    sha256: str
    size_bytes: int
    redactions: int
    classification: ArtifactClassification
    encrypted: bool

    @classmethod
    def of(cls, artifact: ArtifactRecord) -> Self:
        return cls(
            id=artifact.id,
            kind=artifact.kind,
            path=artifact.path,
            sha256=artifact.sha256,
            size_bytes=artifact.size,
            redactions=artifact.redactions,
            classification=artifact.classification,
            encrypted=artifact.encrypted,
        )


class RunProvenanceOut(_Frozen):
    id: UUID
    engine: Engine
    sequence: int
    status: RunStatus
    error_code: str | None
    image_ref: str | None
    plan_hash: str | None
    profile_definition_sha256: str | None
    engine_version: str | None
    parser_version: str | None
    started_at: datetime | None
    finished_at: datetime | None

    @classmethod
    def of(cls, run: RunRecord) -> Self:
        values = {name: getattr(run, name) for name in cls.model_fields if name != "status"}
        return cls(**values, status=RunStatus(run.status))


class TracedObservationOut(_Frozen):
    link: LinkOut
    observation: ObservationOut
    artifact: ArtifactMetadataOut | None
    run: RunProvenanceOut

    @classmethod
    def of(cls, traced: TracedObservation) -> Self:
        return cls(
            link=LinkOut.of(traced.link),
            observation=ObservationOut.of(traced.observation),
            artifact=ArtifactMetadataOut.of(traced.artifact) if traced.artifact else None,
            run=RunProvenanceOut.of(traced.run),
        )
