"""finding 的來源追溯查詢（T20；docs/DECISIONS.md §26）。

每個查詢都限定在快照的連結（`finding_id = F AND link_sequence <= as_of`）：翻頁時集合不變，計數與
分組都由同一個集合算出。每頁的 SQL 數固定（沒有 N+1）。artifact 只讀 metadata 的欄位，不讀
storage_key。
"""

from collections.abc import Sequence
from typing import Any
from uuid import UUID

from sqlalchemy import ColumnElement, Row, case, distinct, func, select
from sqlalchemy.orm import Session

from secscan.core.pagination import Page, PageRequest
from secscan.findings.domain.normalization import Confidence, Severity
from secscan.findings.domain.provenance import (
    RECENT_SCANS,
    ArtifactRecord,
    EngineCount,
    FindingHead,
    LinkRecord,
    RunAppearance,
    RunRecord,
    ScanAppearance,
    SeenSummary,
    Snapshot,
    TracedObservation,
)
from secscan.findings.models import FindingModel, FindingObservationModel
from secscan.findings.repository import finding_of
from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.observation import ArtifactClassification, ArtifactKind
from secscan.scans.models import ArtifactModel, ObservationModel, ScanModel, ScannerRunModel
from secscan.scans.repository import observation_of

_SEVERITIES = tuple(Severity)
_SEVERITY_RANK = {severity.value: rank for rank, severity in enumerate(_SEVERITIES)}
_LINKS = FindingObservationModel
_ARTIFACT_COLUMNS = (
    ArtifactModel.id.label("artifact_id"),
    ArtifactModel.kind.label("artifact_kind"),
    ArtifactModel.path.label("artifact_path"),
    ArtifactModel.sha256.label("artifact_sha256"),
    ArtifactModel.size.label("artifact_size"),
    ArtifactModel.redactions.label("artifact_redactions"),
    ArtifactModel.classification.label("artifact_classification"),
    ArtifactModel.encrypted.label("artifact_encrypted"),
)


class ProvenanceIntegrityError(RuntimeError):
    """快照的連結序號不完整（不應發生：DB 在 commit 時核對）。"""


class ProvenanceRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def head(self, finding_id: UUID) -> FindingHead | None:
        model = self._session.get(FindingModel, finding_id)
        if model is None:
            return None
        return FindingHead(
            finding=finding_of(model),
            fingerprint=model.fingerprint,
            taxonomy_sha256=model.taxonomy_sha256,
            observations_linked=model.observations_linked,
        )

    def seen(self, snapshot: Snapshot) -> SeenSummary:
        """快照中的 scan 數，以及第一個與最後一個連結的 scan 與 run（和快照一致）。"""
        scans = self._session.scalar(
            select(func.count(distinct(ObservationModel.scan_id)))
            .select_from(_LINKS)
            .join(ObservationModel, ObservationModel.id == _LINKS.observation_id)
            .where(*_in(snapshot))
        )
        ends = {
            row.link_sequence: row
            for row in self._session.execute(
                select(
                    _LINKS.link_sequence, ObservationModel.scan_id, ObservationModel.scanner_run_id
                )
                .join(ObservationModel, ObservationModel.id == _LINKS.observation_id)
                .where(
                    _LINKS.finding_id == snapshot.finding_id,
                    _LINKS.link_sequence.in_((1, snapshot.as_of)),
                )
            )
        }
        first, last = ends.get(1), ends.get(snapshot.as_of)
        if first is None or last is None:
            # commit 時 DB 核對連結數等於連結的筆數（v0015）：走到這裡是資料不一致，不回傳半套。
            raise ProvenanceIntegrityError(f"finding {snapshot.finding_id} 的連結序號不完整")
        return SeenSummary(
            scans=scans or 0,
            observations=snapshot.as_of,
            first_seen_scan_id=first.scan_id,
            first_seen_run_id=first.scanner_run_id,
            last_seen_scan_id=last.scan_id,
            last_seen_run_id=last.scanner_run_id,
        )

    def engines(self, snapshot: Snapshot) -> tuple[EngineCount, ...]:
        rows = self._session.execute(
            select(
                ScannerRunModel.engine,
                func.count().label("observations"),
                func.count(distinct(ObservationModel.scan_id)).label("scans"),
            )
            .select_from(_LINKS)
            .join(ObservationModel, ObservationModel.id == _LINKS.observation_id)
            .join(ScannerRunModel, ScannerRunModel.id == ObservationModel.scanner_run_id)
            .where(*_in(snapshot))
            .group_by(ScannerRunModel.engine)
            .order_by(ScannerRunModel.engine)
        )
        return tuple(EngineCount(Engine(row.engine), row.observations, row.scans) for row in rows)

    def recent_scans(self, snapshot: Snapshot) -> tuple[ScanAppearance, ...]:
        return self._appearances(snapshot, newest_first=True, offset=0, limit=RECENT_SCANS)

    def scans(self, snapshot: Snapshot, page: PageRequest) -> Page[ScanAppearance]:
        """快照中出現過的 scan，由舊到新（scan 的建立時間，再依 id）。"""
        total = self._session.scalar(
            select(func.count(distinct(ObservationModel.scan_id)))
            .select_from(_LINKS)
            .join(ObservationModel, ObservationModel.id == _LINKS.observation_id)
            .where(*_in(snapshot))
        )
        items = self._appearances(
            snapshot, newest_first=False, offset=page.offset, limit=page.limit
        )
        return Page(items=items, total=total or 0, request=page)

    def observations(
        self,
        snapshot: Snapshot,
        page: PageRequest,
        *,
        scan_id: UUID | None,
        engine: Engine | None,
    ) -> Page[TracedObservation]:
        """依連結的序號排序；scan_id 與 engine 篩選同一個快照的集合。"""
        conditions = [*_in(snapshot)]
        if scan_id is not None:
            conditions.append(ObservationModel.scan_id == scan_id)
        if engine is not None:
            conditions.append(ScannerRunModel.engine == engine.value)
        joined = (
            select(_LINKS, ObservationModel, ScannerRunModel, *_ARTIFACT_COLUMNS)
            .join(ObservationModel, ObservationModel.id == _LINKS.observation_id)
            .join(ScannerRunModel, ScannerRunModel.id == ObservationModel.scanner_run_id)
            .outerjoin(ArtifactModel, ArtifactModel.id == ObservationModel.report_artifact_id)
            .where(*conditions)
        )
        total = self._session.scalar(
            select(func.count())
            .select_from(_LINKS)
            .join(ObservationModel, ObservationModel.id == _LINKS.observation_id)
            .join(ScannerRunModel, ScannerRunModel.id == ObservationModel.scanner_run_id)
            .where(*conditions)
        )
        rows = self._session.execute(
            joined.order_by(_LINKS.link_sequence).offset(page.offset).limit(page.limit)
        ).all()
        return Page(items=tuple(_traced(row) for row in rows), total=total or 0, request=page)

    def _appearances(
        self, snapshot: Snapshot, *, newest_first: bool, offset: int, limit: int
    ) -> tuple[ScanAppearance, ...]:
        rank = case(_SEVERITY_RANK, value=_LINKS.normalized_severity)
        grouped = (
            select(
                ObservationModel.scan_id,
                func.count().label("observations"),
                func.max(rank).label("rank"),
            )
            .select_from(_LINKS)
            .join(ObservationModel, ObservationModel.id == _LINKS.observation_id)
            .where(*_in(snapshot))
            .group_by(ObservationModel.scan_id)
            .subquery()
        )
        order = (ScanModel.created_at, ScanModel.id)
        rows = self._session.execute(
            select(
                ScanModel.id,
                ScanModel.created_at,
                ScanModel.status,
                grouped.c.observations,
                grouped.c.rank,
            )
            .join(grouped, grouped.c.scan_id == ScanModel.id)
            .order_by(*(column.desc() for column in order) if newest_first else order)
            .offset(offset)
            .limit(limit)
        ).all()
        runs = self._runs(snapshot, [row.id for row in rows])
        return tuple(
            ScanAppearance(
                scan_id=row.id,
                created_at=row.created_at,
                status=row.status,
                observations=row.observations,
                severity=_SEVERITIES[row.rank],
                runs=runs.get(row.id, ()),
            )
            for row in rows
        )

    def _runs(
        self, snapshot: Snapshot, scan_ids: Sequence[UUID]
    ) -> dict[UUID, tuple[RunAppearance, ...]]:
        """這幾個 scan 的所有 run（含沒有觀察、失敗的引擎）與各自在快照中的觀察數。"""
        if not scan_ids:
            return {}
        counted = (
            select(ObservationModel.scanner_run_id, func.count().label("observations"))
            .select_from(_LINKS)
            .join(ObservationModel, ObservationModel.id == _LINKS.observation_id)
            .where(*_in(snapshot), ObservationModel.scan_id.in_(scan_ids))
            .group_by(ObservationModel.scanner_run_id)
            .subquery()
        )
        rows = self._session.execute(
            select(
                ScannerRunModel.id,
                ScannerRunModel.scan_id,
                ScannerRunModel.engine,
                ScannerRunModel.sequence,
                ScannerRunModel.status,
                ScannerRunModel.error_code,
                func.coalesce(counted.c.observations, 0).label("observations"),
            )
            .outerjoin(counted, counted.c.scanner_run_id == ScannerRunModel.id)
            .where(ScannerRunModel.scan_id.in_(scan_ids))
            .order_by(ScannerRunModel.scan_id, ScannerRunModel.sequence)
        )
        runs: dict[UUID, list[RunAppearance]] = {}
        for row in rows:
            runs.setdefault(row.scan_id, []).append(
                RunAppearance(
                    run_id=row.id,
                    engine=Engine(row.engine),
                    sequence=row.sequence,
                    status=row.status,
                    error_code=row.error_code,
                    observations=row.observations,
                )
            )
        return {scan_id: tuple(items) for scan_id, items in runs.items()}


def _in(snapshot: Snapshot) -> list[ColumnElement[bool]]:
    return [_LINKS.finding_id == snapshot.finding_id, _LINKS.link_sequence <= snapshot.as_of]


def _traced(row: Row[*tuple[Any, ...]]) -> TracedObservation:
    link: FindingObservationModel = row[0]
    observation: ObservationModel = row[1]
    run: ScannerRunModel = row[2]
    return TracedObservation(
        observation=observation_of(observation, run.engine),
        link=LinkRecord(
            sequence=link.link_sequence,
            normalized_severity=Severity(link.normalized_severity),
            normalized_confidence=Confidence(link.normalized_confidence),
            needs_review=link.needs_review,
            taxonomy_sha256=link.taxonomy_sha256,
            linked_at=link.created_at,
        ),
        artifact=_artifact(row),
        run=RunRecord(
            id=run.id,
            engine=Engine(run.engine),
            sequence=run.sequence,
            status=run.status,
            error_code=run.error_code,
            image_ref=run.image_ref,
            plan_hash=run.plan_hash,
            profile_definition_sha256=run.profile_definition_sha256,
            engine_version=run.engine_version,
            parser_version=run.parser_version,
            started_at=run.started_at,
            finished_at=run.finished_at,
        ),
    )


def _artifact(row: Row[*tuple[Any, ...]]) -> ArtifactRecord | None:
    if row.artifact_id is None:
        return None
    return ArtifactRecord(
        id=row.artifact_id,
        kind=ArtifactKind(row.artifact_kind),
        path=row.artifact_path,
        sha256=row.artifact_sha256,
        size=row.artifact_size,
        redactions=row.artifact_redactions,
        classification=ArtifactClassification(row.artifact_classification),
        encrypted=row.artifact_encrypted,
    )
