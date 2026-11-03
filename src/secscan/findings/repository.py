"""findings 的資料存取（docs/DECISIONS.md §25.7、§25.9）。

- FindingRecords：worker 連結觀察時用（在 FindingLinker 的 transaction 中）。鎖序固定：先以 lease 的
  fencing 鎖住 run，再依 fingerprint 的順序新增（ON CONFLICT DO NOTHING）與鎖住既有的 finding；
  不鎖 scans（對帳是 scans → runs）。
- FindingRepository：API 的查詢（一個 scan 的 finding 與它們在這個 scan 中的來源）。
"""

from collections.abc import Iterator, Mapping, Sequence
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import ColumnElement, Row, case, exists, func, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from secscan.core.json_types import JsonObject
from secscan.core.pagination import Page, PageRequest
from secscan.findings.domain.fingerprint import RouteSource
from secscan.findings.domain.linking import (
    Aggregate,
    FindingDraft,
    LinkContext,
    ObservationRow,
    identity_verified,
)
from secscan.findings.domain.model import (
    Finding,
    FindingFilters,
    FindingSource,
    LifecycleState,
    MappingSource,
    TriageState,
)
from secscan.findings.domain.normalization import Confidence, Severity
from secscan.findings.domain.taxonomy import CweSource, FindingKind
from secscan.findings.models import FindingModel, FindingObservationModel
from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.coverage import FrozenOperation
from secscan.scans.domain.model import Lease
from secscan.scans.domain.observation import ParameterLocation
from secscan.scans.domain.preflight import PreflightResult
from secscan.scans.leases import LeaseLostError, holds
from secscan.scans.models import ObservationModel, ScanModel, ScannerRunModel, ScanOperationModel

# 每個 statement 的列數：參數總數遠低於 PostgreSQL 的 65,535 上限。
BATCH_SIZE = 500
_SEVERITY_RANK = {severity.value: rank for rank, severity in enumerate(Severity)}
_OBSERVATION_COLUMNS = (
    ObservationModel.id,
    ObservationModel.source_rule,
    ObservationModel.rule_variant,
    ObservationModel.title,
    ObservationModel.raw_severity,
    ObservationModel.raw_confidence,
    ObservationModel.cwe_id,
    ObservationModel.method,
    ObservationModel.path,
    ObservationModel.parameter,
    ObservationModel.parameter_location,
    ObservationModel.auth_role,
)


class FindingRecords:
    def __init__(self, session: Session) -> None:
        self._session = session

    def lock_run(self, lease: Lease) -> JsonObject | None:
        """以 lease 的 fencing 鎖住 run，回傳它的 result_details；lease 失效時拋 LeaseLostError。"""
        row = self._session.execute(
            select(ScannerRunModel.id, ScannerRunModel.result_details)
            .where(*holds(lease))
            .with_for_update()
        ).first()
        if row is None:
            raise LeaseLostError("lease 已過期或不屬於這個 worker：不連結 finding")
        details: JsonObject | None = row.result_details
        return details

    def unlinked(self, lease: Lease) -> tuple[ObservationRow, ...]:
        """還沒有連結的觀察，依入庫的順序；只讀連結需要的欄位（不讀 evidence 等長文字）。"""
        linked = exists().where(FindingObservationModel.observation_id == ObservationModel.id)
        rows = self._session.execute(
            select(*_OBSERVATION_COLUMNS)
            .where(ObservationModel.scanner_run_id == lease.run_id, ~linked)
            .order_by(ObservationModel.ordinal)
        )
        return tuple(_observation_row(row, lease.engine) for row in rows)

    def context(self, lease: Lease, details: JsonObject | None) -> LinkContext:
        """scan 凍結的欄位與規格的 operation 都不可變（trigger）：不另外加鎖。"""
        scan = self._session.execute(
            select(ScanModel.target_id, ScanModel.auth_role, ScanModel.api_spec_id).where(
                ScanModel.id == lease.scan_id
            )
        ).one()
        preflight = self._session.scalar(
            select(ScannerRunModel.preflight_result).where(
                ScannerRunModel.scan_id == lease.scan_id,
                ScannerRunModel.engine == Engine.PREFLIGHT.value,
            )
        )
        operations: tuple[FrozenOperation, ...] = ()
        if scan.api_spec_id is not None:
            operations = tuple(
                FrozenOperation(row.ordinal, row.method, row.path)
                for row in self._session.execute(
                    select(
                        ScanOperationModel.ordinal,
                        ScanOperationModel.method,
                        ScanOperationModel.path,
                    )
                    .where(
                        ScanOperationModel.scan_id == lease.scan_id,
                        ScanOperationModel.ineligible_reason.is_(None),
                    )
                    .order_by(ScanOperationModel.ordinal)
                )
            )
        verified = identity_verified(
            scan.auth_role, PreflightResult(preflight) if preflight else None, details
        )
        return LinkContext(target_id=scan.target_id, auth_verified=verified, operations=operations)

    def insert_findings(
        self, drafts: Sequence[FindingDraft], lease: Lease, mapping: tuple[str, str]
    ) -> dict[str, UUID]:
        """新的 fingerprint 寫成 finding（依 fingerprint 的順序）；回傳新增的 fingerprint → id。"""
        inserted: dict[str, UUID] = {}
        for batch in _batches([_new_finding(draft, lease, mapping) for draft in drafts]):
            rows = self._session.execute(
                pg_insert(FindingModel)
                .values(batch)
                .on_conflict_do_nothing(index_elements=["target_id", "fingerprint"])
                .returning(FindingModel.fingerprint, FindingModel.id)
            )
            inserted.update({row.fingerprint: row.id for row in rows})
        return inserted

    def lock_findings(
        self, target_id: UUID, fingerprints: Sequence[str]
    ) -> dict[str, tuple[UUID, Aggregate]]:
        """既有的 finding 依 fingerprint 的順序鎖住（呼叫端傳入排序過的 fingerprint）。"""
        locked: dict[str, tuple[UUID, Aggregate]] = {}
        for batch in _batches(list(fingerprints)):
            rows = self._session.execute(
                select(
                    FindingModel.id,
                    FindingModel.fingerprint,
                    FindingModel.normalized_severity,
                    FindingModel.severity_conflict,
                    FindingModel.needs_review,
                )
                .where(FindingModel.target_id == target_id, FindingModel.fingerprint.in_(batch))
                .order_by(FindingModel.fingerprint)
                .with_for_update()
            )
            for row in rows:
                aggregate = Aggregate(
                    Severity(row.normalized_severity), row.severity_conflict, row.needs_review
                )
                locked[row.fingerprint] = (row.id, aggregate)
        return locked

    def update_finding(self, finding_id: UUID, aggregate: Aggregate, lease: Lease) -> None:
        """已鎖住的 finding：新的聚合與最後看到的 run（時間不倒退，trigger 也檢查）。"""
        self._session.execute(
            update(FindingModel)
            .where(FindingModel.id == finding_id)
            .values(
                normalized_severity=aggregate.severity.value,
                severity_conflict=aggregate.severity_conflict,
                needs_review=aggregate.needs_review,
                last_seen_run_id=lease.run_id,
                last_seen_scan_id=lease.scan_id,
                last_seen_at=func.greatest(FindingModel.last_seen_at, func.clock_timestamp()),
            )
            .execution_options(synchronize_session=False)
        )

    def insert_links(
        self, drafts: Sequence[FindingDraft], finding_ids: Mapping[str, UUID], taxonomy_sha256: str
    ) -> None:
        rows = [
            {
                "observation_id": link.observation_id,
                "finding_id": finding_ids[draft.fingerprint],
                "normalized_severity": link.severity.value,
                "normalized_confidence": link.confidence.value,
                "needs_review": link.needs_review,
                "taxonomy_sha256": taxonomy_sha256,
            }
            for draft in drafts
            for link in draft.links
        ]
        for batch in _batches(rows):
            self._session.execute(insert(FindingObservationModel), batch)


class FindingRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def for_scan(self, scan_id: UUID, filters: FindingFilters, page: PageRequest) -> Page[Finding]:
        """這個 scan 有觀察連結到的 finding：等級由高到低，再依群組、route 與 id（順序穩定）。"""
        conditions = _conditions(scan_id, filters)
        total = self._session.scalar(
            select(func.count()).select_from(FindingModel).where(*conditions)
        )
        models = self._session.scalars(
            select(FindingModel)
            .where(*conditions)
            .order_by(
                case(_SEVERITY_RANK, value=FindingModel.normalized_severity).desc(),
                FindingModel.rule_group,
                FindingModel.route,
                FindingModel.id,
            )
            .offset(page.offset)
            .limit(page.limit)
        ).all()
        sources = self._sources(scan_id, [model.id for model in models])
        return Page(
            items=tuple(_finding(model, sources.get(model.id, ())) for model in models),
            total=total or 0,
            request=page,
        )

    def _sources(
        self, scan_id: UUID, finding_ids: list[UUID]
    ) -> dict[UUID, tuple[FindingSource, ...]]:
        if not finding_ids:
            return {}
        columns = (
            FindingObservationModel.finding_id,
            ScannerRunModel.sequence,
            ScannerRunModel.engine,
            ObservationModel.source_rule,
            ObservationModel.rule_variant,
            ObservationModel.raw_severity,
            ObservationModel.severity_label,
            FindingObservationModel.normalized_severity,
            ObservationModel.raw_confidence,
            ObservationModel.confidence_label,
            FindingObservationModel.normalized_confidence,
            ObservationModel.cwe_id,
        )
        rows = self._session.execute(
            select(*columns, func.count().label("observations"))
            .join(ObservationModel, ObservationModel.id == FindingObservationModel.observation_id)
            .join(ScannerRunModel, ScannerRunModel.id == ObservationModel.scanner_run_id)
            .where(
                ObservationModel.scan_id == scan_id,
                FindingObservationModel.finding_id.in_(finding_ids),
            )
            .group_by(*columns)
            .order_by(*columns)
        )
        sources: dict[UUID, list[FindingSource]] = {}
        for row in rows:
            sources.setdefault(row.finding_id, []).append(_source(row))
        return {finding_id: tuple(items) for finding_id, items in sources.items()}


def _conditions(scan_id: UUID, filters: FindingFilters) -> list[ColumnElement[bool]]:
    in_scan = (
        select(FindingObservationModel.finding_id)
        .join(ObservationModel, ObservationModel.id == FindingObservationModel.observation_id)
        .where(ObservationModel.scan_id == scan_id)
    )
    if filters.engine is not None:
        in_scan = in_scan.join(
            ScannerRunModel, ScannerRunModel.id == ObservationModel.scanner_run_id
        ).where(ScannerRunModel.engine == filters.engine.value)
    conditions: list[ColumnElement[bool]] = [FindingModel.id.in_(in_scan)]
    if filters.kind is not None:
        conditions.append(FindingModel.kind == filters.kind.value)
    if filters.severity is not None:
        conditions.append(FindingModel.normalized_severity == filters.severity.value)
    if filters.triage_state is not None:
        conditions.append(FindingModel.triage_state == filters.triage_state.value)
    return conditions


def _new_finding(draft: FindingDraft, lease: Lease, mapping: tuple[str, str]) -> dict[str, object]:
    inputs, aggregate = draft.inputs, draft.aggregate
    version, taxonomy_sha256 = mapping
    return {
        "id": uuid4(),
        "target_id": inputs.target_id,
        "fingerprint": draft.fingerprint,
        "kind": inputs.kind.value,
        "rule_group": inputs.rule_group,
        "title": draft.title,
        "method": inputs.method,
        "route": inputs.route,
        "route_source": draft.route_source.value,
        "parameter_location": inputs.parameter_location,
        "parameter_name": inputs.parameter_name,
        "resource": inputs.resource,
        "auth_role": inputs.auth_role,
        "auth_verified": inputs.auth_verified,
        "normalized_severity": aggregate.severity.value,
        "severity_conflict": aggregate.severity_conflict,
        "needs_review": aggregate.needs_review,
        "cwe_id": draft.cwe_id,
        "cwe_source": draft.cwe_source.value if draft.cwe_source is not None else None,
        "owasp_top10_2025": draft.owasp_top10_2025,
        "owasp_top10_2025_source": _source_of(draft.owasp_top10_2025, MappingSource.OFFICIAL),
        "owasp_api_2023": draft.owasp_api_2023,
        "owasp_api_2023_source": _source_of(draft.owasp_api_2023, MappingSource.CURATED),
        "mapping_version": version,
        "taxonomy_sha256": taxonomy_sha256,
        "first_seen_run_id": lease.run_id,
        "first_seen_scan_id": lease.scan_id,
        "last_seen_run_id": lease.run_id,
        "last_seen_scan_id": lease.scan_id,
    }


def _source_of(category: str | None, source: MappingSource) -> str:
    return (source if category is not None else MappingSource.NONE).value


def _observation_row(row: Row[*tuple[Any, ...]], engine: Engine) -> ObservationRow:
    return ObservationRow(
        id=row.id,
        engine=engine,
        source_rule=row.source_rule,
        rule_variant=row.rule_variant,
        title=row.title,
        raw_severity=row.raw_severity,
        raw_confidence=row.raw_confidence,
        cwe_id=row.cwe_id,
        method=row.method,
        path=row.path,
        parameter=row.parameter,
        parameter_location=ParameterLocation(row.parameter_location),
        auth_role=row.auth_role,
    )


def _finding(model: FindingModel, sources: tuple[FindingSource, ...]) -> Finding:
    return Finding(
        id=model.id,
        target_id=model.target_id,
        kind=FindingKind(model.kind),
        rule_group=model.rule_group,
        title=model.title,
        method=model.method,
        route=model.route,
        route_source=RouteSource(model.route_source),
        parameter_location=model.parameter_location,
        parameter_name=model.parameter_name,
        resource=model.resource,
        auth_role=model.auth_role,
        auth_verified=model.auth_verified,
        normalized_severity=Severity(model.normalized_severity),
        severity_conflict=model.severity_conflict,
        needs_review=model.needs_review,
        cwe_id=model.cwe_id,
        cwe_source=CweSource(model.cwe_source) if model.cwe_source is not None else None,
        owasp_top10_2025=model.owasp_top10_2025,
        owasp_top10_2025_source=MappingSource(model.owasp_top10_2025_source),
        owasp_api_2023=model.owasp_api_2023,
        owasp_api_2023_source=MappingSource(model.owasp_api_2023_source),
        mapping_version=model.mapping_version,
        triage_state=TriageState(model.triage_state),
        lifecycle_state=LifecycleState(model.lifecycle_state),
        first_seen_scan_id=model.first_seen_scan_id,
        last_seen_scan_id=model.last_seen_scan_id,
        created_at=model.created_at,
        last_seen_at=model.last_seen_at,
        sources=sources,
    )


def _source(row: Row[*tuple[Any, ...]]) -> FindingSource:
    return FindingSource(
        engine=Engine(row.engine),
        source_rule=row.source_rule,
        rule_variant=row.rule_variant,
        raw_severity=row.raw_severity,
        severity_label=row.severity_label,
        normalized_severity=Severity(row.normalized_severity),
        raw_confidence=row.raw_confidence,
        confidence_label=row.confidence_label,
        normalized_confidence=Confidence(row.normalized_confidence),
        cwe_id=row.cwe_id,
        observations=row.observations,
    )


def _batches[T](items: list[T]) -> Iterator[list[T]]:
    for start in range(0, len(items), BATCH_SIZE):
        yield items[start : start + BATCH_SIZE]
