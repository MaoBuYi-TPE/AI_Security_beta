"""linker 的寫入（docs/DECISIONS.md §25.7、§26.4）：在 FindingLinker 的 transaction 中執行。

鎖序固定：先以 lease 的 fencing 鎖住 run，再依 fingerprint 的順序新增（ON CONFLICT DO NOTHING）與
鎖住既有的 finding；不鎖 scans（對帳是 scans → runs）。連結的序號在持有 finding 的列鎖時保留：
新的 finding 以連結數建立，既有的以一次 `observations_linked + k` 更新，連結帶著
(保留之前的連結數, 之後] 的序號寫入（DB 在寫入與 commit 時核對）。
"""

import hashlib
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Row, exists, func, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from secscan.core.json_types import JsonObject
from secscan.findings.domain.linking import (
    Aggregate,
    FindingDraft,
    LinkContext,
    ObservationRow,
    identity_verified,
)
from secscan.findings.domain.model import LifecycleState, MappingSource, TriageState
from secscan.findings.domain.normalization import Severity
from secscan.findings.domain.taxonomy import MemberKey, member_key
from secscan.findings.domain.triage import TriageStatus
from secscan.findings.errors import MappingChangedError
from secscan.findings.models import FindingModel, FindingObservationModel
from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.coverage import FrozenOperation
from secscan.scans.domain.locations import LocationSummary
from secscan.scans.domain.model import Lease
from secscan.scans.domain.observation import ParameterLocation
from secscan.scans.domain.preflight import PreflightResult
from secscan.scans.leases import LeaseLostError, holds
from secscan.scans.location_models import RunLocationModel, RunRuleLocationModel
from secscan.scans.models import ObservationModel, ScanModel, ScannerRunModel, ScanOperationModel

# 每個 statement 的列數：參數總數遠低於 PostgreSQL 的 65,535 上限。
BATCH_SIZE = 500
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


@dataclass(frozen=True, slots=True)
class LockedFinding:
    id: UUID
    aggregate: Aggregate
    # 鎖住時的連結數：這個 transaction 保留的序號從它之後開始。
    linked: int
    # T21：自動重開需要的狀態（R1、R3、R4）。
    status: TriageStatus
    resolved_scan_position: int | None
    mapping: tuple[str, str]


@dataclass(frozen=True, slots=True)
class RunScan:
    """這個 run 所屬 scan 的佇列位置與 project（scan 的這兩個欄位不可修改，不另外加鎖）。"""

    queue_position: int
    project_id: UUID


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

    def frozen_mapping(self, lease: Lease) -> tuple[str, str] | None:
        """run 已持鎖；只讀連結時凍結的版本，不以目前 taxonomy 回填。"""
        row = self._session.execute(
            select(
                ScannerRunModel.link_mapping_version, ScannerRunModel.link_taxonomy_sha256
            ).where(ScannerRunModel.id == lease.run_id)
        ).one()
        if row.link_mapping_version is None:
            return None
        return row.link_mapping_version, row.link_taxonomy_sha256

    def record_comparison(
        self, lease: Lease, mapping: tuple[str, str], locations: LocationSummary | None
    ) -> None:
        """run 已持鎖；寫連結時一併凍結 mapping 與位置，重試不覆寫。"""
        existing = self.frozen_mapping(lease)
        if existing is not None:
            if existing != mapping:
                raise MappingChangedError("run 的 mapping 版本與目前版本不一致")
            return
        usable = locations is not None and not locations.has_unusable_paths
        if usable and locations is not None:
            self._insert_locations(lease, locations)
        updated = self._session.execute(
            update(ScannerRunModel)
            .where(*holds(lease))
            .values(
                link_mapping_version=mapping[0],
                link_taxonomy_sha256=mapping[1],
                locations_recorded=usable,
            )
            .returning(ScannerRunModel.id)
        ).scalar_one_or_none()
        if updated is None:
            raise LeaseLostError("lease 已過期或不屬於這個 worker：不記錄複掃證據")

    def _insert_locations(self, lease: Lease, locations: LocationSummary) -> None:
        rows = [
            {
                "scanner_run_id": lease.run_id,
                "scan_id": lease.scan_id,
                "method": item.method,
                "path_sha256": hashlib.sha256(item.path.encode("utf-8")).hexdigest(),
                "answered": item.answered,
                "discovery_answered": item.discovery_answered,
                "authenticated": item.authenticated,
                "unanswered": item.unanswered,
            }
            for item in locations.locations
        ]
        rules = [
            {
                "scanner_run_id": lease.run_id,
                "method": item.method,
                "path_sha256": hashlib.sha256(item.path.encode("utf-8")).hexdigest(),
                "rule": item.rule,
                "answered": item.answered,
                "parameters_unknown": item.parameters_unknown,
                "parameters_truncated": item.parameters_truncated,
            }
            for item in locations.rules
        ]
        for batch in _batches(rows):
            self._session.execute(insert(RunLocationModel), batch)
        for batch in _batches(rules):
            self._session.execute(insert(RunRuleLocationModel), batch)

    def unlinked(self, lease: Lease) -> tuple[ObservationRow, ...]:
        """還沒有連結的觀察，依入庫的順序；只讀連結需要的欄位（不讀 evidence 等長文字）。"""
        linked = exists().where(FindingObservationModel.observation_id == ObservationModel.id)
        rows = self._session.execute(
            select(*_OBSERVATION_COLUMNS)
            .where(ObservationModel.scanner_run_id == lease.run_id, ~linked)
            .order_by(ObservationModel.ordinal)
        )
        return tuple(_observation_row(row, lease.engine) for row in rows)

    def context(
        self,
        lease: Lease,
        details: JsonObject | None,
        anchor_members: Mapping[MemberKey, str],
    ) -> LinkContext:
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
        return LinkContext(
            target_id=scan.target_id,
            auth_verified=verified,
            operations=operations,
            anchors=self._anchors(lease, anchor_members),
        )

    def _anchors(
        self, lease: Lease, anchor_members: Mapping[MemberKey, str]
    ) -> frozenset[tuple[str, str, str]]:
        """同一次 scan 中錨點群組的觀察（群組 id, method, path）。觀察不可修改，不另外加鎖。

        錨點的 run 還沒寫入結果時（多個 worker 同時解析）找不到它：佐證成員就留在自己的群組
        （保守，不會誤合併）。
        """
        rules = sorted({rule for _, rule, _ in anchor_members})
        if not rules:
            return frozenset()
        rows = self._session.execute(
            select(
                ScannerRunModel.engine,
                ObservationModel.source_rule,
                ObservationModel.rule_variant,
                ObservationModel.method,
                ObservationModel.path,
            )
            .distinct()
            .join(ScannerRunModel, ScannerRunModel.id == ObservationModel.scanner_run_id)
            .where(
                ObservationModel.scan_id == lease.scan_id, ObservationModel.source_rule.in_(rules)
            )
        )
        anchors: set[tuple[str, str, str]] = set()
        for row in rows:
            group_id = anchor_members.get(
                member_key(Engine(row.engine), row.source_rule, row.rule_variant)
            )
            if group_id is not None:
                anchors.add((group_id, row.method, row.path))
        return frozenset(anchors)

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

    def run_scan(self, lease: Lease) -> RunScan:
        row = self._session.execute(
            select(ScanModel.queue_position, ScanModel.project_id).where(
                ScanModel.id == lease.scan_id
            )
        ).one()
        return RunScan(row.queue_position, row.project_id)

    def lock_findings(
        self, target_id: UUID, fingerprints: Sequence[str]
    ) -> dict[str, LockedFinding]:
        """既有的 finding 依 fingerprint 的順序鎖住（呼叫端傳入排序過的 fingerprint）。

        FOR NO KEY UPDATE（T21）：建立比較快照時 FK 檢查會依 UUID 的順序對 findings 取 KEY SHARE；
        FOR UPDATE 與 KEY SHARE 互斥，兩者以不同順序鎖同一批 finding 會死鎖。
        """
        locked: dict[str, LockedFinding] = {}
        for batch in _batches(list(fingerprints)):
            rows = self._session.execute(
                select(
                    FindingModel.id,
                    FindingModel.fingerprint,
                    FindingModel.normalized_severity,
                    FindingModel.severity_conflict,
                    FindingModel.needs_review,
                    FindingModel.observations_linked,
                    FindingModel.triage_state,
                    FindingModel.lifecycle_state,
                    FindingModel.triage_version,
                    FindingModel.resolved_scan_position,
                    FindingModel.mapping_version,
                    FindingModel.taxonomy_sha256,
                )
                .where(FindingModel.target_id == target_id, FindingModel.fingerprint.in_(batch))
                .order_by(FindingModel.fingerprint)
                .with_for_update(key_share=True)
            )
            for row in rows:
                aggregate = Aggregate(
                    Severity(row.normalized_severity), row.severity_conflict, row.needs_review
                )
                status = TriageStatus(
                    TriageState(row.triage_state),
                    LifecycleState(row.lifecycle_state),
                    row.triage_version,
                )
                locked[row.fingerprint] = LockedFinding(
                    row.id,
                    aggregate,
                    row.observations_linked,
                    status,
                    row.resolved_scan_position,
                    (row.mapping_version, row.taxonomy_sha256),
                )
        return locked

    def update_finding(
        self, finding_id: UUID, aggregate: Aggregate, lease: Lease, *, links: int
    ) -> None:
        """已鎖住的 finding：新的聚合、最後看到的 run（時間不倒退，trigger 也檢查），並保留 links 個
        連結的序號。"""
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
                observations_linked=FindingModel.observations_linked + links,
            )
            .execution_options(synchronize_session=False)
        )

    def insert_links(
        self,
        drafts: Sequence[FindingDraft],
        targets: Mapping[str, tuple[UUID, int]],
        taxonomy_sha256: str,
    ) -> None:
        """targets：fingerprint → (finding id, 保留之前的連結數)；序號接在後面、依 draft 的順序。"""
        rows = [
            {
                "observation_id": link.observation_id,
                "finding_id": targets[draft.fingerprint][0],
                "link_sequence": targets[draft.fingerprint][1] + offset,
                "normalized_severity": link.severity.value,
                "normalized_confidence": link.confidence.value,
                "needs_review": link.needs_review,
                "taxonomy_sha256": taxonomy_sha256,
            }
            for draft in drafts
            for offset, link in enumerate(draft.links, start=1)
        ]
        for batch in _batches(rows):
            self._session.execute(insert(FindingObservationModel), batch)


def _new_finding(draft: FindingDraft, lease: Lease, mapping: tuple[str, str]) -> dict[str, object]:
    inputs, aggregate = draft.inputs, draft.aggregate
    version, taxonomy_sha256 = mapping
    return {
        "id": uuid4(),
        "target_id": inputs.target_id,
        "fingerprint": draft.fingerprint,
        "kind": inputs.kind.value,
        "category": draft.category.value,
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
        # 建立時就保留這一批連結的序號（1..k）。
        "observations_linked": len(draft.links),
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


def _batches[T](items: list[T]) -> Iterator[list[T]]:
    for start in range(0, len(items), BATCH_SIZE):
        yield items[start : start + BATCH_SIZE]
