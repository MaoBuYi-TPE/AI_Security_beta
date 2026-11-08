"""報告的資料快照（docs/DECISIONS.md §28.5）。

在呼叫端開啟的 REPEATABLE READ READ ONLY transaction 中分頁讀取；data_as_of 是 transaction
的開始時間。只讀 DB 中保存的值，不以目前的 taxonomy 重算。

每頁 finding 以固定數量的查詢取得來源、樣本（每個最多 3 筆）、不同 path 數與 resolved 的依據；
每讀完一頁呼叫 on_page（worker 以另一個短 transaction 寫心跳）。
"""

import re
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import ColumnElement, Row, and_, distinct, func, select
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.orm import Session

from secscan.api_keys.models import ApiKeyModel
from secscan.comparisons.models import ScanComparisonFindingModel, ScanComparisonModel
from secscan.core.pagination import PageRequest
from secscan.findings.domain.model import Finding, FindingFilters, LifecycleState
from secscan.findings.domain.triage import PROVENANCE_OF_BASIS, ResolutionBasis
from secscan.findings.models import (
    FindingModel,
    FindingObservationModel,
    FindingTriageEventModel,
)
from secscan.findings.repository import FindingRepository
from secscan.grants.repository import ScopeGrantRepository
from secscan.reports.domain.model import (
    MAX_COMPARISONS,
    MAX_SAMPLES,
    AuthorizationSection,
    AuthSection,
    ComparisonSection,
    EngineRow,
    FindingSection,
    ReportFormat,
    ReportSnapshot,
    ResolutionSection,
    Sample,
    ScanSection,
    SourceRow,
    SpecSection,
)
from secscan.scans.domain.model import Scan
from secscan.scans.models import ObservationModel
from secscan.scans.repository import ScanRepository
from secscan.scans.schemas import ScanOut
from secscan.specs.repository import ApiSpecRepository
from secscan.targets.models import TargetModel

PAGE_SIZE = 100
_SHA256 = re.compile(r"[0-9a-f]{64}")
_CHECK_NAME = re.compile(r"[a-z][a-z_]{0,63}")


class SnapshotUnavailableError(Exception):
    """scan 或 grant 已不存在（不應發生：都不能刪除）。"""


class SnapshotReader:
    def __init__(self, session: Session) -> None:
        self._session = session

    def read(
        self,
        report_id: UUID,
        scan_id: UUID,
        report_format: ReportFormat,
        *,
        on_page: Callable[[], None] = lambda: None,
    ) -> ReportSnapshot:
        data_as_of: datetime = self._session.execute(select(func.now())).scalar_one()
        scan = ScanRepository(self._session).get(scan_id)
        if scan is None:
            raise SnapshotUnavailableError("scan 不存在")
        grant = ScopeGrantRepository(self._session).get(scan.scope_grant.id)
        if grant is None:
            raise SnapshotUnavailableError("grant 不存在")
        public = ScanOut.of(scan)
        return ReportSnapshot(
            report_id=report_id,
            format=report_format,
            data_as_of=data_as_of,
            scan=self._scan_section(scan, public),
            authorization=AuthorizationSection(
                grant_id=grant.id,
                grant_version=scan.scope_grant.version,
                approved_at=grant.approved_at,
                valid_from=grant.window.valid_from,
                valid_until=grant.window.valid_until,
                authorization_reference=grant.authorization_reference,
            ),
            spec=self._spec(scan),
            auth=AuthSection(
                role=scan.auth_role,
                profile_version=scan.auth.version if scan.auth is not None else None,
                preflight=public.auth.preflight if public.auth is not None else None,
            ),
            findings=self._findings(scan_id, on_page),
            comparisons=self._comparisons(scan_id),
            comparisons_omitted=max(0, self._comparison_total(scan_id) - MAX_COMPARISONS),
        )

    def _scan_section(self, scan: Scan, public: ScanOut) -> ScanSection:
        target_name = self._session.scalar(
            select(TargetModel.name).where(TargetModel.id == scan.target_id)
        )
        return ScanSection(
            id=scan.id,
            status=scan.status.value,
            profile=scan.profile.value,
            fixture=scan.fixture,
            results_complete=scan.results_complete,
            auth_role=scan.auth_role,
            created_at=scan.created_at,
            finished_at=scan.finished_at,
            target_name=target_name or "",
            target_origin=str(scan.target_origin),
            engines=tuple(
                EngineRow(
                    run.engine.value,
                    run.status.value,
                    run.error_code.value if run.error_code is not None else None,
                    run.started_at,
                    run.finished_at,
                )
                for run in scan.runs
            ),
            requests_sent=public.budget_usage.requests_sent,
            requests_denied=public.budget_usage.requests_denied,
            traffic_duration_seconds=public.budget_usage.traffic_duration_seconds,
            coverage_measured=public.coverage.coverage_measured,
            eligible_operations=public.coverage.eligible_operations,
            ineligible_operations=public.coverage.ineligible_operations,
            observed_operations=public.coverage.observed_operations,
            authenticated_operations=public.coverage.authenticated_operations,
            coverage_limitations=tuple(public.coverage.limitations),
        )

    def _spec(self, scan: Scan) -> SpecSection | None:
        if scan.api_spec is None:
            return None
        found = ApiSpecRepository(self._session).get(scan.api_spec.id)
        if found is None:
            return None
        return SpecSection(
            found.id, scan.api_spec.version, found.openapi_version, found.operation_count
        )

    def _findings(self, scan_id: UUID, on_page: Callable[[], None]) -> tuple[FindingSection, ...]:
        repository = FindingRepository(self._session)
        sections: list[FindingSection] = []
        page_number = 1
        while True:
            page = repository.for_scan(
                scan_id, FindingFilters(), PageRequest(page_number, PAGE_SIZE), {}
            )
            ids = [item.id for item in page.items]
            samples, paths = self._samples(scan_id, ids)
            resolutions = self._resolutions(ids)
            sections.extend(
                _section(item, samples.get(item.id, ()), paths.get(item.id, 0), resolutions)
                for item in page.items
            )
            on_page()
            if page_number * PAGE_SIZE >= page.total or not page.items:
                return tuple(sections)
            page_number += 1

    def _samples(
        self, scan_id: UUID, finding_ids: Sequence[UUID]
    ) -> tuple[dict[UUID, tuple[Sample, ...]], dict[UUID, int]]:
        if not finding_ids:
            return {}, {}
        links = FindingObservationModel
        in_scan = and_(
            links.finding_id.in_(finding_ids),
            ObservationModel.id == links.observation_id,
            ObservationModel.scan_id == scan_id,
        )
        counts = self._session.execute(
            select(links.finding_id, func.count(distinct(ObservationModel.path)))
            .select_from(links)
            .join(ObservationModel, in_scan)
            .group_by(links.finding_id)
        ).all()
        ranked = (
            select(
                links.finding_id,
                ObservationModel.path,
                ObservationModel.parameter,
                ObservationModel.evidence,
                func.row_number()
                .over(partition_by=links.finding_id, order_by=links.link_sequence)
                .label("rank"),
            )
            .select_from(links)
            .join(ObservationModel, in_scan)
            .subquery()
        )
        rows = self._session.execute(
            select(ranked)
            .where(ranked.c.rank <= MAX_SAMPLES)
            .order_by(ranked.c.finding_id, ranked.c.rank)
        ).all()
        samples: dict[UUID, list[Sample]] = {}
        for row in rows:
            samples.setdefault(row.finding_id, []).append(
                Sample(row.path, row.parameter, row.evidence)
            )
        return (
            {key: tuple(value) for key, value in samples.items()},
            {row[0]: int(row[1]) for row in counts},
        )

    def _resolutions(self, finding_ids: Sequence[UUID]) -> dict[UUID, ResolutionSection]:
        """目前是 resolved 的 finding：最後一次轉成 resolved 的事件（DISTINCT ON）。"""
        if not finding_ids:
            return {}
        events = FindingTriageEventModel
        rows = self._session.execute(
            select(events, ApiKeyModel.role)
            .ext(distinct_on(events.finding_id))
            .join(
                FindingModel,
                and_(
                    FindingModel.id == events.finding_id,
                    FindingModel.lifecycle_state == LifecycleState.RESOLVED.value,
                ),
            )
            .outerjoin(ApiKeyModel, ApiKeyModel.id == events.actor_key_id)
            .where(events.finding_id.in_(finding_ids), events.comparison_id.is_not(None))
            .order_by(events.finding_id, events.sequence.desc())
        ).all()
        return {row[0].finding_id: _resolution(row) for row in rows}

    def _comparison_total(self, scan_id: UUID) -> int:
        total = self._session.scalar(
            select(func.count()).select_from(ScanComparisonModel).where(*_involving(scan_id))
        )
        return total or 0

    def _comparisons(self, scan_id: UUID) -> tuple[ComparisonSection, ...]:
        """這個 scan 參與的比較快照，最新的 MAX_COMPARISONS 份（省略的數量另外揭露）。"""
        comparisons = ScanComparisonModel
        rows = self._session.scalars(
            select(comparisons)
            .where(*_involving(scan_id))
            .order_by(comparisons.created_at.desc(), comparisons.id.desc())
            .limit(MAX_COMPARISONS)
        ).all()
        sections = []
        for row in rows:
            counts = self._session.execute(
                select(ScanComparisonFindingModel.classification, func.count())
                .where(ScanComparisonFindingModel.comparison_id == row.id)
                .group_by(ScanComparisonFindingModel.classification)
                .order_by(ScanComparisonFindingModel.classification)
            ).all()
            baseline = row.baseline_scan_id == scan_id
            sections.append(
                ComparisonSection(
                    id=row.id,
                    role="baseline" if baseline else "current",
                    other_scan_id=row.current_scan_id if baseline else row.baseline_scan_id,
                    comparability=row.comparability,
                    counts=tuple((str(name), int(count)) for name, count in counts),
                )
            )
        return tuple(sections)


def _involving(scan_id: UUID) -> tuple[ColumnElement[bool], ...]:
    comparisons = ScanComparisonModel
    return (
        comparisons.sealed.is_(True),
        (comparisons.baseline_scan_id == scan_id) | (comparisons.current_scan_id == scan_id),
    )


def _section(
    item: Finding,
    samples: tuple[Sample, ...],
    paths: int,
    resolutions: dict[UUID, ResolutionSection],
) -> FindingSection:
    return FindingSection(
        id=item.id,
        title=item.title,
        kind=item.kind.value,
        category=item.category.value,
        rule_group=item.rule_group,
        severity=item.normalized_severity.value,
        method=item.method,
        route=item.route,
        parameter_location=item.parameter_location,
        parameter_name=item.parameter_name,
        auth_role=item.auth_role,
        auth_verified=item.auth_verified,
        triage_state=item.triage_state.value,
        lifecycle_state=item.lifecycle_state.value,
        triage_version=item.triage_version,
        resolution=resolutions.get(item.id),
        review_reasons=item.resolution_review,
        sources=tuple(
            SourceRow(
                source.engine.value,
                source.source_rule,
                source.severity_label,
                source.normalized_severity.value,
                source.confidence_label,
                source.observations,
            )
            for source in item.sources
        ),
        distinct_paths=paths,
        samples=samples,
    )


def _resolution(row: Row[FindingTriageEventModel, str | None]) -> ResolutionSection:
    event: FindingTriageEventModel = row[0]
    if event.comparison_id is None or event.resolution_basis is None:
        raise SnapshotUnavailableError("resolved 的事件缺少依據或比較快照")
    basis = ResolutionBasis(event.resolution_basis)
    attestation = event.evidence.get("attestation")
    values = _attestation(attestation) if isinstance(attestation, dict) else {}
    return ResolutionSection(
        basis=basis.value,
        provenance=PROVENANCE_OF_BASIS[basis].value,
        decided_at=event.created_at,
        decided_by_role=row.role,
        comparison_id=event.comparison_id,
        **values,
    )


def _attestation(attestation: dict[str, Any]) -> dict[str, Any]:
    """事件 evidence（JSONB）中的複測 metadata：逐欄驗證型別與格式（安全審查 L4）。

    performed_at、雜湊、長度與版本在 Markdown 中放在 code 以外，只接受平台寫入的格式；不符代表
    DB 中的資料被改過或寫入路徑出錯，這次嘗試失敗（不把它渲染出來）。performed_by、procedure 是
    操作者的文字，投影時遮罩、渲染時一律放在 code 中。
    """
    return {
        "performed_at": _timestamp(attestation.get("performed_at")),
        "performed_by": _text(attestation.get("performed_by")),
        "procedure": _text(attestation.get("procedure")),
        "request_excerpt_sha256": _digest(attestation.get("request_excerpt_sha256")),
        "request_excerpt_bytes": _count(attestation.get("request_excerpt_bytes")),
        "response_excerpt_sha256": _digest(attestation.get("response_excerpt_sha256")),
        "response_excerpt_bytes": _count(attestation.get("response_excerpt_bytes")),
        "checks_version": _count(attestation.get("checks_version")),
        "platform_checks": _check_names(attestation.get("platform_checks")),
    }


def _timestamp(value: object) -> str:
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            parsed = None
        if parsed is not None and parsed.tzinfo is not None:
            return parsed.isoformat()
    raise SnapshotUnavailableError("人工複測的時間格式不符")


def _text(value: object) -> str:
    if not isinstance(value, str):
        raise SnapshotUnavailableError("人工複測的文字欄位格式不符")
    return value


def _digest(value: object) -> str:
    if isinstance(value, str) and _SHA256.fullmatch(value):
        return value
    raise SnapshotUnavailableError("人工複測摘錄的雜湊格式不符")


def _count(value: object) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    raise SnapshotUnavailableError("人工複測的長度或版本格式不符")


def _check_names(value: object) -> tuple[str, ...]:
    if isinstance(value, list) and all(
        isinstance(item, str) and _CHECK_NAME.fullmatch(item) for item in value
    ):
        return tuple(value)
    raise SnapshotUnavailableError("人工複測的檢查清單格式不符")
