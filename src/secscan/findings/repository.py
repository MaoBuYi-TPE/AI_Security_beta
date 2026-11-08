"""finding 的查詢（docs/DECISIONS.md §25.9）：一個 scan 的 finding 與它們在這個 scan 中的來源。"""

from collections.abc import Mapping, Sequence
from typing import Any
from uuid import UUID

from sqlalchemy import ColumnElement, Row, Select, case, exists, func, select, tuple_
from sqlalchemy.orm import Session

from secscan.core.pagination import Page, PageRequest
from secscan.findings.domain.fingerprint import RouteSource
from secscan.findings.domain.model import (
    Finding,
    FindingFilters,
    FindingSource,
    LifecycleState,
    MappingSource,
    TriageState,
)
from secscan.findings.domain.normalization import Confidence, Severity
from secscan.findings.domain.taxonomy import CweSource, FindingCategory, FindingKind
from secscan.findings.domain.triage import review_reasons
from secscan.findings.models import FindingModel, FindingObservationModel
from secscan.scans.domain.catalog import Engine
from secscan.scans.models import ObservationModel, ScanModel, ScannerRunModel

_SEVERITY_RANK = {severity.value: rank for rank, severity in enumerate(Severity)}


class FindingRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def for_scan(
        self,
        scan_id: UUID,
        filters: FindingFilters,
        page: PageRequest,
        related: Mapping[str, frozenset[str]],
    ) -> Page[Finding]:
        """這個 scan 有觀察連結到的 finding：等級由高到低，再依群組、route 與 id（順序穩定）。

        related 是 taxonomy 的相關群組：同一次 scan、同一個 method 與 route 的相關 finding 一併列出
        id（只標示，不合併）。
        """
        conditions = _conditions(scan_id, filters)
        total = self._session.scalar(
            select(func.count()).select_from(FindingModel).where(*conditions)
        )
        rows = self._session.execute(
            select(FindingModel, later_mapping_differs())
            .where(*conditions)
            .order_by(
                case(_SEVERITY_RANK, value=FindingModel.normalized_severity).desc(),
                # 同一等級中 security 在前：工具標 info 的高風險項目（例如 Werkzeug debugger）不會
                # 排在技術識別之後（安全審查；等級保留工具的原值，不捏造）。
                (FindingModel.kind == FindingKind.SECURITY.value).desc(),
                FindingModel.rule_group,
                FindingModel.route,
                FindingModel.id,
            )
            .offset(page.offset)
            .limit(page.limit)
        ).all()
        models = [row[0] for row in rows]
        later = {row[0].id: bool(row[1]) for row in rows}
        sources = self._sources(scan_id, [model.id for model in models])
        links = self._related(scan_id, models, related)
        return Page(
            items=tuple(
                finding_of(
                    model,
                    sources.get(model.id, ()),
                    links.get(model.id, ()),
                    later_mapping=later[model.id],
                )
                for model in models
            ),
            total=total or 0,
            request=page,
        )

    def _related(
        self,
        scan_id: UUID,
        models: Sequence[FindingModel],
        related: Mapping[str, frozenset[str]],
    ) -> dict[UUID, tuple[UUID, ...]]:
        """只查這一頁的 (method, route) 與相關群組（安全審查：不讀整個 scan 的 finding）。"""
        wanted = {group for model in models for group in related.get(model.rule_group, ())}
        if not wanted:
            return {}
        positions = sorted({(model.method, model.route) for model in models})
        rows = self._session.execute(
            select(
                FindingModel.id, FindingModel.rule_group, FindingModel.method, FindingModel.route
            )
            .where(
                FindingModel.id.in_(_in_scan(scan_id)),
                FindingModel.rule_group.in_(sorted(wanted)),
                tuple_(FindingModel.method, FindingModel.route).in_(positions),
            )
            .order_by(FindingModel.id)
        ).all()
        by_position: dict[tuple[str, str, str], list[UUID]] = {}
        for row in rows:
            by_position.setdefault((row.method, row.route, row.rule_group), []).append(row.id)
        links: dict[UUID, tuple[UUID, ...]] = {}
        for model in models:
            matched = tuple(
                finding_id
                for group in sorted(related.get(model.rule_group, frozenset()))
                for finding_id in by_position.get((model.method, model.route, group), ())
            )
            if matched:
                links[model.id] = matched
        return links

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


def _in_scan(scan_id: UUID) -> Select[UUID]:
    return (
        select(FindingObservationModel.finding_id)
        .join(ObservationModel, ObservationModel.id == FindingObservationModel.observation_id)
        .where(ObservationModel.scan_id == scan_id)
    )


def _conditions(scan_id: UUID, filters: FindingFilters) -> list[ColumnElement[bool]]:
    in_scan = _in_scan(scan_id)
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
    if filters.category is not None:
        conditions.append(FindingModel.category == filters.category.value)
    if filters.needs_review is not None:
        conditions.append(FindingModel.needs_review.is_(filters.needs_review))
    if filters.lifecycle_state is not None:
        conditions.append(FindingModel.lifecycle_state == filters.lifecycle_state.value)
    return conditions


def later_mapping_differs() -> ColumnElement[bool]:
    """resolve 之後，這個 target 有 scan 的 run 以不同的 mapping 連結（平台無法自動判斷是否復發）。

    只對 resolved 有意義（其他狀態的 resolved_scan_position 是 NULL，比較結果不成立）。
    """
    return (
        exists()
        .where(
            ScanModel.target_id == FindingModel.target_id,
            ScanModel.queue_position > FindingModel.resolved_scan_position,
            ScannerRunModel.scan_id == ScanModel.id,
            ScannerRunModel.link_mapping_version.is_not(None),
            tuple_(ScannerRunModel.link_mapping_version, ScannerRunModel.link_taxonomy_sha256)
            != tuple_(FindingModel.mapping_version, FindingModel.taxonomy_sha256),
        )
        .correlate(FindingModel)
        .label("later_mapping_differs")
    )


def finding_of(
    model: FindingModel,
    sources: tuple[FindingSource, ...] = (),
    related: tuple[UUID, ...] = (),
    *,
    later_mapping: bool = False,
) -> Finding:
    lifecycle = LifecycleState(model.lifecycle_state)
    review = review_reasons(
        lifecycle,
        observations_linked=model.observations_linked,
        resolved_link_count=model.resolved_link_count,
        later_mapping_differs=later_mapping,
    )
    return Finding(
        id=model.id,
        target_id=model.target_id,
        kind=FindingKind(model.kind),
        category=FindingCategory(model.category),
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
        lifecycle_state=lifecycle,
        first_seen_scan_id=model.first_seen_scan_id,
        last_seen_scan_id=model.last_seen_scan_id,
        created_at=model.created_at,
        last_seen_at=model.last_seen_at,
        sources=sources,
        related_finding_ids=related,
        triage_version=model.triage_version,
        resolution_review=tuple(reason.value for reason in review),
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
