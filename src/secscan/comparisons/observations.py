"""以兩次 scan 的不可變連結建立 finding 身分；不讀跨 scan 的可變等級及 triage。"""

from collections import defaultdict
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from secscan.comparisons.domain.classification import SourceRef
from secscan.comparisons.domain.facts import FindingFacts, FindingPresence, SourcePresence
from secscan.findings.domain.fingerprint import RouteSource
from secscan.findings.models import FindingModel, FindingObservationModel
from secscan.scans.models import ObservationModel, ScannerRunModel

MAX_COMPARISON_INPUT_ROWS = 100_000


class ComparisonInputLimitError(ValueError):
    """輸入超過有界處理上限；不產生截斷但看似完整的比較。"""


def finding_inputs(session: Session, scans: tuple[UUID, UUID]) -> tuple[FindingFacts, ...]:
    columns = (
        FindingObservationModel.finding_id,
        ObservationModel.scan_id,
        ObservationModel.scanner_run_id,
        ScannerRunModel.engine,
        ObservationModel.source_rule,
        ObservationModel.rule_variant,
        ObservationModel.path,
        FindingObservationModel.taxonomy_sha256,
    )
    rows = session.execute(
        select(*columns)
        .join(ObservationModel, ObservationModel.id == FindingObservationModel.observation_id)
        .join(ScannerRunModel, ScannerRunModel.id == ObservationModel.scanner_run_id)
        .where(ObservationModel.scan_id.in_(scans))
        .distinct()
        .order_by(*columns)
        .limit(MAX_COMPARISON_INPUT_ROWS + 1)
    ).all()
    if len(rows) > MAX_COMPARISON_INPUT_ROWS:
        raise ComparisonInputLimitError("比較資料超過處理上限")
    type Key = tuple[UUID, UUID, SourceRef, UUID]
    paths: dict[Key, set[str]] = defaultdict(set)
    hashes: dict[Key, set[str]] = defaultdict(set)
    for row in rows:
        key = (
            row.finding_id,
            row.scan_id,
            SourceRef(row.engine, row.source_rule, row.rule_variant),
            row.scanner_run_id,
        )
        paths[key].add(row.path)
        hashes[key].add(row.taxonomy_sha256)
    appearances: dict[UUID, dict[UUID, list[SourcePresence]]] = {}
    for (finding, scan, source, run), values in paths.items():
        appearances.setdefault(finding, {}).setdefault(scan, []).append(
            SourcePresence(
                source,
                run,
                tuple(sorted(values)),
                tuple(sorted(hashes[finding, scan, source, run])),
            )
        )
    if not appearances:
        return ()
    return _findings(session, scans, appearances)


def _findings(
    session: Session,
    scans: tuple[UUID, UUID],
    appearances: dict[UUID, dict[UUID, list[SourcePresence]]],
) -> tuple[FindingFacts, ...]:
    selected = (
        select(FindingObservationModel.finding_id)
        .join(ObservationModel, ObservationModel.id == FindingObservationModel.observation_id)
        .where(ObservationModel.scan_id.in_(scans))
    )
    rows = session.execute(
        select(
            FindingModel.id,
            FindingModel.rule_group,
            FindingModel.method,
            FindingModel.route,
            FindingModel.route_source,
            FindingModel.resource,
            FindingModel.auth_role,
            FindingModel.auth_verified,
            FindingModel.parameter_name.is_not(None).label("has_parameter"),
            FindingModel.mapping_version,
            FindingModel.taxonomy_sha256,
        )
        .where(FindingModel.id.in_(selected))
        .order_by(FindingModel.id)
    )
    return tuple(
        FindingFacts(
            finding_id=row.id,
            rule_group=row.rule_group,
            method=row.method,
            route=row.route,
            route_source=RouteSource(row.route_source),
            resource=row.resource,
            auth_role=row.auth_role,
            auth_verified=row.auth_verified,
            has_parameter=row.has_parameter,
            mapping_version=row.mapping_version,
            taxonomy_sha256=row.taxonomy_sha256,
            appearances=tuple(
                FindingPresence(scan, tuple(sources))
                for scan, sources in appearances[row.id].items()
            ),
        )
        for row in rows
    )
