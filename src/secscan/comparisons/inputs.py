"""比較的唯讀資料來源；只取必要凍結欄位，不載入憑證或工具原始輸出。"""

import hashlib
import json
import re
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from secscan.comparisons.domain.comparability import ScanFacts
from secscan.comparisons.domain.facts import FindingFacts, LocationFact, RunFacts, ScanEvidence
from secscan.comparisons.domain.provenance import (
    EngineProvenance,
    definition_digest,
    mapping_identity,
)
from secscan.findings.domain.linking import identity_verified
from secscan.findings.models import FindingObservationModel
from secscan.grants.domain.matching import ScopeRules
from secscan.grants.domain.scope import Scope
from secscan.grants.repository import ScopeGrantRepository
from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.lifecycle import RunStatus, ScanStatus
from secscan.scans.domain.preflight import PreflightResult
from secscan.scans.location_models import RunLocationModel
from secscan.scans.models import ObservationModel, ScanModel, ScannerRunModel
from secscan.specs.models import ApiSpecModel

_VERSION = re.compile(r"rules-[0-9.]+\+owasp2025-[0-9a-f]{12}\+norm-[0-9]+\+fp-([1-9][0-9]*)\Z")


class ComparisonInputs:
    def __init__(self, session: Session) -> None:
        self._session = session

    def project_id(self, scan_id: UUID) -> UUID | None:
        return self._session.scalar(select(ScanModel.project_id).where(ScanModel.id == scan_id))

    def scan(self, scan_id: UUID) -> ScanEvidence | None:
        model = self._session.get(ScanModel, scan_id)
        if model is None:
            return None
        grant = ScopeGrantRepository(self._session).get(model.scope_grant_id)
        if grant is None:
            raise ValueError("scan 引用的 grant 不存在")
        runs = self._runs(model)
        identities = tuple(
            (run.mapping_version, run.taxonomy_sha256)
            if run.mapping_version is not None and run.taxonomy_sha256 is not None
            else None
            for run in runs
        )
        mapping = mapping_identity(identities)
        version = _VERSION.fullmatch(mapping[0]) if mapping else None
        spec = (
            self._session.scalar(
                select(ApiSpecModel.document_sha256).where(ApiSpecModel.id == model.api_spec_id)
            )
            if model.api_spec_id is not None
            else None
        )
        return ScanEvidence(
            scan=ScanFacts(
                scan_id=model.id,
                project_id=model.project_id,
                target_id=model.target_id,
                queue_position=model.queue_position,
                status=ScanStatus(model.status),
                fixture=any(run.engine == Engine.FAKE.value for run in runs),
                profile=model.scan_profile,
                scope_sha256=_scope_hash(grant.scope),
                has_spec=model.api_spec_id is not None,
                spec_sha256=spec.hex() if spec else None,
                auth_role=model.auth_role,
                definitions=tuple((run.engine, run.definition_sha256) for run in runs),
                fingerprint_version=version.group(1) if version else None,
                mapping_version=mapping[0] if mapping else None,
                taxonomy_sha256=mapping[1] if mapping else None,
            ),
            origin=model.target_origin,
            scope=ScopeRules.of(grant.scope),
            runs=runs,
        )

    def findings(self, baseline: UUID, current: UUID) -> tuple[FindingFacts, ...]:
        from secscan.comparisons.observations import finding_inputs

        return finding_inputs(self._session, (baseline, current))

    def _runs(self, scan: ScanModel) -> tuple[RunFacts, ...]:
        models = self._session.scalars(
            select(ScannerRunModel)
            .where(ScannerRunModel.scan_id == scan.id)
            .order_by(ScannerRunModel.sequence)
        ).all()
        preflight = next((row for row in models if row.engine == Engine.PREFLIGHT.value), None)
        checked = (
            PreflightResult(preflight.preflight_result)
            if preflight
            and preflight.status == RunStatus.SUCCEEDED.value
            and preflight.preflight_result is not None
            else None
        )
        locations = self._locations(scan.id)
        complete = self._complete_observations(scan.id)
        return tuple(
            RunFacts(
                run_id=row.id,
                engine=row.engine,
                status=RunStatus(row.status),
                definition_sha256=_definition(row),
                mapping_version=row.link_mapping_version,
                taxonomy_sha256=row.link_taxonomy_sha256,
                identity_verified=identity_verified(scan.auth_role, checked, row.result_details),
                time_limit_reached=_time_limit(row),
                locations_recorded=row.locations_recorded,
                locations=locations.get(row.id, ()),
                observations_complete=(
                    row.results_recorded
                    and row.observation_count is not None
                    and complete.get(row.id, (0, 0))
                    == (row.observation_count, row.observation_count)
                ),
            )
            for row in models
            if row.engine != Engine.PREFLIGHT.value
        )

    def _locations(self, scan_id: UUID) -> dict[UUID, tuple[LocationFact, ...]]:
        rows = self._session.scalars(
            select(RunLocationModel).where(RunLocationModel.scan_id == scan_id)
        )
        grouped: dict[UUID, list[LocationFact]] = {}
        for row in rows:
            grouped.setdefault(row.scanner_run_id, []).append(
                LocationFact(
                    row.method,
                    row.path_sha256,
                    row.answered,
                    row.authenticated,
                )
            )
        return {run_id: tuple(items) for run_id, items in grouped.items()}

    def _complete_observations(self, scan_id: UUID) -> dict[UUID, tuple[int, int]]:
        rows = self._session.execute(
            select(
                ObservationModel.scanner_run_id,
                func.count(ObservationModel.id),
                func.count(FindingObservationModel.observation_id),
            )
            .outerjoin(
                FindingObservationModel,
                FindingObservationModel.observation_id == ObservationModel.id,
            )
            .where(ObservationModel.scan_id == scan_id)
            .group_by(ObservationModel.scanner_run_id)
        )
        return {row[0]: (row[1], row[2]) for row in rows}


def _scope_hash(scope: Scope) -> str:
    document = {
        "origins": sorted(map(str, scope.origins)),
        "ips": sorted(map(str, scope.ips)),
        "paths": sorted(scope.paths),
        "allow_all_paths": scope.allow_all_paths,
        "excluded": sorted(scope.excluded_paths),
        "methods": sorted(scope.methods),
    }
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _definition(row: ScannerRunModel) -> str | None:
    rules = row.rule_set
    if not rules or any(not isinstance(rule, str) for rule in rules) or rules != sorted(set(rules)):
        return None
    digest = hashlib.sha256(
        json.dumps(rules, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    if digest != row.rule_set_sha256:
        return None
    return definition_digest(
        EngineProvenance(
            row.engine,
            row.image_ref,
            row.engine_version,
            row.parser_version,
            row.profile_definition_sha256,
            row.rule_set_sha256,
            _components(row),
        )
    )


def _time_limit(row: ScannerRunModel) -> bool | None:
    details = row.result_details
    if details is None:
        return None
    reached = details.get("time_limit_reached")
    traffic = details.get("guard_traffic")
    exhausted = traffic.get("exhausted") if isinstance(traffic, dict) else None
    if reached is True or exhausted is True or row.status == RunStatus.TIMED_OUT.value:
        return True
    return False if reached is False and exhausted is False else None


def _components(row: ScannerRunModel) -> tuple[tuple[str, str], ...] | None:
    value = row.result_details.get("components") if row.result_details else None
    if not isinstance(value, dict) or any(not isinstance(item, str) for item in value.values()):
        return None
    return tuple(sorted((name, item) for name, item in value.items() if isinstance(item, str)))
