"""triage 需要的唯讀查詢（PATCH 的證據門檻）；寫入在 findings.triage_records。"""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import exists, func, select
from sqlalchemy.orm import Session

from secscan.findings.domain.fingerprint import RouteSource
from secscan.findings.models import FindingModel, FindingObservationModel
from secscan.scans.domain.lifecycle import ACTIVE_SCAN_STATUSES
from secscan.scans.models import ObservationModel, ScanModel
from secscan.targets.domain import parse_origin
from secscan.targets.models import TargetModel
from secscan.triage.domain.attestation import FindingLocation, TargetHost


@dataclass(frozen=True, slots=True)
class FindingFacts:
    target_id: UUID
    project_id: UUID
    location: FindingLocation
    target: TargetHost


class TriageQueries:
    def __init__(self, session: Session) -> None:
        self._session = session

    def finding(self, finding_id: UUID) -> FindingFacts | None:
        row = self._session.execute(
            select(
                FindingModel.target_id,
                FindingModel.method,
                FindingModel.route,
                FindingModel.route_source,
                FindingModel.parameter_name,
                FindingModel.auth_role,
                TargetModel.project_id,
                TargetModel.canonical_origin,
            )
            .join(TargetModel, TargetModel.id == FindingModel.target_id)
            .where(FindingModel.id == finding_id)
        ).first()
        if row is None:
            return None
        origin = parse_origin(row.canonical_origin)
        location = FindingLocation(
            method=row.method,
            route=row.route,
            route_source=RouteSource(row.route_source),
            parameter_name=row.parameter_name,
            auth_role=row.auth_role,
        )
        return FindingFacts(
            row.target_id, row.project_id, location, TargetHost(origin.host, origin.port)
        )

    def now(self) -> datetime:
        """DB 的時間（transaction 開始時）：人工複測的時間以它為準，不信任 client 或 API 的時鐘。"""
        value: datetime = self._session.execute(select(func.now())).scalar_one()
        return value

    def target_busy(self, target_id: UUID) -> bool:
        return bool(
            self._session.scalar(
                select(
                    exists().where(
                        ScanModel.target_id == target_id,
                        ScanModel.status.in_([status.value for status in ACTIVE_SCAN_STATUSES]),
                    )
                )
            )
        )

    def observed_after(self, finding_id: UUID, scan_id: UUID) -> bool:
        """比較的 current 之後的 scan 是否又觀察到這個 finding（條件 3：新的有效陽性觀察）。"""
        position = select(ScanModel.queue_position).where(ScanModel.id == scan_id).scalar_subquery()
        return bool(
            self._session.scalar(
                select(
                    exists()
                    .where(FindingObservationModel.finding_id == finding_id)
                    .where(ObservationModel.id == FindingObservationModel.observation_id)
                    .where(ScanModel.id == ObservationModel.scan_id)
                    .where(ScanModel.queue_position > position)
                )
            )
        )

    def last_observed_at(self, finding_id: UUID) -> datetime | None:
        """最後一次觀察到這個 finding 的 scan 的結束時間（人工複測不能比它早）。"""
        value: datetime | None = self._session.scalar(
            select(func.max(ScanModel.finished_at))
            .select_from(FindingObservationModel)
            .join(ObservationModel, ObservationModel.id == FindingObservationModel.observation_id)
            .join(ScanModel, ScanModel.id == ObservationModel.scan_id)
            .where(FindingObservationModel.finding_id == finding_id)
        )
        return value

    def linked_observations(self, finding_id: UUID, observation_ids: list[UUID]) -> int:
        if not observation_ids:
            return 0
        count = self._session.scalar(
            select(func.count())
            .select_from(FindingObservationModel)
            .where(
                FindingObservationModel.finding_id == finding_id,
                FindingObservationModel.observation_id.in_(observation_ids),
            )
        )
        return count or 0
