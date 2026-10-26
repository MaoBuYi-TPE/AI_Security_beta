"""scans、scanner_runs、scan_events、scan_operations 的寫入與查詢；回傳 frozen domain model。

誰能看到哪些 scan 由 service 決定。狀態的轉換（佇列與取消）在 scans.progress：所有改 scan 或 run
的寫入都先鎖住 scan。讀取一律以 DB 的最新值覆蓋已載入的物件（佇列以 Core 的 UPDATE 改資料）。
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import ColumnElement, Select, func, insert, select
from sqlalchemy.orm import Session

from secscan.api_keys.domain import AllProjects, ProjectScope
from secscan.core.db import flush_or_raise
from secscan.core.json_types import JsonObject
from secscan.core.pagination import Page, PageRequest
from secscan.grants.domain.matching import IneligibleReason
from secscan.grants.domain.scope import Budget
from secscan.grants.models import ScopeGrantModel
from secscan.scans.domain.catalog import Engine, ScanProfile
from secscan.scans.domain.lifecycle import ACTIVE_SCAN_STATUSES, RunErrorCode, RunStatus, ScanStatus
from secscan.scans.domain.model import (
    ANONYMOUS_ROLE,
    AuthBinding,
    Coverage,
    EventType,
    NewScan,
    Scan,
    ScanEvent,
    ScannerRun,
    VersionRef,
)
from secscan.scans.models import ScanEventModel, ScanModel, ScannerRunModel, ScanOperationModel
from secscan.specs.models import ApiSpecModel
from secscan.targets.domain import parse_origin


@dataclass(frozen=True, slots=True)
class KeyedScan:
    """某個 Idempotency-Key 建立的 scan，與當時請求內容的 fingerprint。"""

    scan_id: UUID
    request_sha256: bytes


@dataclass(frozen=True, slots=True)
class ScanFilters:
    """清單的篩選；None 代表不篩選。"""

    target_id: UUID | None = None
    status: ScanStatus | None = None
    created_after: datetime | None = None
    created_before: datetime | None = None


class ScanRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def find_by_key(self, project_id: UUID, idempotency_key: str) -> KeyedScan | None:
        row = self._session.execute(
            select(ScanModel.id, ScanModel.request_sha256).where(
                ScanModel.project_id == project_id, ScanModel.idempotency_key == idempotency_key
            )
        ).first()
        return KeyedScan(scan_id=row.id, request_sha256=row.request_sha256) if row else None

    def has_active(self, target_id: UUID) -> bool:
        """已 commit 的進行中 scan（同時建立的由 uq_scans_active_target 判斷）。"""
        active = [status.value for status in ACTIVE_SCAN_STATUSES]
        return (
            self._session.scalar(
                select(ScanModel.id)
                .where(ScanModel.target_id == target_id, ScanModel.status.in_(active))
                .limit(1)
            )
            is not None
        )

    def count_created_since(self, target_id: UUID, since: datetime) -> int:
        return (
            self._session.scalar(
                select(func.count())
                .select_from(ScanModel)
                .where(ScanModel.target_id == target_id, ScanModel.created_at > since)
            )
            or 0
        )

    def create(self, new_scan: NewScan) -> UUID:
        """寫入 scan（queued）、它的 run 與凍結的 operation。

        scan 在 savepoint 中寫入：撞到唯一索引（同一個 key、同一個 target 已有進行中的 scan）時拋出
        ConstraintViolationError，savepoint 回滾，呼叫端的 transaction 仍可繼續查詢。
        """
        auth = new_scan.auth
        budget = new_scan.budget
        model = ScanModel(
            project_id=new_scan.project_id,
            target_id=new_scan.target_id,
            target_origin=str(new_scan.target_origin),
            scope_grant_id=new_scan.scope_grant_id,
            api_spec_id=new_scan.api_spec_id,
            auth_profile_id=auth.profile_id if auth is not None else None,
            auth_profile_version=auth.version if auth is not None else None,
            auth_role=auth.role_label if auth is not None else ANONYMOUS_ROLE,
            scan_profile=new_scan.profile.value,
            requests_per_second=budget.requests_per_second,
            max_requests=budget.max_requests,
            max_duration_seconds=budget.max_duration_seconds,
            status=ScanStatus.QUEUED.value,
            idempotency_key=new_scan.idempotency_key,
            request_sha256=new_scan.request_sha256,
            created_by_key_id=new_scan.created_by_key_id,
        )
        with self._session.begin_nested():
            self._session.add(model)
            flush_or_raise(self._session)
        self._session.add_all(
            ScannerRunModel(
                scan_id=model.id,
                engine=run.engine.value,
                sequence=run.sequence,
                status=RunStatus.QUEUED.value,
            )
            for run in new_scan.runs
        )
        if new_scan.operations:
            self._session.execute(
                insert(ScanOperationModel),
                [
                    {
                        "scan_id": model.id,
                        "ordinal": operation.ordinal,
                        "method": operation.method,
                        "path": operation.path,
                        "operation_id": operation.operation_id,
                        "ineligible_reason": _reason_value(operation.ineligible_reason),
                    }
                    for operation in new_scan.operations
                ],
            )
        flush_or_raise(self._session)
        return model.id

    def append_event(
        self,
        scan_id: UUID,
        event_type: EventType,
        payload: JsonObject,
        *,
        run_id: UUID | None = None,
    ) -> None:
        """下一個 sequence 是這個 scan 目前最大的加 1。

        呼叫端必須持有 scan 的鎖（或剛建立這個 scan）：sequence 才會依 commit 的順序、沒有間隔。
        """
        next_sequence = (
            select(func.coalesce(func.max(ScanEventModel.sequence), 0) + 1)
            .where(ScanEventModel.scan_id == scan_id)
            .scalar_subquery()
        )
        self._session.execute(
            insert(ScanEventModel).values(
                scan_id=scan_id,
                sequence=next_sequence,
                event_type=event_type.value,
                scanner_run_id=run_id,
                payload=payload,
            )
        )

    def get(self, scan_id: UUID) -> Scan | None:
        scans = self._load(_with_versions().where(ScanModel.id == scan_id))
        return scans[0] if scans else None

    def list(self, scope: ProjectScope, filters: ScanFilters, page: PageRequest) -> Page[Scan]:
        """新的在前（同時間再依佇列的先後）。"""
        conditions = _conditions(scope, filters)
        total = (
            self._session.scalar(select(func.count()).select_from(ScanModel).where(*conditions))
            or 0
        )
        items = self._load(
            _with_versions()
            .where(*conditions)
            .order_by(ScanModel.created_at.desc(), ScanModel.queue_position.desc())
            .offset(page.offset)
            .limit(page.limit)
        )
        return Page(items=items, total=total, request=page)

    def events(self, scan_id: UUID, *, after_sequence: int, limit: int) -> tuple[ScanEvent, ...]:
        models = self._session.scalars(
            select(ScanEventModel)
            .where(ScanEventModel.scan_id == scan_id, ScanEventModel.sequence > after_sequence)
            .order_by(ScanEventModel.sequence)
            .limit(limit)
        )
        return tuple(
            ScanEvent(
                scan_id=model.scan_id,
                sequence=model.sequence,
                type=EventType(model.event_type),
                scanner_run_id=model.scanner_run_id,
                payload=model.payload,
                created_at=model.created_at,
            )
            for model in models
        )

    def _load(self, statement: Select[ScanModel, int, int]) -> tuple[Scan, ...]:
        rows = self._session.execute(statement.execution_options(populate_existing=True)).all()
        scan_ids = [row[0].id for row in rows]
        runs = self._runs(scan_ids)
        coverage = self._coverage(scan_ids)
        return tuple(
            _to_domain(
                model,
                grant_version=grant_version,
                spec_version=spec_version,
                runs=runs.get(model.id, ()),
                coverage=coverage.get(model.id),
            )
            for model, grant_version, spec_version in rows
        )

    def _runs(self, scan_ids: Sequence[UUID]) -> dict[UUID, tuple[ScannerRun, ...]]:
        models = self._session.scalars(
            select(ScannerRunModel)
            .where(ScannerRunModel.scan_id.in_(scan_ids))
            .order_by(ScannerRunModel.scan_id, ScannerRunModel.sequence)
            .execution_options(populate_existing=True)
        )
        grouped: dict[UUID, list[ScannerRun]] = {}
        for model in models:
            grouped.setdefault(model.scan_id, []).append(_run(model))
        return {scan_id: tuple(runs) for scan_id, runs in grouped.items()}

    def _coverage(self, scan_ids: Sequence[UUID]) -> dict[UUID, Coverage]:
        eligible = ScanOperationModel.ineligible_reason.is_(None)
        rows = self._session.execute(
            select(
                ScanOperationModel.scan_id,
                func.count().filter(eligible),
                func.count().filter(~eligible),
            )
            .where(ScanOperationModel.scan_id.in_(scan_ids))
            .group_by(ScanOperationModel.scan_id)
        )
        return {
            scan_id: Coverage(eligible_operations=yes, ineligible_operations=no)
            for scan_id, yes, no in rows
        }


def _with_versions() -> Select[ScanModel, int, int]:
    """scan 與 grant、規格的版本。沒有規格的 scan（outer join）規格的版本是 None。"""
    return (
        select(ScanModel, ScopeGrantModel.version, ApiSpecModel.version)
        .join(ScopeGrantModel, ScopeGrantModel.id == ScanModel.scope_grant_id)
        .outerjoin(ApiSpecModel, ApiSpecModel.id == ScanModel.api_spec_id)
    )


def _conditions(scope: ProjectScope, filters: ScanFilters) -> list[ColumnElement[bool]]:
    conditions: list[ColumnElement[bool]] = []
    if not isinstance(scope, AllProjects):
        conditions.append(ScanModel.project_id == scope.project_id)
    if filters.target_id is not None:
        conditions.append(ScanModel.target_id == filters.target_id)
    if filters.status is not None:
        conditions.append(ScanModel.status == filters.status.value)
    if filters.created_after is not None:
        conditions.append(ScanModel.created_at >= filters.created_after)
    if filters.created_before is not None:
        conditions.append(ScanModel.created_at < filters.created_before)
    return conditions


def _to_domain(
    model: ScanModel,
    *,
    grant_version: int,
    spec_version: int | None,
    runs: Iterable[ScannerRun],
    coverage: Coverage | None,
) -> Scan:
    # 讀回的值再經過 domain 的規則：DB 中不合規則的資料會讓讀取失敗（fail closed）。
    auth = None
    if model.auth_profile_id is not None and model.auth_profile_version is not None:
        auth = AuthBinding(
            profile_id=model.auth_profile_id,
            version=model.auth_profile_version,
            role_label=model.auth_role,
        )
    api_spec = None
    if model.api_spec_id is not None and spec_version is not None:
        api_spec = VersionRef(id=model.api_spec_id, version=spec_version)
    return Scan(
        id=model.id,
        project_id=model.project_id,
        target_id=model.target_id,
        target_origin=parse_origin(model.target_origin),
        status=ScanStatus(model.status),
        profile=ScanProfile(model.scan_profile),
        scope_grant=VersionRef(id=model.scope_grant_id, version=grant_version),
        api_spec=api_spec,
        auth=auth,
        budget=Budget(
            requests_per_second=model.requests_per_second,
            max_requests=model.max_requests,
            max_duration_seconds=model.max_duration_seconds,
        ),
        runs=tuple(runs),
        coverage=coverage if model.api_spec_id is not None else None,
        cancel_requested_at=model.cancel_requested_at,
        created_by_key_id=model.created_by_key_id,
        created_at=model.created_at,
        finished_at=model.finished_at,
    )


def _run(model: ScannerRunModel) -> ScannerRun:
    return ScannerRun(
        id=model.id,
        scan_id=model.scan_id,
        engine=Engine(model.engine),
        sequence=model.sequence,
        status=RunStatus(model.status),
        error_code=RunErrorCode(model.error_code) if model.error_code is not None else None,
        started_at=model.started_at,
        finished_at=model.finished_at,
        created_at=model.created_at,
    )


def _reason_value(reason: IneligibleReason | None) -> str | None:
    return reason.value if reason is not None else None
