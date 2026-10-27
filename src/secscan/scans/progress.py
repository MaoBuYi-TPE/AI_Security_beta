"""scan 與 run 的狀態轉換（docs/DECISIONS.md §13.4、§13.5）；佇列與取消共用。

- 所有改 scan 或 run 的寫入都先以 FOR UPDATE 鎖住 scan，再改 run：鎖的順序固定，不會死結；
  持有 scan 的鎖時，它的 run 不會被別人改變（心跳只延長 lease）。
- scan 的狀態由所有 run 彙總（aggregate），和 run 的轉換在同一個 transaction 寫入。
- 事件的 sequence 在持有 scan 的鎖時取得：依 commit 的順序、沒有間隔。
- 寫入的時間用 statement_timestamp()：同一列的欄位是同一個時間；鎖在前一個 statement 已經取得，
  所以不會是等鎖之前的時間。判斷 lease 是否過期用 clock_timestamp()（實際的時間）。
"""

from dataclasses import dataclass, replace
from datetime import timedelta
from uuid import UUID

from sqlalchemy import ColumnElement, DateTime, Row, Select, func, select, update
from sqlalchemy.orm import Session

from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.lifecycle import (
    LEASED_RUN_STATUSES,
    TERMINAL_RUN_STATUSES,
    TERMINAL_SCAN_STATUSES,
    RunErrorCode,
    RunStatus,
    ScanStatus,
    aggregate,
    plan_run_transition,
)
from secscan.scans.domain.model import (
    EventType,
    cancel_requested_payload,
    run_status_payload,
    scan_status_payload,
)
from secscan.scans.models import ScanModel, ScannerRunModel
from secscan.scans.repository import ScanRepository
from secscan.targets.domain import Origin, parse_origin

# lease 的長度（ARCHITECTURE.md §9：每 5 秒心跳、lease 30 秒）。
LEASE_DURATION = timedelta(seconds=30)


@dataclass(frozen=True, slots=True)
class LockedScan:
    """以 FOR UPDATE 鎖住的 scan：狀態轉換需要的欄位。"""

    id: UUID
    project_id: UUID
    target_id: UUID
    target_origin: Origin
    scope_grant_id: UUID
    auth_profile_id: UUID | None
    auth_profile_version: int | None
    created_by_key_id: UUID
    status: ScanStatus
    cancel_requested: bool

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_SCAN_STATUSES


@dataclass(frozen=True, slots=True)
class RunState:
    id: UUID
    scan_id: UUID
    engine: Engine
    sequence: int
    status: RunStatus


def now() -> ColumnElement[DateTime]:
    """這個 statement 開始的時間（同一列的欄位一致）。"""
    return func.statement_timestamp(type_=DateTime(timezone=True))


class ScanProgress:
    def __init__(self, session: Session) -> None:
        self._session = session
        self._scans = ScanRepository(session)

    def lock_scan(self, scan_id: UUID) -> LockedScan | None:
        row = self._session.execute(
            select(
                ScanModel.id,
                ScanModel.project_id,
                ScanModel.target_id,
                ScanModel.target_origin,
                ScanModel.scope_grant_id,
                ScanModel.auth_profile_id,
                ScanModel.auth_profile_version,
                ScanModel.created_by_key_id,
                ScanModel.status,
                ScanModel.cancel_requested_at,
            )
            .where(ScanModel.id == scan_id)
            .with_for_update()
        ).first()
        if row is None:
            return None
        return LockedScan(
            id=row.id,
            project_id=row.project_id,
            target_id=row.target_id,
            target_origin=parse_origin(row.target_origin),
            scope_grant_id=row.scope_grant_id,
            auth_profile_id=row.auth_profile_id,
            auth_profile_version=row.auth_profile_version,
            created_by_key_id=row.created_by_key_id,
            status=ScanStatus(row.status),
            cancel_requested=row.cancel_requested_at is not None,
        )

    def runs(self, scan_id: UUID) -> tuple[RunState, ...]:
        rows = self._session.execute(
            _run_columns()
            .where(ScannerRunModel.scan_id == scan_id)
            .order_by(ScannerRunModel.sequence)
        )
        return tuple(_run_state(row) for row in rows)

    def run(
        self, run_id: UUID, *, conditions: tuple[ColumnElement[bool], ...] = ()
    ) -> RunState | None:
        """以新的 statement 讀 run 目前的狀態並鎖住它（呼叫端持有 scan 的鎖）。

        conditions 不成立時回 None。
        """
        row = self._session.execute(
            _run_columns().where(ScannerRunModel.id == run_id, *conditions).with_for_update()
        ).first()
        return _run_state(row) if row is not None else None

    def request_cancel(self, scan: LockedScan) -> LockedScan:
        """記下取消的要求（只記一次；trigger 也禁止再改）。"""
        self._session.execute(
            update(ScanModel)
            .where(ScanModel.id == scan.id)
            .values(cancel_requested_at=now())
            .execution_options(synchronize_session=False)
        )
        self._scans.append_event(
            scan.id, EventType.SCAN_CANCEL_REQUESTED, cancel_requested_payload(previous=scan.status)
        )
        return replace(scan, cancel_requested=True)

    def move(
        self,
        scan: LockedScan,
        run: RunState,
        to: RunStatus,
        *,
        error_code: RunErrorCode | None = None,
        lease_owner: str | None = None,
    ) -> None:
        """依 domain 的轉換表改變 run，並寫入事件。

        lease_owner 只在認領時給：寫入新的 lease。轉到不需要 lease 的狀態（collected、終止）時清除
        lease；其他轉換保留原本的 lease。只有要求過取消的 scan，run 才能轉到 cancelling
        （DB 的 ck_scans_cancel_matches_status 也這樣要求；審查發現）。
        """
        plan_run_transition(run.status, to, error_code=error_code)
        if to is RunStatus.CANCELLING and not scan.cancel_requested:
            raise ValueError("只有要求過取消的 scan，run 才能轉到 cancelling")
        values: dict[str, object] = {
            "status": to.value,
            "error_code": error_code.value if error_code is not None else None,
        }
        if to not in LEASED_RUN_STATUSES:
            values.update(lease_owner=None, lease_expires_at=None, heartbeat_at=None)
        elif lease_owner is not None:
            values.update(
                lease_owner=lease_owner,
                lease_expires_at=now() + LEASE_DURATION,
                heartbeat_at=now(),
            )
        elif run.status not in LEASED_RUN_STATUSES:
            raise ValueError("認領 run 時必須給 lease_owner")
        if run.status is RunStatus.QUEUED and to is RunStatus.PREPARING:
            values["started_at"] = now()
        if to in TERMINAL_RUN_STATUSES:
            values["finished_at"] = now()
        self._session.execute(
            update(ScannerRunModel)
            .where(ScannerRunModel.id == run.id)
            .values(**values)
            .execution_options(synchronize_session=False)
        )
        payload = run_status_payload(
            engine=run.engine, status=to, previous=run.status, error_code=error_code
        )
        self._scans.append_event(scan.id, EventType.RUN_STATUS, payload, run_id=run.id)

    def settle(self, scan: LockedScan) -> ScanStatus:
        """由所有 run 重新彙總 scan 的狀態；改變時寫入狀態、結束的時間與事件。"""
        status = aggregate(
            (run.status for run in self.runs(scan.id)), cancel_requested=scan.cancel_requested
        )
        if status is scan.status:
            return status
        values: dict[str, object] = {"status": status.value}
        if status in TERMINAL_SCAN_STATUSES:
            values["finished_at"] = now()
        self._session.execute(
            update(ScanModel)
            .where(ScanModel.id == scan.id)
            .values(**values)
            .execution_options(synchronize_session=False)
        )
        self._scans.append_event(
            scan.id, EventType.SCAN_STATUS, scan_status_payload(status=status, previous=scan.status)
        )
        return status


def _run_columns() -> Select[UUID, UUID, str, int, str]:
    return select(
        ScannerRunModel.id,
        ScannerRunModel.scan_id,
        ScannerRunModel.engine,
        ScannerRunModel.sequence,
        ScannerRunModel.status,
    )


def _run_state(row: Row[UUID, UUID, str, int, str]) -> RunState:
    run_id, scan_id, engine, sequence, status = row
    return RunState(
        id=run_id,
        scan_id=scan_id,
        engine=Engine(engine),
        sequence=sequence,
        status=RunStatus(status),
    )
