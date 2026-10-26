"""PostgreSQL 工作佇列（docs/DECISIONS.md §3、§13.5）：runner 與 worker 用的操作。

- QueueOperations：在呼叫端的 transaction 中執行（併發測試可以在持有鎖時直接呼叫）。
- ScanQueue：每個操作一個短 transaction；長時間的工作（掃描、等待）不持有 transaction。

認領以 `FOR UPDATE OF scans SKIP LOCKED` 先鎖 scan，再改 run [S28]；ORDER BY 搭配鎖可能用到舊的
資料，所以鎖到之後以新的 statement 再確認一次條件。lease 過期不代表工作已經停止
（ARCHITECTURE.md §9）：過期的 lease 不能延長，也不會被別人認領，只由對帳處理。
"""

from collections.abc import Callable, Collection
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import ColumnElement, Select, exists, func, select, update
from sqlalchemy.orm import Session, aliased, sessionmaker

from secscan.auth_profiles.repository import AuthProfileRepository
from secscan.grants.domain.lifecycle import GrantUnusableError, check_usable
from secscan.grants.repository import ScopeGrantRepository
from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.lifecycle import (
    GATE_ERROR_CODES,
    TRAFFIC_STOPPED_RUN_STATUSES,
    RunErrorCode,
    RunStatus,
    ScanStatus,
)
from secscan.scans.domain.model import Lease
from secscan.scans.models import ScanModel, ScannerRunModel
from secscan.scans.progress import LEASE_DURATION, LockedScan, RunState, ScanProgress, now
from secscan.targets.domain import LabNetwork, OutsideLabError
from secscan.targets.repository import TargetRepository

__all__ = [
    "HEARTBEAT_INTERVAL",
    "LEASE_DURATION",
    "Heartbeat",
    "LeaseLostError",
    "Progress",
    "QueueOperations",
    "ScanQueue",
]

HEARTBEAT_INTERVAL = timedelta(seconds=5)
# 鎖到的 scan 已經不符合條件（別人剛改了它）時，以新的快照再找幾次。
MAX_CLAIM_ATTEMPTS = 3
MAX_RECONCILED_PER_CALL = 100


class LeaseLostError(Exception):
    """lease 已過期，或不屬於這個 owner：不能再改變這個 run（fencing）。"""


@dataclass(frozen=True, slots=True)
class Heartbeat:
    valid: bool
    cancel_requested: bool


@dataclass(frozen=True, slots=True)
class Progress:
    """轉換之後 run 與 scan 的狀態。"""

    run_status: RunStatus
    scan_status: ScanStatus


class QueueOperations:
    def __init__(self, session: Session, *, lab: LabNetwork) -> None:
        self._session = session
        self._progress = ScanProgress(session)
        self._targets = TargetRepository(session)
        self._grants = ScopeGrantRepository(session)
        self._profiles = AuthProfileRepository(session)
        self._lab = lab

    def claim(self, owner: str, engines: Collection[Engine]) -> Lease | None:
        """runner 認領 queued 的 run → preparing，寫入新的 lease。"""
        return self._claim(RunStatus.QUEUED, RunStatus.PREPARING, owner, engines, run_id=None)

    def claim_collected(
        self, owner: str, engines: Collection[Engine], *, run_id: UUID | None = None
    ) -> Lease | None:
        """worker 認領 collected 的 run → normalizing。run_id 給定時只認領那一個（自己收集的）。"""
        return self._claim(
            RunStatus.COLLECTED, RunStatus.NORMALIZING, owner, engines, run_id=run_id
        )

    def heartbeat(self, lease: Lease) -> Heartbeat:
        """延長還沒過期的 lease；回報 scan 是否被要求取消。只改 run 的列，不等 scan 的鎖。"""
        scan_id = self._session.execute(
            update(ScannerRunModel)
            .where(*_holds(lease))
            .values(lease_expires_at=now() + LEASE_DURATION, heartbeat_at=now())
            .returning(ScannerRunModel.scan_id)
            .execution_options(synchronize_session=False)
        ).scalar()
        if scan_id is None:
            return Heartbeat(valid=False, cancel_requested=False)
        cancel_requested_at = self._session.scalar(
            select(ScanModel.cancel_requested_at).where(ScanModel.id == scan_id)
        )
        return Heartbeat(valid=True, cancel_requested=cancel_requested_at is not None)

    def prepare(self, lease: Lease, *, clock: Callable[[], datetime]) -> Progress:
        """runner 啟動前：要求過取消 → cancelling；gate 或綁定的 profile 版本不再有效 → failed；
        都通過 → running。target、grant 與 profile 的版本以 FOR SHARE 鎖住（在 scan 之後）。"""
        scan, run = self._fenced(lease)
        if scan.cancel_requested:
            return self._move(scan, run, RunStatus.CANCELLING)
        error_code = self._gate(scan, clock) or self._binding(scan)
        if error_code is not None:
            return self._move(scan, run, RunStatus.FAILED, error_code)
        return self._move(scan, run, RunStatus.RUNNING)

    def advance(
        self, lease: Lease, to: RunStatus, *, error_code: RunErrorCode | None = None
    ) -> Progress:
        """持有 lease 的 run 依轉換表轉換；collected 與終止時清除 lease。"""
        scan, run = self._fenced(lease)
        return self._move(scan, run, to, error_code)

    def reconcile_expired(self, engines: Collection[Engine]) -> int:
        """lease 過期的 run：runner 階段 → interrupted（LEASE_EXPIRED）；normalizing → collected。

        只能用在確定已經停止的引擎（T09 只有 fake：不發流量、沒有容器）；容器的對帳在 T13。
        """
        expired = (
            ScannerRunModel.lease_owner.is_not(None),
            ScannerRunModel.lease_expires_at <= func.clock_timestamp(),
        )
        reconciled = 0
        for _ in range(MAX_RECONCILED_PER_CALL):
            candidate = self._session.execute(
                _join_runs()
                .where(ScannerRunModel.engine.in_(_values(engines)), *expired)
                .order_by(ScanModel.queue_position, ScannerRunModel.sequence)
                .limit(1)
                .with_for_update(of=ScanModel, skip_locked=True)
            ).first()
            if candidate is None:
                break
            scan = self._progress.lock_scan(candidate.scan_id)
            run = self._progress.run(candidate.run_id, conditions=expired)
            if scan is None or run is None:
                continue
            if run.status is RunStatus.NORMALIZING:
                self._move(scan, run, RunStatus.COLLECTED)
            else:
                self._move(scan, run, RunStatus.INTERRUPTED, RunErrorCode.LEASE_EXPIRED)
            reconciled += 1
        return reconciled

    def _claim(
        self,
        waiting: RunStatus,
        to: RunStatus,
        owner: str,
        engines: Collection[Engine],
        *,
        run_id: UUID | None,
    ) -> Lease | None:
        for _ in range(MAX_CLAIM_ATTEMPTS):
            candidate = self._session.execute(
                _join_runs()
                .where(*_claimable(waiting, engines, run_id))
                .order_by(ScanModel.queue_position, ScannerRunModel.sequence)
                .limit(1)
                .with_for_update(of=ScanModel, skip_locked=True)
            ).first()
            if candidate is None:
                return None
            # 已經鎖住 scan：新的 statement 看到的是 commit 之後的最新狀態，再確認一次條件。
            scan = self._progress.lock_scan(candidate.scan_id)
            run = self._progress.run(
                candidate.run_id, conditions=tuple(_claimable(waiting, engines, run_id))
            )
            if scan is None or run is None:
                continue
            self._progress.move(scan, run, to, lease_owner=owner)
            self._progress.settle(scan)
            return Lease(run_id=run.id, scan_id=scan.id, engine=run.engine, owner=owner)
        return None

    def _fenced(self, lease: Lease) -> tuple[LockedScan, RunState]:
        """先鎖 scan，再確認 lease 仍屬於這個 owner、而且還沒過期。"""
        scan = self._progress.lock_scan(lease.scan_id)
        run = self._progress.run(lease.run_id, conditions=tuple(_holds(lease)))
        if scan is None or run is None or run.scan_id != scan.id:
            raise LeaseLostError("lease 已過期或不屬於這個 runner")
        return scan, run

    def _move(
        self,
        scan: LockedScan,
        run: RunState,
        to: RunStatus,
        error_code: RunErrorCode | None = None,
    ) -> Progress:
        self._progress.move(scan, run, to, error_code=error_code)
        return Progress(run_status=to, scan_status=self._progress.settle(scan))

    def _gate(self, scan: LockedScan, clock: Callable[[], datetime]) -> RunErrorCode | None:
        """以建立 scan 時相同的規則重新判斷（§10.6）；時間在取得鎖之後才取。"""
        target = self._targets.lock(scan.target_id, shared=True)
        grant = self._grants.lock(scan.scope_grant_id, shared=True)
        if target is None or grant is None or target.origin != scan.target_origin:
            return RunErrorCode.SCOPE_MISMATCH
        try:
            check_usable(grant, target=target, lab=self._lab, now=clock())
        except GrantUnusableError as exc:
            return GATE_ERROR_CODES[exc.reason]
        except OutsideLabError:
            return RunErrorCode.SCOPE_OUTSIDE_LAB
        return None

    def _binding(self, scan: LockedScan) -> RunErrorCode | None:
        """綁定的 profile 版本被取代、密文已清除：不改用新版本，直接失敗（§12.3）。"""
        if scan.auth_profile_id is None or scan.auth_profile_version is None:
            return None
        if self._profiles.version_has_secret(
            scan.auth_profile_id, version=scan.auth_profile_version
        ):
            return None
        return RunErrorCode.AUTH_PROFILE_SUPERSEDED


class ScanQueue:
    """每個操作在自己的短 transaction 中完成（runner 與 worker 不經 HTTP）。"""

    def __init__(
        self,
        sessions: sessionmaker[Session],
        *,
        lab: LabNetwork,
        clock: Callable[[], datetime],
    ) -> None:
        self._sessions = sessions
        self._lab = lab
        self._clock = clock

    def claim(self, owner: str, engines: Collection[Engine]) -> Lease | None:
        with self._sessions.begin() as session:
            return self._operations(session).claim(owner, engines)

    def claim_collected(
        self, owner: str, engines: Collection[Engine], *, run_id: UUID | None = None
    ) -> Lease | None:
        with self._sessions.begin() as session:
            return self._operations(session).claim_collected(owner, engines, run_id=run_id)

    def heartbeat(self, lease: Lease) -> Heartbeat:
        with self._sessions.begin() as session:
            return self._operations(session).heartbeat(lease)

    def prepare(self, lease: Lease) -> Progress:
        with self._sessions.begin() as session:
            return self._operations(session).prepare(lease, clock=self._clock)

    def advance(
        self, lease: Lease, to: RunStatus, *, error_code: RunErrorCode | None = None
    ) -> Progress:
        with self._sessions.begin() as session:
            return self._operations(session).advance(lease, to, error_code=error_code)

    def reconcile_expired(self, engines: Collection[Engine]) -> int:
        with self._sessions.begin() as session:
            return self._operations(session).reconcile_expired(engines)

    def _operations(self, session: Session) -> QueueOperations:
        return QueueOperations(session, lab=self._lab)


def _join_runs() -> Select[UUID, UUID]:
    return select(ScanModel.id.label("scan_id"), ScannerRunModel.id.label("run_id")).join(
        ScannerRunModel, ScannerRunModel.scan_id == ScanModel.id
    )


def _claimable(
    waiting: RunStatus, engines: Collection[Engine], run_id: UUID | None
) -> list[ColumnElement[bool]]:
    """可以認領的 run：狀態、引擎；runner 認領時 scan 沒有被要求取消、前面的 run 都不再送出流量。"""
    conditions: list[ColumnElement[bool]] = [
        ScannerRunModel.status == waiting.value,
        ScannerRunModel.engine.in_(_values(engines)),
    ]
    if run_id is not None:
        conditions.append(ScannerRunModel.id == run_id)
    if waiting is RunStatus.QUEUED:
        earlier = aliased(ScannerRunModel)
        conditions.append(
            ~exists().where(
                earlier.scan_id == ScannerRunModel.scan_id,
                earlier.sequence < ScannerRunModel.sequence,
                earlier.status.not_in(_values(TRAFFIC_STOPPED_RUN_STATUSES)),
            )
        )
        cancelled = aliased(ScanModel)
        conditions.append(
            ~exists().where(
                cancelled.id == ScannerRunModel.scan_id, cancelled.cancel_requested_at.is_not(None)
            )
        )
    return conditions


def _holds(lease: Lease) -> tuple[ColumnElement[bool], ...]:
    """lease 仍屬於這個 owner、而且還沒過期（以 DB 的實際時間判斷）。"""
    return (
        ScannerRunModel.id == lease.run_id,
        ScannerRunModel.scan_id == lease.scan_id,
        ScannerRunModel.lease_owner == lease.owner,
        ScannerRunModel.lease_expires_at > func.clock_timestamp(),
    )


def _values(items: Collection[Engine] | Collection[RunStatus]) -> list[str]:
    return sorted(item.value for item in items)
