"""PostgreSQL 工作佇列（docs/DECISIONS.md §3、§13.5）：runner 與 worker 用的操作。

- QueueOperations：在呼叫端的 transaction 中執行（併發測試可以在持有鎖時直接呼叫）。
- ScanQueue：每個操作一個短 transaction；長時間的工作（掃描、等待）不持有 transaction。

認領以 `FOR UPDATE OF scans SKIP LOCKED` 先鎖 scan，再改 run [S28]；ORDER BY 搭配鎖可能用到舊的
資料，所以鎖到之後以新的 statement 再確認一次條件。lease 過期不代表工作已經停止
（ARCHITECTURE.md §9）：過期的 lease 不能延長，也不會被別人認領，只由對帳處理。
"""

from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import ColumnElement, Select, and_, exists, func, or_, select, update
from sqlalchemy.orm import Session, aliased, sessionmaker

from secscan.auth_profiles.domain.model import StoredSecret
from secscan.auth_profiles.domain.preflight import Preflight
from secscan.auth_profiles.repository import AuthProfileRepository
from secscan.grants.domain.lifecycle import ScopeGrant
from secscan.grants.domain.scope import Scope
from secscan.guard.domain.budget import RunBudget
from secscan.guard.domain.policy import GuardPolicyVersion
from secscan.scans.containers import ContainerRecords, PendingContainer
from secscan.scans.domain.catalog import Engine, ScanProfile
from secscan.scans.domain.lifecycle import (
    MAX_PARSE_ATTEMPTS,
    RUNNER_STAGE_RUN_STATUSES,
    TERMINAL_SCAN_STATUSES,
    TRAFFIC_STOPPED_RUN_STATUSES,
    RunErrorCode,
    RunStatus,
    ScanStatus,
)
from secscan.scans.domain.model import CONTAINER_NAME_PREFIX, Lease
from secscan.scans.domain.observation import ArtifactRecord, ParsedRun
from secscan.scans.domain.preflight import PreflightResult
from secscan.scans.gate import RunGate
from secscan.scans.leases import LeaseLostError, holds
from secscan.scans.models import ScanModel, ScannerRunModel
from secscan.scans.progress import (
    LEASE_DURATION,
    ContainerAssignment,
    LockedScan,
    RunState,
    ScanProgress,
    now,
)
from secscan.scans.run_records import (
    CoverageInputs,
    ResultContext,
    RunRecords,
    RunUsage,
    SpecInputs,
)
from secscan.targets.domain import LabNetwork, Origin

__all__ = [
    "HEARTBEAT_INTERVAL",
    "LEASE_DURATION",
    "CoverageInputs",
    "EgressScope",
    "Heartbeat",
    "Launch",
    "LeaseLostError",
    "PendingContainer",
    "Progress",
    "QueueOperations",
    "ResultContext",
    "RunReport",
    "RunUsage",
    "ScanQueue",
]

HEARTBEAT_INTERVAL = timedelta(seconds=5)
# 鎖到的 scan 已經不符合條件（別人剛改了它）時，以新的快照再找幾次。
MAX_CLAIM_ATTEMPTS = 3
MAX_RECONCILED_PER_CALL = 100


@dataclass(frozen=True, slots=True)
class Heartbeat:
    """stop_reason：lease 有效、沒有要求取消，但 gate 或建立者的 key 已不再有效（§17.5）。"""

    valid: bool
    cancel_requested: bool
    stop_reason: RunErrorCode | None = None


@dataclass(frozen=True, slots=True)
class Progress:
    """轉換之後 run 與 scan 的狀態。"""

    run_status: RunStatus
    scan_status: ScanStatus


@dataclass(frozen=True, slots=True)
class RunReport:
    """runner 或 worker 處理完一個 run 之後的狀態（CLI 與測試用）。"""

    run_id: UUID
    scan_id: UUID
    run_status: RunStatus
    scan_status: ScanStatus

    @classmethod
    def of(cls, lease: Lease, progress: Progress) -> "RunReport":
        return cls(
            run_id=lease.run_id,
            scan_id=lease.scan_id,
            run_status=progress.run_status,
            scan_status=progress.scan_status,
        )


@dataclass(frozen=True, slots=True)
class EgressScope:
    """running 的 run 能連到的範圍：guard 的 policy 由此產生（docs/DECISIONS.md §15.7、§16）。

    origin 是 scan 的 target（T11 只放行它）；scope 是 gate 剛以 FOR SHARE 確認過的 grant 範圍。
    budget 是這個 run 的速率與請求數；auth_header 是送出目標 secret 的 header（小寫；沒有綁定
    auth profile 或不讀 secret 時是 None），guard 據此記下每個請求是否帶著憑證。
    """

    origin: Origin
    scope: Scope
    valid_until: datetime
    budget: RunBudget
    auth_header: str | None


@dataclass(frozen=True, slots=True)
class Launch:
    """容器版 runner 的 prepare 結果（docs/DECISIONS.md §14.6）。

    run 轉到 running 時，已記下容器名稱與映像；secret 是綁定版本的密文（沒有 auth profile、或沒有
    開始執行時是 None），由 runner 在建立容器前才解密。egress 只在轉到 running 時才有。
    """

    progress: Progress
    max_duration_seconds: int
    secret: StoredSecret | None
    egress: EgressScope | None = None
    # preflight 的 run 要送的請求（綁定版本的定義；docs/DECISIONS.md §16.5）。
    preflight: Preflight | None = None
    # zap 的 plan 依 profile 產生（§18.4）；api profile 另外有規格的原料（§18.6）。
    scan_profile: ScanProfile | None = None
    spec: SpecInputs | None = None


class QueueOperations:
    def __init__(self, session: Session, *, lab: LabNetwork) -> None:
        self._session = session
        self._progress = ScanProgress(session)
        self._gate = RunGate(session, lab=lab)
        self._profiles = AuthProfileRepository(session)
        self._records = RunRecords(session)
        self._containers = ContainerRecords(session)
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

    def heartbeat(self, lease: Lease, *, clock: Callable[[], datetime]) -> Heartbeat:
        """延長還沒過期的 lease；回報 scan 是否被要求取消，或執行中的 run 是否必須停止。

        只改 run 的列、其餘都不加鎖讀取：不等 scan 的鎖，也不等撤銷或停用的 FOR UPDATE
        （docs/DECISIONS.md §17.5）。
        """
        scan_id = self._session.execute(
            update(ScannerRunModel)
            .where(*holds(lease))
            .values(lease_expires_at=now() + LEASE_DURATION, heartbeat_at=now())
            .returning(ScannerRunModel.scan_id)
            .execution_options(synchronize_session=False)
        ).scalar()
        if scan_id is None:
            return Heartbeat(valid=False, cancel_requested=False)
        scan = self._progress.current_scan(scan_id)
        if scan.cancel_requested:
            return Heartbeat(valid=True, cancel_requested=True)
        return Heartbeat(
            valid=True, cancel_requested=False, stop_reason=self._gate.current(scan, clock)
        )

    def prepare(self, lease: Lease, *, clock: Callable[[], datetime]) -> Progress:
        """runner 啟動前：要求過取消 → cancelling；gate、綁定的 profile 版本或建立者的 key
        不再有效 → failed；都通過 → running（唯一能讓 run 開始執行的路徑）。

        target、grant、profile 的版本與建立者的 key 以 FOR SHARE 鎖住（在 scan 之後）。
        """
        return self._prepare(lease, clock=clock, image_ref=None).progress

    def prepare_launch(
        self, lease: Lease, *, clock: Callable[[], datetime], image_ref: str
    ) -> Launch:
        """容器版的 prepare：通過時在同一個 transaction 中記下容器與映像（先記下、才建立容器），
        並以 FOR SHARE 讀出綁定版本的密文（T09 的交接：密文在 commit 之前不會被清除）。
        """
        return self._prepare(lease, clock=clock, image_ref=image_ref)

    def _prepare(
        self, lease: Lease, *, clock: Callable[[], datetime], image_ref: str | None
    ) -> Launch:
        scan, run = self._fenced(lease)
        if scan.cancel_requested:
            return self._launch(scan, self._move(scan, run, RunStatus.CANCELLING))
        error_code, grant = self._gate.locked(scan, clock)
        secret: StoredSecret | None = None
        if error_code is None:
            error_code, secret = self._binding(scan, read_secret=image_ref is not None)
        error_code = error_code or self._gate.locked_creator(scan)
        requests, seconds = self._records.remaining(
            scan.id,
            run.id,
            max_requests=scan.max_requests,
            max_duration_seconds=scan.max_duration_seconds,
        )
        if error_code is None and (requests == 0 or seconds == 0):
            error_code = RunErrorCode.BUDGET_EXHAUSTED
        if error_code is not None or grant is None:
            failed = error_code or RunErrorCode.SCOPE_MISMATCH
            return self._launch(scan, self._move(scan, run, RunStatus.FAILED, failed))
        container = (
            ContainerAssignment(name=f"{CONTAINER_NAME_PREFIX}{run.id}", image_ref=image_ref)
            if image_ref is not None
            else None
        )
        self._progress.move(scan, run, RunStatus.RUNNING, container=container)
        if container is not None:
            self._records.allot(run.id, requests)
        progress = Progress(run_status=RunStatus.RUNNING, scan_status=self._progress.settle(scan))
        launch = self._launch(
            scan, progress, secret, _egress(scan, grant, secret, requests), seconds=seconds
        )
        return self._engine_inputs(scan, run, launch)

    def _engine_inputs(self, scan: LockedScan, run: RunState, launch: Launch) -> Launch:
        """preflight 要送的請求；zap 的 api profile 要交給工具的規格（§16.5、§18.6）。"""
        if run.engine is Engine.PREFLIGHT:
            preflight = self._records.preflight(scan.auth_profile_id, scan.auth_profile_version)
            return replace(launch, preflight=preflight)
        if run.engine is Engine.ZAP and scan.api_spec_id is not None:
            return replace(launch, spec=self._records.spec_inputs(scan.id, scan.api_spec_id))
        return launch

    @staticmethod
    def _launch(
        scan: LockedScan,
        progress: Progress,
        secret: StoredSecret | None = None,
        egress: EgressScope | None = None,
        *,
        seconds: int | None = None,
    ) -> Launch:
        return Launch(
            progress=progress,
            max_duration_seconds=scan.max_duration_seconds if seconds is None else seconds,
            secret=secret,
            egress=egress,
            scan_profile=scan.scan_profile,
        )

    def advance(
        self, lease: Lease, to: RunStatus, *, error_code: RunErrorCode | None = None
    ) -> Progress:
        """持有 lease 的 run 依轉換表轉換；collected 與終止時清除 lease。

        不能轉到 running：只有 prepare 重新判斷 gate 之後才能開始執行，誤用 advance 也不會
        跳過檢查（fail closed；審查發現）。
        """
        if to is RunStatus.RUNNING:
            raise ValueError("run 只能由 prepare 開始執行（先重新判斷 gate）")
        scan, run = self._fenced(lease)
        return self._move(scan, run, to, error_code)

    def reconcile_expired(self, engines: Collection[Engine]) -> int:
        """in-process 的 fake runner 用：runner 階段與解析中的對帳（下面兩個的合併）。"""
        return self._reconcile(engines, or_(_parsing(), _without_live_container()))

    def reconcile_expired_runner(self, engines: Collection[Engine]) -> int:
        """lease 過期、沒有容器或容器已確認刪除的 runner 階段 → interrupted（LEASE_EXPIRED）。

        不必呼叫 Docker：沒有流量（in-process 的 fake、preparing 時中斷），或容器已確認不存在。
        容器還沒確認刪除的 run，lease 過期不代表容器已經停止（ARCHITECTURE.md §9），由 runner 的
        容器對帳處理（docs/DECISIONS.md §17.2）。
        """
        runner_stage = ScannerRunModel.status.in_(_values(RUNNER_STAGE_RUN_STATUSES))
        return self._reconcile(engines, and_(runner_stage, _without_live_container()))

    def reconcile_expired_parsing(self, engines: Collection[Engine]) -> int:
        """worker 用：lease 過期的 normalizing 退回 collected，嘗試太多次就 failed（§17.6）。"""
        return self._reconcile(engines, _parsing())

    def pending_containers(self, limit: int) -> tuple[PendingContainer, ...]:
        return self._containers.pending(limit)

    def settle_container(self, run_id: UUID) -> bool:
        return self._containers.settle(run_id)

    def unsettled_runs(self, run_ids: Collection[UUID]) -> frozenset[UUID]:
        return self._containers.unsettled(run_ids)

    def _reconcile(self, engines: Collection[Engine], stage: ColumnElement[bool]) -> int:
        expired = (
            ScannerRunModel.lease_owner.is_not(None),
            ScannerRunModel.lease_expires_at <= func.clock_timestamp(),
            stage,
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
                self._retry_parsing(scan, run)
            else:
                self._move(scan, run, RunStatus.INTERRUPTED, RunErrorCode.LEASE_EXPIRED)
            reconciled += 1
        return reconciled

    def _retry_parsing(self, scan: LockedScan, run: RunState) -> None:
        """解析不送流量，可以對不可變的 artifact 重試；但最多 MAX_PARSE_ATTEMPTS 次（§17.6）。"""
        if self._records.parse_attempts(run.id, scan.id) >= MAX_PARSE_ATTEMPTS:
            self._move(scan, run, RunStatus.FAILED, RunErrorCode.PARSE_ATTEMPTS_EXHAUSTED)
        else:
            self._move(scan, run, RunStatus.COLLECTED)

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
        run = self._progress.run(lease.run_id, conditions=tuple(holds(lease)))
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

    def _binding(
        self, scan: LockedScan, *, read_secret: bool
    ) -> tuple[RunErrorCode | None, StoredSecret | None]:
        """綁定的 profile 版本被取代、密文已清除：不改用新版本，直接失敗（§12.3）。

        兩種都以 FOR SHARE 鎖住版本列；read_secret 時一併讀出密文（容器版的 runner 要注入）。
        """
        if scan.auth_profile_id is None or scan.auth_profile_version is None:
            return None, None
        profile_id, version = scan.auth_profile_id, scan.auth_profile_version
        if read_secret:
            secret = self._profiles.sealed_secret(profile_id, version=version)
            if secret is None:
                return RunErrorCode.AUTH_PROFILE_SUPERSEDED, None
            return None, secret
        if self._profiles.version_has_secret(profile_id, version=version):
            return None, None
        return RunErrorCode.AUTH_PROFILE_SUPERSEDED, None


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
            return self._operations(session).heartbeat(lease, clock=self._clock)

    def record_plan(
        self,
        lease: Lease,
        *,
        plan_hash: str,
        profile_definition_sha256: str | None,
        guard_policy_version: GuardPolicyVersion,
    ) -> None:
        with self._sessions.begin() as session:
            RunRecords(session).record_plan(
                lease,
                plan_hash=plan_hash,
                profile_definition_sha256=profile_definition_sha256,
                guard_policy_version=guard_policy_version,
            )

    def record_usage(
        self, lease: Lease, usage: RunUsage, *, container_removed: bool = False
    ) -> None:
        with self._sessions.begin() as session:
            RunRecords(session).record_usage(lease, usage, container_removed=container_removed)

    def record_preflight(self, lease: Lease, result: PreflightResult) -> None:
        with self._sessions.begin() as session:
            RunRecords(session).record_preflight(lease, result)

    def coverage_inputs(self, lease: Lease) -> CoverageInputs:
        with self._sessions.begin() as session:
            return RunRecords(session).coverage_inputs(lease)

    def record_coverage(self, lease: Lease, observed: Mapping[int, bool]) -> None:
        with self._sessions.begin() as session:
            RunRecords(session).record_coverage(lease, observed)

    def bound_preflight(self, lease: Lease) -> Preflight | None:
        with self._sessions.begin() as session:
            return RunRecords(session).bound_preflight(lease)

    def result_context(self, lease: Lease) -> ResultContext:
        with self._sessions.begin() as session:
            return RunRecords(session).result_context(lease)

    def record_results(
        self,
        lease: Lease,
        parsed: ParsedRun,
        artifacts: Sequence[ArtifactRecord],
        *,
        exit_code: int | None,
        report_path: str | None = None,
    ) -> None:
        with self._sessions.begin() as session:
            RunRecords(session).record_results(
                lease, parsed, artifacts, exit_code=exit_code, report_path=report_path
            )

    def prepare(self, lease: Lease) -> Progress:
        with self._sessions.begin() as session:
            return self._operations(session).prepare(lease, clock=self._clock)

    def prepare_launch(self, lease: Lease, *, image_ref: str) -> Launch:
        with self._sessions.begin() as session:
            return self._operations(session).prepare_launch(
                lease, clock=self._clock, image_ref=image_ref
            )

    def advance(
        self, lease: Lease, to: RunStatus, *, error_code: RunErrorCode | None = None
    ) -> Progress:
        with self._sessions.begin() as session:
            return self._operations(session).advance(lease, to, error_code=error_code)

    def reconcile_expired(self, engines: Collection[Engine]) -> int:
        with self._sessions.begin() as session:
            return self._operations(session).reconcile_expired(engines)

    def reconcile_expired_runner(self, engines: Collection[Engine]) -> int:
        with self._sessions.begin() as session:
            return self._operations(session).reconcile_expired_runner(engines)

    def reconcile_expired_parsing(self, engines: Collection[Engine]) -> int:
        with self._sessions.begin() as session:
            return self._operations(session).reconcile_expired_parsing(engines)

    def pending_containers(self, limit: int) -> tuple[PendingContainer, ...]:
        with self._sessions.begin() as session:
            return self._operations(session).pending_containers(limit)

    def settle_container(self, run_id: UUID) -> bool:
        with self._sessions.begin() as session:
            return self._operations(session).settle_container(run_id)

    def unsettled_runs(self, run_ids: Collection[UUID]) -> frozenset[UUID]:
        with self._sessions.begin() as session:
            return self._operations(session).unsettled_runs(run_ids)

    def _operations(self, session: Session) -> QueueOperations:
        return QueueOperations(session, lab=self._lab)


def _egress(
    scan: LockedScan, grant: ScopeGrant, secret: StoredSecret | None, requests: int
) -> EgressScope:
    return EgressScope(
        origin=scan.target_origin,
        scope=grant.scope,
        valid_until=grant.window.valid_until,
        budget=RunBudget(
            requests_per_second=scan.requests_per_second, burst=1, max_requests=requests
        ),
        auth_header=secret.credential.wire_header.lower() if secret is not None else None,
    )


def _parsing() -> ColumnElement[bool]:
    return ScannerRunModel.status == RunStatus.NORMALIZING.value


def _without_live_container() -> ColumnElement[bool]:
    """沒有容器（in-process 的 fake、還沒開始），或容器已確認不存在（§17.2）。"""
    return or_(
        ScannerRunModel.container_name.is_(None),
        ScannerRunModel.container_removed_at.is_not(None),
    )


def _join_runs() -> Select[UUID, UUID]:
    return select(ScanModel.id.label("scan_id"), ScannerRunModel.id.label("run_id")).join(
        ScannerRunModel, ScannerRunModel.scan_id == ScanModel.id
    )


def _claimable(
    waiting: RunStatus, engines: Collection[Engine], run_id: UUID | None
) -> list[ColumnElement[bool]]:
    """可以認領的 run：狀態、引擎、scan 還沒終止；runner 認領時 scan 也沒有被要求取消、
    前面的 run 都不再送出流量。

    已終止的 scan 不會有等待中的 run（trigger 只允許在建立 scan 時新增 run）；萬一有，也不能
    認領：之後的 settle 會被 scans_guard 擋下，FIFO 每次又選到同一個 run，卡住佇列（審查發現）。
    """
    conditions: list[ColumnElement[bool]] = [
        ScannerRunModel.status == waiting.value,
        ScannerRunModel.engine.in_(_values(engines)),
    ]
    if run_id is not None:
        conditions.append(ScannerRunModel.id == run_id)
    stopped = aliased(ScanModel)
    reasons: list[ColumnElement[bool]] = [stopped.status.in_(_values(TERMINAL_SCAN_STATUSES))]
    if waiting is RunStatus.QUEUED:
        earlier = aliased(ScannerRunModel)
        conditions.append(
            ~exists().where(
                earlier.scan_id == ScannerRunModel.scan_id,
                earlier.sequence < ScannerRunModel.sequence,
                earlier.status.not_in(_values(TRAFFIC_STOPPED_RUN_STATUSES)),
            )
        )
        reasons.append(stopped.cancel_requested_at.is_not(None))
    conditions.append(~exists().where(stopped.id == ScannerRunModel.scan_id, or_(*reasons)))
    return conditions


def _values(
    items: Collection[Engine] | Collection[RunStatus] | Collection[ScanStatus],
) -> list[str]:
    return sorted(item.value for item in items)
