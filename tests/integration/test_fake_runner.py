"""FakeRunner（docs/DECISIONS.md §13.7）：跑完、失敗、被取消、lease 失效與對帳。

fake 不連任何位址；sleep 與時間可以注入：測試在「停留」期間取消 scan 或讓 lease 過期，不必真的等待。
每個測試用自己的資料庫（queue_database），runner 只會認領這個測試的 run。
"""

from collections.abc import Callable, Collection
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from secscan.grants.service import ScopeGrantService
from secscan.runner.fake import FakeOutcome, FakeRunner, FakeScript, RunReport
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.catalog import ScanProfile, plan_runs
from secscan.scans.domain.lifecycle import RunStatus, ScanStatus
from secscan.scans.domain.model import Lease, NewScan, Scan
from secscan.scans.queue import LeaseLostError, ScanQueue
from secscan.scans.repository import ScanRepository
from secscan.scans.service import ScanService
from tests.integration.api_support import LAB, Scannable, Seeder, World

pytestmark = pytest.mark.integration

R = RunStatus
S = ScanStatus


@dataclass
class FakeClock:
    """注入 runner 的時間：sleep 只把時間往前推，並在指定的時刻執行測試的動作。"""

    now: float = 0.0
    sleeps: list[float] = field(default_factory=list)
    on_sleep: Callable[[int], None] | None = None

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds
        if self.on_sleep is not None:
            self.on_sleep(len(self.sleeps))


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


@pytest.fixture
def scannable(queue_seed: Seeder, world: World) -> Scannable:
    return queue_seed.scannable(world)


def _runner(
    engine: Engine,
    script: FakeScript | None = None,
    clock: FakeClock | None = None,
) -> FakeRunner:
    timer = clock if clock is not None else FakeClock()
    queue = ScanQueue(
        sessionmaker(engine, expire_on_commit=False), lab=LAB, clock=lambda: datetime.now(UTC)
    )
    return FakeRunner(
        queue,
        owner=f"fake-runner-test-{uuid4().hex[:8]}",
        script=script if script is not None else FakeScript(),
        sleep=timer.sleep,
        monotonic=timer.monotonic,
    )


def _get(engine: Engine, world: World, scan_id: UUID) -> Scan:
    with Session(engine, expire_on_commit=False) as session, session.begin():
        return ScanService(session, lab=LAB).get(world.operator_a.principal, scan_id)


def _cancel(engine: Engine, world: World, scan_id: UUID) -> Scan:
    with Session(engine, expire_on_commit=False) as session, session.begin():
        return ScanService(session, lab=LAB).cancel(
            world.operator_a.principal, scan_id, request_id=None
        )


def _events(seed: Seeder, scan_id: UUID) -> list[tuple[str, object]]:
    rows = seed.query(
        "SELECT event_type, payload FROM scan_events WHERE scan_id = :id ORDER BY sequence",
        id=scan_id,
    )
    return [(row.event_type, row.payload.get("status")) for row in rows]


def _report(scan: Scan, run_status: RunStatus, scan_status: ScanStatus) -> RunReport:
    return RunReport(
        run_id=scan.runs[0].id, scan_id=scan.id, run_status=run_status, scan_status=scan_status
    )


def test_a_succeeding_script_completes_the_scan(
    queue_engine: Engine, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    scan = queue_seed.scan(world.operator_a, scannable)

    report = _runner(queue_engine).run_once()

    assert report == _report(scan, R.SUCCEEDED, S.COMPLETED)
    done = _get(queue_engine, world, scan.id)
    assert (done.status, done.fixture, done.results_complete) == (S.COMPLETED, True, True)
    assert _events(queue_seed, scan.id) == [
        ("scan.created", "queued"),
        ("run.status", "preparing"),
        ("scan.status", "preparing"),
        ("run.status", "running"),
        ("scan.status", "running"),
        ("run.status", "collecting"),
        ("scan.status", "collecting"),
        ("run.status", "collected"),
        ("run.status", "normalizing"),
        ("scan.status", "normalizing"),
        ("run.status", "succeeded"),
        ("scan.status", "completed"),
    ]
    # 結束之後 target 不再忙碌。
    assert queue_seed.scan(world.operator_a, scannable).status is S.QUEUED


def test_a_failing_script_fails_the_run(
    queue_engine: Engine, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    scan = queue_seed.scan(world.operator_a, scannable)

    report = _runner(queue_engine, FakeScript(outcome=FakeOutcome.FAIL)).run_once()

    assert report == _report(scan, R.FAILED, S.FAILED)
    [row] = queue_seed.query("SELECT error_code FROM scanner_runs WHERE scan_id = :id", id=scan.id)
    assert row.error_code == "ENGINE_FAILED"


def test_a_revoked_grant_fails_before_any_traffic(
    queue_engine: Engine, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    scan = queue_seed.scan(world.operator_a, scannable)
    with Session(queue_engine, expire_on_commit=False) as session, session.begin():
        ScopeGrantService(session, lab=LAB).revoke(
            world.admin.principal,
            scannable.grant.id,
            reason="停止",
            now=datetime.now(UTC),
            request_id=None,
        )

    assert _runner(queue_engine).run_once() == _report(scan, R.FAILED, S.FAILED)
    [row] = queue_seed.query("SELECT error_code FROM scanner_runs WHERE scan_id = :id", id=scan.id)
    assert row.error_code == "SCOPE_REVOKED"


def test_holding_sends_a_heartbeat_at_least_every_five_seconds(
    queue_engine: Engine, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    scan = queue_seed.scan(world.operator_a, scannable)
    clock = FakeClock()
    expiries: list[datetime] = []

    def record_lease(_: int) -> None:
        [row] = queue_seed.query(
            "SELECT lease_expires_at FROM scanner_runs WHERE scan_id = :id", id=scan.id
        )
        expiries.append(row.lease_expires_at)

    clock.on_sleep = record_lease
    report = _runner(queue_engine, FakeScript(hold_seconds=12), clock).run_once()

    assert report == _report(scan, R.SUCCEEDED, S.COMPLETED)
    assert clock.sleeps == [5, 5, 2]
    # 每次醒來時讀到的是上一次心跳延長的 lease：一次比一次晚。
    assert expiries == sorted(expiries)
    assert len(set(expiries)) == len(expiries)


def test_a_cancel_while_running_is_confirmed_by_the_runner(
    queue_engine: Engine, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    scan = queue_seed.scan(world.operator_a, scannable)
    clock = FakeClock()
    seen: list[ScanStatus] = []
    clock.on_sleep = lambda _: seen.append(_cancel(queue_engine, world, scan.id).status)

    report = _runner(queue_engine, FakeScript(hold_seconds=30), clock).run_once()

    # 取消的當下 runner 還在執行：scan 是 cancelling；runner 看到之後才是 cancelled。
    assert seen[0] is S.CANCELLING
    assert report == _report(scan, R.CANCELLED, S.CANCELLED)
    assert clock.sleeps == [5]
    assert _events(queue_seed, scan.id)[-5:] == [
        ("scan.cancel_requested", None),
        ("scan.status", "cancelling"),
        ("run.status", "cancelling"),
        ("run.status", "cancelled"),
        ("scan.status", "cancelled"),
    ]


def test_a_cancelled_queued_scan_is_never_run(
    queue_engine: Engine, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    scan = queue_seed.scan(world.operator_a, scannable)
    assert _cancel(queue_engine, world, scan.id).status is S.CANCELLED

    assert _runner(queue_engine).run_once() is None


def test_a_lost_lease_stops_the_runner_and_is_reconciled_later(
    queue_engine: Engine, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    """runner 停太久（例如被暫停）：lease 失效就停止，不再改變 run；之後由對帳標成 interrupted。"""
    scan = queue_seed.scan(world.operator_a, scannable)
    clock = FakeClock()

    def expire(_: int) -> None:
        queue_seed.execute(
            "UPDATE scanner_runs SET lease_expires_at = now() - interval '1 second' "
            "WHERE scan_id = :id",
            id=scan.id,
        )

    clock.on_sleep = expire

    with pytest.raises(LeaseLostError):
        _runner(queue_engine, FakeScript(hold_seconds=30), clock).run_once()
    assert _get(queue_engine, world, scan.id).status is S.RUNNING

    assert _runner(queue_engine).reconcile() == 1
    interrupted = _get(queue_engine, world, scan.id)
    assert interrupted.status is S.INTERRUPTED
    assert interrupted.runs[0].error_code is not None


def test_the_runner_only_claims_fake_runs(
    queue_engine: Engine, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    with Session(queue_engine, expire_on_commit=False) as session, session.begin():
        ScanRepository(session).create(
            NewScan(
                project_id=world.project_a.id,
                target_id=scannable.target.id,
                target_origin=scannable.target.origin,
                scope_grant_id=scannable.grant.id,
                api_spec_id=scannable.spec.id,
                auth=None,
                profile=ScanProfile.API_ACTIVE_LAB,
                budget=scannable.grant.budget,
                runs=plan_runs((ScanEngine.ZAP,), available=frozenset(ScanEngine)),
                operations=(),
                idempotency_key=uuid4().hex,
                request_sha256=bytes(32),
                created_by_key_id=world.operator_a.principal.key_id,
            )
        )

    assert _runner(queue_engine).run_once() is None


def test_drain_runs_every_queued_fake_run_or_stops_at_the_limit(
    queue_engine: Engine, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    first = queue_seed.scan(world.operator_a, scannable)
    second = queue_seed.scan(world.operator_a, queue_seed.scannable(world))
    third = queue_seed.scan(world.operator_a, queue_seed.scannable(world))
    seen: list[RunReport] = []

    assert _runner(queue_engine).drain(limit=1, on_report=seen.append) == [
        _report(first, R.SUCCEEDED, S.COMPLETED)
    ]
    assert seen == [_report(first, R.SUCCEEDED, S.COMPLETED)]
    assert [report.scan_id for report in _runner(queue_engine).drain()] == [second.id, third.id]
    assert _runner(queue_engine).drain() == []


def test_drain_first_finishes_runs_left_collected(
    queue_engine: Engine, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    """解析中被中斷、對帳退回 collected 的 run：下一次執行先把它解析完。"""
    scan = queue_seed.scan(world.operator_a, scannable)
    queue = ScanQueue(
        sessionmaker(queue_engine, expire_on_commit=False), lab=LAB, clock=lambda: datetime.now(UTC)
    )
    lease = queue.claim("crashed-runner", frozenset({ScanEngine.FAKE}))
    assert lease is not None
    queue.prepare(lease)
    queue.advance(lease, R.COLLECTING)
    queue.advance(lease, R.COLLECTED)

    assert _runner(queue_engine).drain() == [_report(scan, R.SUCCEEDED, S.COMPLETED)]


class _CancelAfterClaim(ScanQueue):
    """在 runner 認領之後、prepare 之前，使用者取消了 scan。"""

    def __init__(self, engine: Engine, world: World) -> None:
        super().__init__(
            sessionmaker(engine, expire_on_commit=False), lab=LAB, clock=lambda: datetime.now(UTC)
        )
        self._engine = engine
        self._world = world

    def claim(self, owner: str, engines: Collection[ScanEngine]) -> Lease | None:
        lease = super().claim(owner, engines)
        if lease is not None:
            assert _cancel(self._engine, self._world, lease.scan_id).status is S.CANCELLING
        return lease


class _OtherWorkerParses(ScanQueue):
    """收集之後，另一個 worker 先認領了這個 collected 的 run。"""

    def claim_collected(
        self, owner: str, engines: Collection[ScanEngine], *, run_id: UUID | None = None
    ) -> Lease | None:
        if run_id is not None:
            return None
        return super().claim_collected(owner, engines, run_id=run_id)


def test_a_cancel_between_claim_and_prepare_is_confirmed_at_prepare(
    queue_engine: Engine, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    scan = queue_seed.scan(world.operator_a, scannable)
    runner = FakeRunner(_CancelAfterClaim(queue_engine, world), owner="runner", script=FakeScript())

    assert runner.run_once() == _report(scan, R.CANCELLED, S.CANCELLED)


def test_a_run_parsed_by_another_worker_is_reported_as_collected(
    queue_engine: Engine, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    scan = queue_seed.scan(world.operator_a, scannable)
    queue = _OtherWorkerParses(
        sessionmaker(queue_engine, expire_on_commit=False), lab=LAB, clock=lambda: datetime.now(UTC)
    )

    assert FakeRunner(queue, owner="runner", script=FakeScript()).run_once() == _report(
        scan, R.COLLECTED, S.COLLECTING
    )
