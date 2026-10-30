"""runner 迴圈的對帳（docs/DECISIONS.md §17.2、§17.4）。

- 啟動時先對帳、再依證據清理，之後才認領；之後每 10 秒對帳一次（在認領之前）。
- 啟動時不再刪除全部的 policy 與 secret：使用中的 run 留下的保留。
- Docker 中斷時迴圈不停、記錄不洗版。
每個測試用自己的資料庫（queue_database）。
"""

import logging
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.runner.loop import RECONCILE_EVERY_SECONDS, RunnerLoop
from secscan.runner.reconciler import ContainerReconciler
from secscan.runner.service import ContainerRunner
from secscan.runner.workspace import Workspace
from secscan.scanners.domain.fake import FakeScript
from secscan.scanners.domain.instances import InstanceRole
from secscan.scanners.service import Fleet
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunStatus
from secscan.scans.domain.model import Lease
from secscan.scans.queue import ScanQueue
from tests.guard_support import ENDPOINT, GuardDouble
from tests.integration.api_support import LAB, Seeder, World
from tests.runner_fakes import FakeClock, FakeContainerRuntime
from tests.runner_spies import POLICY, abandon
from tests.secret_support import shared_cipher

pytestmark = pytest.mark.integration

FAKE = frozenset({ScanEngine.FAKE})


class CountingReconciler(ContainerReconciler):
    def __init__(self, *args: object, clock: FakeClock, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.clock = clock
        self.rounds: list[float] = []

    def reconcile(self) -> int:
        self.rounds.append(self.clock.now)
        return super().reconcile()


@pytest.fixture
def queue(queue_engine: Engine) -> ScanQueue:
    return ScanQueue(
        sessionmaker(queue_engine, expire_on_commit=False),
        lab=LAB,
        clock=lambda: datetime.now(UTC),
    )


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def runtime(clock: FakeClock) -> FakeContainerRuntime:
    return FakeContainerRuntime(clock=clock)


@pytest.fixture
def workspace(tmp_path: Path) -> Workspace:
    (tmp_path / "runs").mkdir()
    (tmp_path / "secrets").mkdir()
    return Workspace(tmp_path / "runs", tmp_path / "secrets")


@pytest.fixture
def guard(tmp_path: Path) -> GuardDouble:
    return GuardDouble.create(tmp_path)


@pytest.fixture
def reconciler(
    queue: ScanQueue,
    runtime: FakeContainerRuntime,
    workspace: Workspace,
    guard: GuardDouble,
    clock: FakeClock,
) -> CountingReconciler:
    return CountingReconciler(queue, runtime, workspace, guard.channel(), clock=clock)


@pytest.fixture
def loop(
    queue: ScanQueue,
    queue_engine: Engine,
    runtime: FakeContainerRuntime,
    workspace: Workspace,
    guard: GuardDouble,
    clock: FakeClock,
    reconciler: CountingReconciler,
) -> RunnerLoop:
    channel = guard.channel()
    loop = RunnerLoop(
        Fleet(
            sessionmaker(queue_engine, expire_on_commit=False),
            owner="runner:loop",
            role=InstanceRole.RUNNER,
            software_version="0.1.0",
        ),
        runtime=runtime,
        workspace=workspace,
        guard=channel,
        reconciler=reconciler,
        policy=POLICY,
        stop_requested=lambda: clock.now >= 25,
        sleep=clock.sleep,
        monotonic=clock.monotonic,
        poll_seconds=2,
    )
    loop.attach(
        ContainerRunner(
            queue,
            runtime,
            workspace,
            owner="runner:loop",
            policy=POLICY,
            script=FakeScript(hold_seconds=1),
            cipher=shared_cipher(),
            guard=channel,
            endpoint=ENDPOINT,
            on_heartbeat=loop.beat,
            sleep=clock.sleep,
            monotonic=clock.monotonic,
        )
    )
    return loop


def _orphan(
    queue: ScanQueue,
    runtime: FakeContainerRuntime,
    workspace: Workspace,
    guard: GuardDouble,
    seed: Seeder,
    world: World,
    *,
    expire: bool = True,
) -> Lease:
    seed.scan(world.operator_a, seed.scannable(world))
    lease = queue.claim("runner:previous", FAKE)
    assert lease is not None
    abandon(queue, runtime, workspace, guard.channel(), lease)
    if expire:
        seed.execute(
            "UPDATE scanner_runs SET lease_expires_at = now() - interval '1 second' WHERE id = :id",
            id=lease.run_id,
        )
    return lease


def _status(seed: Seeder, run_id: UUID) -> str:
    [row] = seed.query("SELECT status FROM scanner_runs WHERE id = :id", id=run_id)
    status: str = row.status
    return status


def test_the_loop_settles_orphans_before_it_claims(
    loop: RunnerLoop,
    queue: ScanQueue,
    runtime: FakeContainerRuntime,
    workspace: Workspace,
    guard: GuardDouble,
    queue_seed: Seeder,
    world: World,
) -> None:
    orphan = _orphan(queue, runtime, workspace, guard, queue_seed, world)
    queue_seed.scan(world.operator_a, queue_seed.scannable(world))

    [report] = loop.run(once=True)

    assert _status(queue_seed, orphan.run_id) == "interrupted"
    assert report.run_status is RunStatus.COLLECTED
    assert runtime.removed[0] == f"secscan-run-{orphan.run_id}"
    assert [spec.name for spec in runtime.created][-1] == f"secscan-run-{report.run_id}"


def test_the_loop_reconciles_every_ten_seconds(
    loop: RunnerLoop, reconciler: CountingReconciler
) -> None:
    assert RECONCILE_EVERY_SECONDS == 10

    loop.run()

    assert reconciler.rounds == [0, 10, 20]


def test_startup_keeps_what_runs_in_use_left(
    loop: RunnerLoop,
    queue: ScanQueue,
    runtime: FakeContainerRuntime,
    workspace: Workspace,
    guard: GuardDouble,
    queue_seed: Seeder,
    world: World,
    tmp_path: Path,
) -> None:
    """另一個 runner 正在執行的 run（lease 有效）：不刪它的 policy、secret 與容器（§17.4）。

    DB 沒有的 run 留下的照常清掉（舊的做法在有其他 runner 存活時整個跳過）。
    """
    alive = _orphan(queue, runtime, workspace, guard, queue_seed, world, expire=False)
    leftover = uuid4()
    (guard.policies / f"{leftover}.json").write_bytes(b"{}")
    (tmp_path / "secrets" / str(leftover)).mkdir()

    loop.run(once=True)

    assert guard.policy_files() == [f"{alive.run_id}.json"]
    assert workspace.secret_runs() == {alive.run_id}
    assert f"secscan-run-{alive.run_id}" in runtime.containers


def test_a_docker_outage_does_not_stop_the_loop_or_flood_the_log(
    loop: RunnerLoop,
    reconciler: CountingReconciler,
    queue: ScanQueue,
    runtime: FakeContainerRuntime,
    workspace: Workspace,
    guard: GuardDouble,
    queue_seed: Seeder,
    world: World,
    caplog: pytest.LogCaptureFixture,
) -> None:
    orphan = _orphan(queue, runtime, workspace, guard, queue_seed, world)
    runtime.failing.add("state")

    with caplog.at_level(logging.WARNING, logger="secscan.runner.reconciler"):
        loop.run()

    assert reconciler.rounds == [0, 10, 20]
    assert _status(queue_seed, orphan.run_id) == "running"
    outage = [record for record in caplog.records if "Docker 不可用" in record.message]
    assert len(outage) == 1
