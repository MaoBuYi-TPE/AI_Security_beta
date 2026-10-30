"""runner 與 worker 的常駐迴圈（docs/DECISIONS.md §14.6、§14.7）。

- 啟動時對帳與清理（test_runner_loop_reconcile.py）、刪掉過期的心跳列、probe；每圈寫心跳，probe
  每 60 秒重做一次。
- probe 不通過就不認領；lease 失效或 Docker 中途不可用時記下，繼續處理下一個。
每個測試用自己的資料庫（queue_database）。
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.runner.domain.policy import ContainerPolicy
from secscan.runner.loop import RunnerLoop
from secscan.runner.reconciler import ContainerReconciler
from secscan.runner.service import ContainerRunner
from secscan.runner.workspace import Workspace
from secscan.scanners.domain.fake import FAKE_IMAGE, FakeScript
from secscan.scanners.domain.instances import InstanceRole
from secscan.scanners.service import Fleet
from secscan.scans.domain.lifecycle import RunStatus
from secscan.scans.queue import ScanQueue
from secscan.worker.loop import WorkerLoop
from secscan.worker.service import Worker
from tests.guard_support import ENDPOINT, GuardDouble
from tests.integration.api_support import LAB, Scannable, Seeder, World
from tests.runner_fakes import FakeClock, FakeContainerRuntime
from tests.secret_support import shared_cipher

pytestmark = pytest.mark.integration

POLICY = ContainerPolicy(
    scan_network="secscan_scan_net",
    runs_volume="secscan_runs",
    secrets_volume="secscan_run_secrets",
)


def _now() -> datetime:
    return datetime.now(UTC)


@pytest.fixture
def queue(queue_engine: Engine) -> ScanQueue:
    return ScanQueue(sessionmaker(queue_engine, expire_on_commit=False), lab=LAB, clock=_now)


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


@pytest.fixture
def scannable(queue_seed: Seeder, world: World) -> Scannable:
    return queue_seed.scannable(world)


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


def _fleet(engine: Engine, role: InstanceRole) -> Fleet:
    return Fleet(
        sessionmaker(engine, expire_on_commit=False),
        owner=f"{role.value}:loop",
        role=role,
        software_version="0.1.0",
    )


def _runner_loop(
    queue: ScanQueue,
    queue_engine: Engine,
    runtime: FakeContainerRuntime,
    workspace: Workspace,
    clock: FakeClock,
    *,
    guard: GuardDouble,
    stop_after: float = 1_000,
) -> RunnerLoop:
    def stop_requested() -> bool:
        return clock.now >= stop_after

    channel = guard.channel()
    loop = RunnerLoop(
        _fleet(queue_engine, InstanceRole.RUNNER),
        runtime=runtime,
        workspace=workspace,
        guard=channel,
        reconciler=ContainerReconciler(queue, runtime, workspace, channel),
        policy=POLICY,
        stop_requested=stop_requested,
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
            stop_requested=stop_requested,
            on_heartbeat=loop.beat,
            sleep=clock.sleep,
            monotonic=clock.monotonic,
        )
    )
    return loop


def _capabilities(seed: Seeder) -> dict[str, object]:
    [row] = seed.query("SELECT capabilities FROM runner_instances WHERE role = 'runner'")
    capabilities: dict[str, object] = row.capabilities
    return capabilities


def test_the_runner_loop_processes_queued_runs_until_stopped(
    queue: ScanQueue,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    runtime: FakeContainerRuntime,
    workspace: Workspace,
    clock: FakeClock,
    tmp_path: Path,
    guard: GuardDouble,
) -> None:
    # DB 沒有的 run 留下的 secret：啟動時依證據清掉（docs/DECISIONS.md §17.4）。
    (tmp_path / "secrets" / "00000000-0000-4000-8000-000000000002").mkdir()
    queue_seed.scan(world.operator_a, scannable)
    queue_seed.scan(world.operator_a, queue_seed.scannable(world))

    reports = _runner_loop(
        queue, queue_engine, runtime, workspace, clock, stop_after=30, guard=guard
    ).run()

    assert [report.run_status for report in reports] == [RunStatus.COLLECTED] * 2
    assert list((tmp_path / "secrets").iterdir()) == []
    # fake 與 preflight 用同一個 busybox 與環境（docs/DECISIONS.md §16.5）。
    assert _capabilities(queue_seed)["engines"] == {
        "fake": {"image": str(runtime.created[0].body["Image"]), "issue": None},
        "preflight": {"image": str(runtime.created[0].body["Image"]), "issue": None},
    }


def test_once_processes_at_most_one_run(
    queue: ScanQueue,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    runtime: FakeContainerRuntime,
    workspace: Workspace,
    clock: FakeClock,
    guard: GuardDouble,
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    queue_seed.scan(world.operator_a, queue_seed.scannable(world))
    loop = _runner_loop(queue, queue_engine, runtime, workspace, clock, guard=guard)

    assert len(loop.run(once=True)) == 1
    assert len(loop.run(once=True)) == 1
    assert loop.run(once=True) == []


def test_an_unready_environment_claims_nothing_and_probes_again(
    queue: ScanQueue,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    runtime: FakeContainerRuntime,
    workspace: Workspace,
    clock: FakeClock,
    guard: GuardDouble,
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    runtime.volumes.clear()
    clock.at(30, lambda: runtime.volumes.update({"secscan_runs", "secscan_run_secrets"}))

    reports = _runner_loop(
        queue, queue_engine, runtime, workspace, clock, stop_after=90, guard=guard
    ).run()

    # 第 60 秒重新 probe 之後才認領。
    assert len(reports) == 1
    assert runtime.created
    # fake 與 preflight 用同一個 busybox 與環境（docs/DECISIONS.md §16.5）。
    assert _capabilities(queue_seed)["engines"] == {
        "fake": {"image": str(runtime.created[0].body["Image"]), "issue": None},
        "preflight": {"image": str(runtime.created[0].body["Image"]), "issue": None},
    }


def test_a_lost_lease_or_docker_failure_does_not_stop_the_loop(
    queue: ScanQueue,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    runtime: FakeContainerRuntime,
    workspace: Workspace,
    clock: FakeClock,
    guard: GuardDouble,
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    runtime.failing.update({"state", "remove"})
    clock.at(5, runtime.failing.clear)

    loop = _runner_loop(queue, queue_engine, runtime, workspace, clock, stop_after=20, guard=guard)
    reports = loop.run()

    assert reports == []
    assert loop.failures == 1


def test_the_worker_loop_completes_collected_runs(
    queue: ScanQueue,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    runtime: FakeContainerRuntime,
    workspace: Workspace,
    clock: FakeClock,
    guard: GuardDouble,
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    _runner_loop(queue, queue_engine, runtime, workspace, clock, guard=guard).run(once=True)
    worker_clock = FakeClock()

    reports = WorkerLoop(
        Worker(queue, owner="worker:loop"),
        _fleet(queue_engine, InstanceRole.WORKER),
        stop_requested=lambda: worker_clock.now >= 10,
        sleep=worker_clock.sleep,
        poll_seconds=2,
    ).run()

    assert [report.run_status for report in reports] == [RunStatus.SUCCEEDED]
    [row] = queue_seed.query("SELECT role FROM runner_instances WHERE role = 'worker'")
    assert row.role == "worker"


def test_the_worker_loop_once(queue: ScanQueue, queue_engine: Engine) -> None:
    clock = FakeClock()
    loop = WorkerLoop(
        Worker(queue, owner="worker:loop"),
        _fleet(queue_engine, InstanceRole.WORKER),
        stop_requested=lambda: False,
        sleep=clock.sleep,
        poll_seconds=2,
    )

    assert loop.run(once=True) == []
    assert clock.now == 0


def test_a_loop_needs_a_runner(
    queue: ScanQueue,
    queue_engine: Engine,
    runtime: FakeContainerRuntime,
    workspace: Workspace,
    guard: GuardDouble,
) -> None:
    loop = RunnerLoop(
        _fleet(queue_engine, InstanceRole.RUNNER),
        runtime=runtime,
        workspace=workspace,
        guard=guard.channel(),
        reconciler=ContainerReconciler(queue, runtime, workspace, guard.channel()),
        policy=POLICY,
        stop_requested=lambda: False,
        poll_seconds=2,
    )

    with pytest.raises(RuntimeError, match="attach"):
        loop.run()


def test_reports_are_passed_on_and_a_lost_lease_is_counted(
    queue: ScanQueue,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    runtime: FakeContainerRuntime,
    workspace: Workspace,
    clock: FakeClock,
    guard: GuardDouble,
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    seen: list[RunStatus] = []
    loop = _runner_loop(queue, queue_engine, runtime, workspace, clock, guard=guard)

    loop.run(once=True, on_report=lambda report: seen.append(report.run_status))
    queue_seed.scan(world.operator_a, queue_seed.scannable(world))
    clock.at(
        clock.now + 0.5,
        lambda: queue_seed.execute(
            "UPDATE scanner_runs SET lease_expires_at = now() - interval '1 second' "
            "WHERE status = 'running'"
        ),
    )
    runtime_hold = loop.run(once=True)

    assert seen == [RunStatus.COLLECTED]
    assert runtime_hold == []
    assert loop.failures == 1


def test_an_unwritable_volume_claims_nothing(
    queue: ScanQueue,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    runtime: FakeContainerRuntime,
    workspace: Workspace,
    clock: FakeClock,
    tmp_path: Path,
    guard: GuardDouble,
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    (tmp_path / "runs").chmod(0o500)
    try:
        reports = _runner_loop(queue, queue_engine, runtime, workspace, clock, guard=guard).run(
            once=True
        )
    finally:
        (tmp_path / "runs").chmod(0o700)

    assert reports == []
    assert runtime.created == []
    # fake 與 preflight 用同一個 busybox 與環境（docs/DECISIONS.md §16.5）。
    assert _capabilities(queue_seed)["engines"] == {
        "fake": {"image": str(FAKE_IMAGE), "issue": "RUN_VOLUME_NOT_WRITABLE"},
        "preflight": {"image": str(FAKE_IMAGE), "issue": "RUN_VOLUME_NOT_WRITABLE"},
    }


# --- egress guard（docs/DECISIONS.md §15.7）------------------------------------------------


@pytest.mark.parametrize("change", ["stop", "vanish", "unwritable"])
def test_an_unavailable_guard_claims_nothing(
    queue: ScanQueue,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    runtime: FakeContainerRuntime,
    workspace: Workspace,
    clock: FakeClock,
    guard: GuardDouble,
    change: str,
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    if change == "stop":
        guard.stop()
    elif change == "vanish":
        guard.vanish()
    else:
        guard.policies.chmod(0o500)
    try:
        reports = _runner_loop(queue, queue_engine, runtime, workspace, clock, guard=guard).run(
            once=True
        )
    finally:
        guard.policies.chmod(0o700)

    assert reports == []
    assert runtime.created == []
    # fake 與 preflight 用同一個 busybox 與環境（docs/DECISIONS.md §16.5）。
    assert _capabilities(queue_seed)["engines"] == {
        "fake": {"image": str(FAKE_IMAGE), "issue": "GUARD_UNAVAILABLE"},
        "preflight": {"image": str(FAKE_IMAGE), "issue": "GUARD_UNAVAILABLE"},
    }


def test_the_guard_is_checked_every_round_not_only_at_the_probe(
    queue: ScanQueue,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    runtime: FakeContainerRuntime,
    workspace: Workspace,
    clock: FakeClock,
    guard: GuardDouble,
) -> None:
    """guard 停機後恢復：不必等 60 秒的 probe，下一輪就認領。"""
    queue_seed.scan(world.operator_a, scannable)
    guard.stop()
    clock.at(5, guard.healthy)

    reports = _runner_loop(
        queue, queue_engine, runtime, workspace, clock, stop_after=20, guard=guard
    ).run()

    assert [report.run_status for report in reports] == [RunStatus.COLLECTED]
    assert 5 <= clock.now < 60


def test_a_guard_that_stops_is_noticed_before_the_next_claim(
    queue: ScanQueue,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    runtime: FakeContainerRuntime,
    workspace: Workspace,
    clock: FakeClock,
    guard: GuardDouble,
) -> None:
    def enqueue() -> None:
        queue_seed.scan(world.operator_a, scannable)

    clock.at(3, guard.stop)
    clock.at(5, enqueue)

    reports = _runner_loop(
        queue, queue_engine, runtime, workspace, clock, stop_after=20, guard=guard
    ).run()

    assert reports == []
    assert runtime.created == []
    # fake 與 preflight 用同一個 busybox 與環境（docs/DECISIONS.md §16.5）。
    assert _capabilities(queue_seed)["engines"] == {
        "fake": {"image": str(FAKE_IMAGE), "issue": "GUARD_UNAVAILABLE"},
        "preflight": {"image": str(FAKE_IMAGE), "issue": "GUARD_UNAVAILABLE"},
    }
