"""runner 內的容器對帳（docs/DECISIONS.md §17.2、§17.4；DoD 1 至 3）。

runner 被 SIGKILL 時不會執行任何清理：測試直接造出它留下的狀態（DB 是 running、lease 過期、容器
還在執行、policy 是 active、secret 還在），再讓 reconciler 處理。一個 spy 把 policy 的寫入、容器的
操作與 DB 的結算記在同一個有序的 log：
- 先封鎖 guard，再刪除容器，確認刪除之後才結算、才刪 policy（DoD 3）。
- Docker 出錯時不結算、policy 保持 blocked；恢復之後才結算。
- lease 過期而容器可能還在執行時，另一個 runner 不會為同一個 scan 啟動任何容器（DoD 1）。
- 啟動時只清理已結算或 DB 沒有的 run 留下的 policy、secret 與容器。
每個測試用自己的資料庫（queue_database）。
"""

import logging
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine, Row

from secscan.guard.domain.policy import Policy, PolicyState
from secscan.runner.domain.admission import PROXY_FILE, ContainerSpec
from secscan.runner.domain.runtime import RuntimeUnavailableError
from secscan.runner.reconciler import ContainerReconciler
from secscan.runner.service import ContainerRunner
from secscan.runner.workspace import Workspace
from secscan.scanners.domain.fake import FakeScript
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunStatus
from secscan.scans.domain.model import Lease
from secscan.scans.queue import ScanQueue
from secscan.worker.service import Worker
from tests.guard_support import ENDPOINT, GuardDouble
from tests.integration.api_support import LAB, Seeder, World
from tests.runner_fakes import FakeClock, FakeContainer
from tests.runner_spies import (
    POLICY,
    SpyChannel,
    SpyRuntime,
    abandon,
    logged_queue,
    orphan_spec,
)
from tests.secret_support import shared_cipher

pytestmark = pytest.mark.integration

OWNER = "runner-reconciler-1"
FAKE = frozenset({ScanEngine.FAKE})
BOTH = frozenset({ScanEngine.FAKE, ScanEngine.PREFLIGHT})
R = RunStatus


@pytest.fixture
def log() -> list[str]:
    return []


@pytest.fixture
def queue(queue_engine: Engine, log: list[str]) -> ScanQueue:
    return logged_queue(queue_engine, log, lab=LAB)


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def runtime(clock: FakeClock, log: list[str]) -> SpyRuntime:
    runtime = SpyRuntime(clock=clock)
    runtime.log = log
    return runtime


@pytest.fixture
def workspace(tmp_path: Path) -> Workspace:
    (tmp_path / "runs").mkdir()
    (tmp_path / "secrets").mkdir()
    return Workspace(tmp_path / "runs", tmp_path / "secrets")


@pytest.fixture
def guard(tmp_path: Path) -> GuardDouble:
    return GuardDouble.create(tmp_path)


@pytest.fixture
def channel(guard: GuardDouble, log: list[str]) -> SpyChannel:
    return SpyChannel(guard, log)


@pytest.fixture
def reconciler(
    queue: ScanQueue, runtime: SpyRuntime, workspace: Workspace, channel: SpyChannel
) -> ContainerReconciler:
    return ContainerReconciler(queue, runtime, workspace, channel)


@pytest.fixture
def make_runner(
    queue: ScanQueue,
    runtime: SpyRuntime,
    workspace: Workspace,
    clock: FakeClock,
    channel: SpyChannel,
) -> Callable[..., ContainerRunner]:
    def factory(**overrides: Any) -> ContainerRunner:
        options: dict[str, Any] = {
            "owner": "runner-reconciler-2",
            "policy": POLICY,
            "script": FakeScript(hold_seconds=1),
            "cipher": shared_cipher(),
            "guard": channel,
            "endpoint": ENDPOINT,
            "sleep": clock.sleep,
            "monotonic": clock.monotonic,
        }
        options.update(overrides)
        return ContainerRunner(queue, runtime, workspace, **options)

    return factory


@pytest.fixture
def orphan(
    queue: ScanQueue,
    runtime: SpyRuntime,
    workspace: Workspace,
    channel: SpyChannel,
    queue_seed: Seeder,
    world: World,
    log: list[str],
) -> Callable[..., Lease]:
    """runner 被 SIGKILL 時留下的 run：容器執行中、policy 是 active、secret 還在。"""

    def make(*, engines: frozenset[ScanEngine] = FAKE, expire: bool = True, **scan: Any) -> Lease:
        if not scan.pop("existing", False):
            queue_seed.scan(world.operator_a, queue_seed.scannable(world), **scan)
        lease = queue.claim(OWNER, engines)
        assert lease is not None
        abandon(queue, runtime, workspace, channel, lease)
        if expire:
            _expire(queue_seed, lease.run_id)
        log.clear()
        return lease

    return make


def _expire(seed: Seeder, run_id: UUID) -> None:
    seed.execute(
        "UPDATE scanner_runs SET lease_expires_at = now() - interval '1 second' WHERE id = :id",
        id=run_id,
    )


def _run(seed: Seeder, run_id: UUID) -> Row[Any]:
    [row] = seed.query(
        "SELECT r.status, r.error_code, r.container_removed_at, r.requests_sent, "
        "s.status AS scan_status FROM scanner_runs r JOIN scans s ON s.id = r.scan_id "
        "WHERE r.id = :id",
        id=run_id,
    )
    return row


def _name(lease: Lease) -> str:
    return f"secscan-run-{lease.run_id}"


# --- 執行中的孤兒 ------------------------------------------------------------------------------


def test_an_orphan_is_blocked_then_removed_then_settled(
    orphan: Callable[..., Lease],
    reconciler: ContainerReconciler,
    runtime: SpyRuntime,
    guard: GuardDouble,
    log: list[str],
    queue_seed: Seeder,
    tmp_path: Path,
) -> None:
    lease = orphan()
    assert (policy := guard.policy(lease.run_id)) is not None
    assert policy.state is PolicyState.ACTIVE

    assert reconciler.reconcile() == 1

    assert log == ["policy:blocked", "remove", "run:settled", "policy:removed"]
    run = _run(queue_seed, lease.run_id)
    assert (run.status, run.error_code, run.scan_status) == (
        "interrupted",
        "LEASE_EXPIRED",
        "interrupted",
    )
    assert run.container_removed_at is not None
    assert run.requests_sent is None  # 用量不明
    assert runtime.containers == {}
    assert guard.policy_files() == []
    assert list((tmp_path / "secrets").iterdir()) == []
    assert reconciler.reconcile() == 0


def test_a_cancelling_run_whose_runner_is_lost_is_blocked_first(
    orphan: Callable[..., Lease],
    reconciler: ContainerReconciler,
    queue: ScanQueue,
    log: list[str],
    queue_seed: Seeder,
) -> None:
    lease = orphan(expire=False)
    queue_seed.execute(
        "UPDATE scans SET cancel_requested_at = now() WHERE id = :id", id=lease.scan_id
    )
    queue.advance(lease, R.CANCELLING)
    _expire(queue_seed, lease.run_id)
    log.clear()

    assert reconciler.reconcile() == 1

    assert log[:2] == ["policy:blocked", "remove"]
    run = _run(queue_seed, lease.run_id)
    assert (run.status, run.scan_status) == ("interrupted", "interrupted")


def test_a_live_lease_is_left_alone(
    orphan: Callable[..., Lease],
    reconciler: ContainerReconciler,
    runtime: SpyRuntime,
    guard: GuardDouble,
    log: list[str],
    queue_seed: Seeder,
) -> None:
    lease = orphan(expire=False)

    assert reconciler.reconcile() == 0

    assert log == []
    assert _name(lease) in runtime.containers
    policy = guard.policy(lease.run_id)
    assert policy is not None
    assert policy.state is PolicyState.ACTIVE
    assert _run(queue_seed, lease.run_id).status == "running"


def test_runs_without_a_container_are_settled_without_docker(
    reconciler: ContainerReconciler,
    queue: ScanQueue,
    log: list[str],
    queue_seed: Seeder,
    world: World,
) -> None:
    """preparing 時中斷：沒有容器、沒有流量，lease 過期就 interrupted（§17.2）。"""
    queue_seed.scan(world.operator_a, queue_seed.scannable(world))
    lease = queue.claim(OWNER, FAKE)
    assert lease is not None
    _expire(queue_seed, lease.run_id)

    assert reconciler.reconcile() == 1

    assert log == []
    assert _run(queue_seed, lease.run_id).error_code == "LEASE_EXPIRED"


def test_a_secret_that_cannot_be_removed_does_not_keep_the_container(
    orphan: Callable[..., Lease],
    reconciler: ContainerReconciler,
    runtime: SpyRuntime,
    queue_seed: Seeder,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    lease = orphan()
    (tmp_path / "secrets" / str(lease.run_id) / "stray").write_bytes(b"x")  # rmdir 會失敗

    with caplog.at_level(logging.ERROR, logger="secscan.runner.reconciler"):
        assert reconciler.reconcile() == 1

    assert runtime.containers == {}
    assert _run(queue_seed, lease.run_id).status == "interrupted"
    assert any("secret" in record.message for record in caplog.records)


# --- Docker 出錯 -------------------------------------------------------------------------------


def test_a_docker_outage_defers_settlement_and_keeps_the_policy_blocked(
    orphan: Callable[..., Lease],
    reconciler: ContainerReconciler,
    runtime: SpyRuntime,
    guard: GuardDouble,
    queue_seed: Seeder,
    caplog: pytest.LogCaptureFixture,
) -> None:
    lease = orphan()
    runtime.failing.update({"state", "version"})  # Docker 不可用：每個呼叫都失敗

    with caplog.at_level(logging.WARNING, logger="secscan.runner.reconciler"):
        assert reconciler.reconcile() == 0
        assert reconciler.reconcile() == 0

    assert _run(queue_seed, lease.run_id).status == "running"
    assert _name(lease) in runtime.containers
    policy = guard.policy(lease.run_id)
    assert policy is not None
    assert policy.state is PolicyState.BLOCKED
    assert len([record for record in caplog.records if "Docker" in record.message]) == 1

    runtime.failing.clear()
    assert reconciler.reconcile() == 1
    assert _run(queue_seed, lease.run_id).status == "interrupted"
    assert guard.policy_files() == []


def test_a_docker_outage_stops_the_round_after_the_first_container(
    orphan: Callable[..., Lease],
    reconciler: ContainerReconciler,
    runtime: SpyRuntime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Docker 不可用時不必逐一嘗試其他容器（每個都會失敗）：這一輪在第一個之後就停。"""
    first, second = orphan(), orphan()
    runtime.failing.update({"state", "version"})
    inspected: list[str] = []
    state = runtime.state

    def counted(name: str) -> object:
        inspected.append(name)
        return state(name)

    monkeypatch.setattr(runtime, "state", counted)

    assert reconciler.reconcile() == 0

    assert inspected == [_name(first)]
    assert _name(second) in runtime.containers


def test_a_conflict_defers_only_that_container(
    orphan: Callable[..., Lease],
    reconciler: ContainerReconciler,
    runtime: SpyRuntime,
    guard: GuardDouble,
    queue_seed: Seeder,
) -> None:
    first, second = orphan(), orphan()
    runtime.conflicting.add(_name(first))

    assert reconciler.reconcile() == 1

    assert _run(queue_seed, first.run_id).status == "running"
    assert _run(queue_seed, second.run_id).status == "interrupted"
    assert guard.policy_files() == [f"{first.run_id}.json"]


def test_one_broken_container_does_not_hold_up_the_others(
    orphan: Callable[..., Lease],
    reconciler: ContainerReconciler,
    runtime: SpyRuntime,
    guard: GuardDouble,
    queue_seed: Seeder,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Docker 本身可用、只有最舊的那個容器刪不掉：其他的照常結算，那個 run 只記一次 ERROR。"""
    first, second = orphan(), orphan()
    runtime.broken.add(_name(first))

    with caplog.at_level(logging.WARNING, logger="secscan.runner.reconciler"):
        assert reconciler.reconcile() == 1
        assert reconciler.reconcile() == 0

    assert _run(queue_seed, first.run_id).status == "running"
    assert _run(queue_seed, second.run_id).status == "interrupted"
    policy = guard.policy(first.run_id)
    assert policy is not None
    assert policy.state is PolicyState.BLOCKED
    about_first = [record for record in caplog.records if str(first.run_id) in record.message]
    assert [record.levelno for record in about_first] == [logging.ERROR]
    assert not any("Docker 不可用" in record.message for record in caplog.records)

    runtime.broken.clear()
    assert reconciler.reconcile() == 1
    assert _run(queue_seed, first.run_id).status == "interrupted"


def test_startup_cleans_the_others_when_one_container_is_broken(
    reconciler: ContainerReconciler,
    runtime: SpyRuntime,
    channel: SpyChannel,
    guard: GuardDouble,
    orphan: Callable[..., Lease],
) -> None:
    template = orphan(expire=False)
    first, second = sorted(
        (Lease(uuid4(), uuid4(), ScanEngine.FAKE, OWNER) for _ in range(2)),
        key=lambda lease: lease.run_id,
    )
    for unknown in (first, second):
        channel.write(guard_policy_for(guard, template.run_id, unknown.run_id))
        runtime.create(orphan_spec(unknown))
    runtime.broken.add(_name(first))

    assert reconciler.sweep_orphans() == 1

    assert guard.policy(second.run_id) is None
    policy = guard.policy(first.run_id)
    assert policy is not None
    assert policy.state is PolicyState.BLOCKED


def test_a_container_that_is_already_gone_is_settled(
    orphan: Callable[..., Lease],
    reconciler: ContainerReconciler,
    runtime: SpyRuntime,
    log: list[str],
    queue_seed: Seeder,
) -> None:
    lease = orphan()
    runtime.containers.pop(_name(lease))

    assert reconciler.reconcile() == 1

    assert log == ["policy:blocked", "run:settled", "policy:removed"]
    assert _run(queue_seed, lease.run_id).status == "interrupted"


def test_a_container_without_our_label_is_left_alone_but_the_run_is_settled(
    orphan: Callable[..., Lease],
    reconciler: ContainerReconciler,
    runtime: SpyRuntime,
    queue_seed: Seeder,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """名稱相同、label 不符：證明我們的容器不存在；不動別人的容器（§17.2）。"""
    lease = orphan()
    spec = runtime.containers[_name(lease)].spec
    foreign = ContainerSpec(name=spec.name, body={**spec.body, "Labels": {"app": "other"}})
    runtime.containers[spec.name] = FakeContainer(foreign, started_at=0.0)

    with caplog.at_level(logging.ERROR, logger="secscan.runner.reconciler"):
        assert reconciler.reconcile() == 1

    assert runtime.containers[spec.name].spec is foreign
    assert "remove" not in runtime.log
    assert any("label" in record.message for record in caplog.records)
    assert _run(queue_seed, lease.run_id).status == "interrupted"


# --- 已結束的 run 留下的容器 -------------------------------------------------------------------


def test_a_normal_run_records_the_removal_and_is_not_pending(
    make_runner: Callable[..., ContainerRunner],
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
) -> None:
    """runner 確認刪除容器時和用量一起記下：不會成為對帳的待處理（§17.2）。"""
    queue_seed.scan(world.operator_a, queue_seed.scannable(world))

    report = make_runner().run_once(FAKE)

    assert report is not None
    assert _run(queue_seed, report.run_id).container_removed_at is not None
    assert queue.pending_containers(limit=20) == ()


def test_a_container_left_by_a_finished_run_is_removed_without_changing_the_run(
    make_runner: Callable[..., ContainerRunner],
    reconciler: ContainerReconciler,
    queue: ScanQueue,
    runtime: SpyRuntime,
    queue_seed: Seeder,
    world: World,
) -> None:
    """容器已結束、刪不掉（EXITED）：run 照常 collected；之後由對帳刪除，worker 仍能解析。"""
    queue_seed.scan(world.operator_a, queue_seed.scannable(world))
    runtime.failing.add("remove")
    report = make_runner().run_once(FAKE)
    assert report is not None
    assert report.run_status is R.COLLECTED
    assert _run(queue_seed, report.run_id).container_removed_at is None
    runtime.failing.clear()

    assert reconciler.reconcile() == 1

    run = _run(queue_seed, report.run_id)
    assert (run.status, run.container_removed_at is not None) == ("collected", True)
    assert runtime.containers == {}
    [parsed] = Worker(queue, owner="worker-1").drain()
    assert parsed.run_status is R.SUCCEEDED


@pytest.mark.parametrize("operation", ["create", "start"])
def test_a_failed_start_whose_container_cannot_be_removed_is_left_for_reconciliation(
    make_runner: Callable[..., ContainerRunner],
    reconciler: ContainerReconciler,
    runtime: SpyRuntime,
    queue_seed: Seeder,
    world: World,
    operation: str,
) -> None:
    """create／start 回錯誤時容器仍可能已建立或已啟動（例如 client 逾時）：刪不掉就不轉成結束的
    狀態（之後的引擎會開始），留給對帳確認之後才結算。"""
    queue_seed.scan(world.operator_a, queue_seed.scannable(world))
    runtime.failing.update({operation, "remove"})

    with pytest.raises(RuntimeUnavailableError):
        make_runner().run_once(FAKE)

    [row] = queue_seed.query("SELECT id, status FROM scanner_runs")
    assert row.status == "running"
    runtime.failing.clear()
    _expire(queue_seed, row.id)
    assert reconciler.reconcile() == 1
    assert _run(queue_seed, row.id).status == "interrupted"


# --- DoD 1：不重複啟動 -------------------------------------------------------------------------


def test_no_container_starts_while_the_previous_one_may_still_run(
    orphan: Callable[..., Lease],
    make_runner: Callable[..., ContainerRunner],
    reconciler: ContainerReconciler,
    runtime: SpyRuntime,
    queue_seed: Seeder,
    world: World,
) -> None:
    """preflight 的容器在 lease 過期後仍在執行：同一個 scan 的下一個引擎要等它結算之後才開始。"""
    scannable = queue_seed.scannable(world)
    queue_seed.scan(world.operator_a, scannable, auth_profile_id=scannable.profile.id)
    preflight = orphan(engines=frozenset({ScanEngine.PREFLIGHT}), existing=True)
    runner = make_runner()

    assert runner.run_once(BOTH) is None  # 不認領同一個 scan 的 fake，也不會重新認領 preflight

    assert reconciler.reconcile() == 1
    report = runner.run_once(BOTH)
    assert report is not None
    assert report.run_id != preflight.run_id
    # 用量不明的 preflight 以分到的數量（當時剩下的全部）扣除（§16.4）：之後的引擎不送流量。
    assert (report.run_status, _run(queue_seed, report.run_id).error_code) == (
        R.FAILED,
        "BUDGET_EXHAUSTED",
    )
    assert [spec.name for spec in runtime.created] == [_name(preflight)]


def test_two_reconcilers_settle_a_run_once(
    orphan: Callable[..., Lease],
    reconciler: ContainerReconciler,
    queue: ScanQueue,
    runtime: SpyRuntime,
    workspace: Workspace,
    channel: SpyChannel,
    queue_seed: Seeder,
) -> None:
    lease = orphan()
    other = ContainerReconciler(queue, runtime, workspace, channel)

    assert reconciler.reconcile() + other.reconcile() == 1

    events = queue_seed.query(
        "SELECT count(*) AS n FROM scan_events WHERE scanner_run_id = :id "
        "AND payload->>'status' = 'interrupted'",
        id=lease.run_id,
    )
    assert events[0].n == 1


# --- 啟動時依證據清理 --------------------------------------------------------------------------


def test_startup_cleans_what_settled_or_unknown_runs_left(
    orphan: Callable[..., Lease],
    reconciler: ContainerReconciler,
    runtime: SpyRuntime,
    workspace: Workspace,
    channel: SpyChannel,
    guard: GuardDouble,
    tmp_path: Path,
) -> None:
    settled = orphan()
    channel.fail_remove = True
    reconciler.reconcile()  # 結算了，但 policy 刪不掉（保持 blocked）
    channel.fail_remove = False
    pending, leased = orphan(), orphan(expire=False)
    runtime.failing.update({"state", "version"})  # Docker 不可用：每個呼叫都失敗
    reconciler.reconcile()  # Docker 不可用：pending 保持待處理
    runtime.failing.clear()
    unknown = Lease(uuid4(), uuid4(), ScanEngine.FAKE, OWNER)
    workspace.write_secrets(unknown.run_id, {PROXY_FILE: "proxy"})
    channel.write(guard_policy_for(guard, settled.run_id, unknown.run_id))
    runtime.create(orphan_spec(unknown))

    cleaned = reconciler.sweep_orphans()

    assert cleaned == 2
    remaining = {pending.run_id, leased.run_id}
    assert {UUID(name.removesuffix(".json")) for name in guard.policy_files()} == remaining
    assert workspace.secret_runs() == {leased.run_id}  # pending 的 secret 在對帳時已刪除
    assert set(runtime.containers) == {_name(pending), _name(leased)}
    assert not (tmp_path / "secrets" / str(settled.run_id)).exists()


def test_startup_keeps_the_blocked_policy_while_docker_is_down(
    reconciler: ContainerReconciler,
    runtime: SpyRuntime,
    workspace: Workspace,
    channel: SpyChannel,
    guard: GuardDouble,
    orphan: Callable[..., Lease],
) -> None:
    template = orphan(expire=False)
    unknown = Lease(uuid4(), uuid4(), ScanEngine.FAKE, OWNER)
    channel.write(guard_policy_for(guard, template.run_id, unknown.run_id))
    runtime.create(orphan_spec(unknown))
    runtime.failing.update({"state", "version"})  # Docker 不可用：每個呼叫都失敗

    assert reconciler.sweep_orphans() == 0

    policy = guard.policy(unknown.run_id)
    assert policy is not None
    assert policy.state is PolicyState.BLOCKED
    assert _name(unknown) in runtime.containers


def guard_policy_for(guard: GuardDouble, source: UUID, run_id: UUID) -> Policy:
    """以另一個 run 的 policy 為範本，造出 DB 沒有的 run 留下的 active policy。"""
    policy = guard.policy(source)
    assert policy is not None
    return replace(policy, run_id=run_id, state=PolicyState.ACTIVE)


def test_startup_keeps_the_policy_of_a_container_being_removed(
    reconciler: ContainerReconciler,
    runtime: SpyRuntime,
    channel: SpyChannel,
    guard: GuardDouble,
    orphan: Callable[..., Lease],
) -> None:
    template = orphan(expire=False)
    first, second = (Lease(uuid4(), uuid4(), ScanEngine.FAKE, OWNER) for _ in range(2))
    for unknown in (first, second):
        channel.write(guard_policy_for(guard, template.run_id, unknown.run_id))
        runtime.create(orphan_spec(unknown))
    runtime.conflicting.add(_name(first))

    assert reconciler.sweep_orphans() == 1

    assert guard.policy(second.run_id) is None
    policy = guard.policy(first.run_id)
    assert policy is not None
    assert policy.state is PolicyState.BLOCKED


@pytest.mark.parametrize("directory", ["policies", "secrets"])
def test_startup_cleanup_survives_an_unreadable_directory(
    reconciler: ContainerReconciler,
    guard: GuardDouble,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    directory: str,
) -> None:
    """目錄讀不出來：記 ERROR、跳過這次清理，不讓 runner 啟動失敗（對帳照常每 10 秒一次）。"""
    target = guard.policies if directory == "policies" else tmp_path / "secrets"
    target.rename(target.with_name(f"{target.name}-moved"))

    with caplog.at_level(logging.ERROR, logger="secscan.runner.reconciler"):
        assert reconciler.sweep_orphans() == 0

    assert any("清理" in record.message for record in caplog.records)
