"""runner 異常結束之後的升級（資料庫審查 M2；docs/DECISIONS.md §30.13 的剩餘風險 12）。

runner 被 OOM kill 或 kill -9 時不會清理：run 停在 running、lease 還有效或已過期、容器可能還在、
DB 沒有記下容器已刪除。搬移指令依核准的前提拒絕（不刪紀錄、不略過檢查），直到 runner 的對帳
（ContainerReconciler，新版與舊版是同一段程式）確認容器的狀態：
- lease 還有效：拒絕（等 lease 過期）。
- lease 已過期、容器還沒確認刪除：拒絕，訊息附上人工修復的程序。
- 容器還在而且是這個 run 的（label 相符）：對帳先刪除容器、才結算，之後可以搬移。
- 容器已經不在（404）：結算，之後可以搬移。
- 同名但不是這個 run 的容器：不刪除它，只結算這個 run（主機端的 make target 另外確認沒有任何容器
  使用 runs volume）。
- Docker 不可用：不結算，搬移仍然拒絕。
每個測試用自己的資料庫（queue_database）；Docker 是記憶體中的替身。
"""

from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import Engine

from secscan.cli import EXIT_FAILURE, EXIT_OK, runs_layout
from secscan.runner.domain.admission import ContainerSpec
from secscan.runner.reconciler import ContainerReconciler
from secscan.runner.workspace import Workspace
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.model import Lease
from secscan.scans.queue import ScanQueue
from tests.guard_support import GuardDouble
from tests.integration.api_support import LAB, Seeder, World
from tests.runner_fakes import FakeClock, FakeContainer
from tests.runner_spies import SpyChannel, SpyRuntime, abandon, logged_queue

pytestmark = pytest.mark.integration

OWNER = "runner-crashed"
FAKE = frozenset({ScanEngine.FAKE})
CANARY = b"canary-crashed-run-3e1d"


@pytest.fixture
def log() -> list[str]:
    return []


@pytest.fixture
def queue(queue_engine: Engine, log: list[str]) -> ScanQueue:
    return logged_queue(queue_engine, log, lab=LAB)


@pytest.fixture
def runtime(log: list[str]) -> SpyRuntime:
    runtime = SpyRuntime(clock=FakeClock())
    runtime.log = log
    return runtime


@pytest.fixture
def volume(tmp_path: Path) -> Path:
    """舊的 layout：run 目錄直接在 volume 的根目錄（升級之前的 runner 就是這樣寫的）。"""
    root = tmp_path / "runs"
    root.mkdir()
    (tmp_path / "secrets").mkdir()
    return root


@pytest.fixture
def workspace(volume: Path) -> Workspace:
    return Workspace(volume, volume.parent / "secrets")


@pytest.fixture
def channel(tmp_path: Path, log: list[str]) -> SpyChannel:
    return SpyChannel(GuardDouble.create(tmp_path), log)


@pytest.fixture
def reconciler(
    queue: ScanQueue, runtime: SpyRuntime, workspace: Workspace, channel: SpyChannel
) -> ContainerReconciler:
    return ContainerReconciler(queue, runtime, workspace, channel)


@pytest.fixture
def crashed(
    queue: ScanQueue,
    runtime: SpyRuntime,
    workspace: Workspace,
    channel: SpyChannel,
    queue_seed: Seeder,
    volume: Path,
) -> Lease:
    """runner 在容器執行中被 OOM kill 或 kill -9：容器還在、lease 還有效、run 目錄有明文。"""
    world: World = queue_seed.world()
    queue_seed.scan(world.operator_a, queue_seed.scannable(world))
    lease = queue.claim(OWNER, FAKE)
    assert lease is not None
    abandon(queue, runtime, workspace, channel, lease)
    (volume / str(lease.run_id) / "out").mkdir(parents=True, exist_ok=True)
    (volume / str(lease.run_id) / "out" / "messages.txt").write_bytes(CANARY)
    return lease


def _expire(seed: Seeder, run_id: UUID) -> None:
    seed.execute(
        "UPDATE scanner_runs SET lease_expires_at = now() - interval '1 second' WHERE id = :id",
        id=run_id,
    )


def _run(seed: Seeder, run_id: UUID) -> Any:
    [row] = seed.query(
        "SELECT status, error_code, container_removed_at FROM scanner_runs WHERE id = :id",
        id=run_id,
    )
    return row


def _migrate(engine: Engine, volume: Path) -> tuple[int, str]:
    messages: list[str] = []
    code = runs_layout.migrate_volume(engine, volume, dry_run=False, report=messages.append)
    return code, "\n".join(messages)


def _untouched(volume: Path, lease: Lease) -> bool:
    plaintext = volume / str(lease.run_id) / "out" / "messages.txt"
    return plaintext.read_bytes() == CANARY and not (volume / "active").exists()


def test_a_crash_with_a_live_lease_blocks_the_migration(
    crashed: Lease, queue_engine: Engine, volume: Path
) -> None:
    code, output = _migrate(queue_engine, volume)

    assert code == EXIT_FAILURE
    assert "有效的 lease" in output
    assert _untouched(volume, crashed)


def test_an_expired_lease_with_an_unconfirmed_container_needs_reconciliation(
    crashed: Lease, queue_engine: Engine, queue_seed: Seeder, volume: Path
) -> None:
    """lease 過期之後仍然拒絕：容器可能還在執行，DB 沒有記下它已刪除。不刪紀錄、不略過檢查。"""
    _expire(queue_seed, crashed.run_id)

    code, output = _migrate(queue_engine, volume)

    assert code == EXIT_FAILURE
    assert "容器還沒確認刪除" in output
    assert "人工修復" in output
    assert _run(queue_seed, crashed.run_id).container_removed_at is None
    assert _untouched(volume, crashed)


def test_a_running_container_is_removed_before_the_run_is_settled(
    crashed: Lease,
    reconciler: ContainerReconciler,
    runtime: SpyRuntime,
    queue_engine: Engine,
    queue_seed: Seeder,
    volume: Path,
    log: list[str],
) -> None:
    """容器還在而且是這個 run 的：對帳先刪除它，才結算；之後搬移可以完成。"""
    _expire(queue_seed, crashed.run_id)
    log.clear()

    assert reconciler.reconcile() == 1

    name = f"secscan-run-{crashed.run_id}"
    assert name not in runtime.containers
    assert log.index("remove") < log.index("run:settled")
    row = _run(queue_seed, crashed.run_id)
    assert (row.status, row.error_code) == ("interrupted", "LEASE_EXPIRED")
    assert row.container_removed_at is not None
    code, output = _migrate(queue_engine, volume)
    assert code == EXIT_OK, output
    assert (volume / "active" / str(crashed.run_id) / "out" / "messages.txt").read_bytes() == CANARY


def test_a_container_that_is_already_gone_is_settled_then_migrated(
    crashed: Lease,
    reconciler: ContainerReconciler,
    runtime: SpyRuntime,
    queue_engine: Engine,
    queue_seed: Seeder,
    volume: Path,
) -> None:
    """OOM 時 Docker 也把容器刪掉了（或操作者已刪除）：inspect 回 404 才結算。"""
    _expire(queue_seed, crashed.run_id)
    runtime.containers.clear()

    assert reconciler.reconcile() == 1

    assert _run(queue_seed, crashed.run_id).container_removed_at is not None
    assert _migrate(queue_engine, volume)[0] == EXIT_OK


def test_a_container_of_someone_else_is_not_removed(
    crashed: Lease,
    reconciler: ContainerReconciler,
    runtime: SpyRuntime,
    queue_engine: Engine,
    queue_seed: Seeder,
    volume: Path,
) -> None:
    """同名、但 label 不是這個 run 的容器：不刪除它，只結算這個 run（不誤判仍存在的容器）。"""
    _expire(queue_seed, crashed.run_id)
    name = f"secscan-run-{crashed.run_id}"
    spec = runtime.containers[name].spec
    foreign = ContainerSpec(name=spec.name, body={**spec.body, "Labels": {"app": "other"}})
    runtime.containers[name] = FakeContainer(foreign, started_at=0.0)

    assert reconciler.reconcile() == 1

    assert runtime.containers[name].spec is foreign
    assert "remove" not in runtime.log
    assert _run(queue_seed, crashed.run_id).container_removed_at is not None


def test_docker_unavailable_keeps_the_migration_blocked(
    crashed: Lease,
    reconciler: ContainerReconciler,
    runtime: SpyRuntime,
    queue_engine: Engine,
    queue_seed: Seeder,
    volume: Path,
) -> None:
    """Docker 不可用時不結算（不能證明容器已停止），搬移仍然拒絕。"""
    _expire(queue_seed, crashed.run_id)
    runtime.failing.update({"state", "version"})

    assert reconciler.reconcile() == 0

    assert _run(queue_seed, crashed.run_id).container_removed_at is None
    code, output = _migrate(queue_engine, volume)
    assert code == EXIT_FAILURE
    assert "容器還沒確認刪除" in output
    assert _untouched(volume, crashed)
