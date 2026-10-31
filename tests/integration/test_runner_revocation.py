"""授權撤回時停止執行中的 scan（docs/DECISIONS.md §17.5；SEC-01 後半）。

心跳回報 stop_reason（grant 撤銷、target 停用、建立者的 key 撤銷…）時：
- 執行中：先封鎖 guard、再停止容器 → run failed（該錯誤碼），不收集輸出。
- 建立容器之前（admit 或建立前的心跳）：不建立容器 → failed。
- 同時要求取消：走取消的路徑。
- 建立前的心跳發現 lease 已失效：不建立容器（LeaseLostError）。
in-process 的 FakeRunner 也一樣停止。每個測試用自己的資料庫（queue_database）。
"""

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from secscan.api_keys.service import ApiKeyService
from secscan.grants.service import ScopeGrantService
from secscan.guard.domain.policy import GuardPolicyVersion
from secscan.runner.fake import FakeRunner
from secscan.runner.service import ContainerRunner
from secscan.runner.workspace import Workspace
from secscan.scanners.domain.fake import FakeScript
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.domain.model import Lease
from secscan.scans.queue import Launch, LeaseLostError, RunReport, ScanQueue
from secscan.targets.domain import TargetUpdate
from secscan.targets.service import TargetService
from tests.guard_support import ENDPOINT, GuardDouble
from tests.integration.api_support import LAB, Scannable, Seeder, World
from tests.runner_fakes import FakeClock
from tests.runner_spies import POLICY, SpyChannel, SpyRuntime, logged_queue, without_renewals
from tests.secret_support import shared_cipher

pytestmark = pytest.mark.integration

OWNER = "runner-revocation-1"
FAKE = frozenset({ScanEngine.FAKE})
R = RunStatus

Change = Callable[[Engine, World, Scannable], None]


def _now() -> datetime:
    return datetime.now(UTC)


def _revoke(engine: Engine, world: World, scannable: Scannable) -> None:
    with Session(engine, expire_on_commit=False) as session, session.begin():
        ScopeGrantService(session, lab=LAB).revoke(
            world.admin.principal, scannable.grant.id, reason="停止", now=_now(), request_id=None
        )


def _disable(engine: Engine, world: World, scannable: Scannable) -> None:
    with Session(engine, expire_on_commit=False) as session, session.begin():
        TargetService(session, lab=LAB).update(
            world.operator_a.principal,
            scannable.target.id,
            TargetUpdate(enabled=False),
            request_id=None,
        )


def _revoke_creator(engine: Engine, world: World, scannable: Scannable) -> None:
    with Session(engine, expire_on_commit=False) as session, session.begin():
        ApiKeyService(session).revoke(
            world.admin.principal, world.operator_a.principal.key_id, request_id=None
        )


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
def scannable(queue_seed: Seeder, world: World) -> Scannable:
    return queue_seed.scannable(world)


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
def make_runner(
    queue: ScanQueue,
    runtime: SpyRuntime,
    workspace: Workspace,
    clock: FakeClock,
    channel: SpyChannel,
) -> Callable[..., ContainerRunner]:
    def factory(**overrides: Any) -> ContainerRunner:
        options: dict[str, Any] = {
            "owner": OWNER,
            "guard_policy_version": GuardPolicyVersion.STRICT,
            "policy": POLICY,
            "script": FakeScript(hold_seconds=12),
            "cipher": shared_cipher(),
            "guard": channel,
            "endpoint": ENDPOINT,
            "sleep": clock.sleep,
            "monotonic": clock.monotonic,
        }
        options.update(overrides)
        return ContainerRunner(queue, runtime, workspace, **options)

    return factory


def _report(runner: ContainerRunner) -> RunReport:
    report = runner.run_once(FAKE)
    assert report is not None
    return report


def _error(seed: Seeder, report: RunReport) -> str | None:
    [row] = seed.query("SELECT error_code FROM scanner_runs WHERE id = :id", id=report.run_id)
    error: str | None = row.error_code
    return error


def _after_heartbeats(count: int, action: Callable[[], None]) -> Callable[[], None]:
    """第 count 次心跳之後執行 action（只執行一次）。"""
    beats = [0]

    def on_heartbeat() -> None:
        beats[0] += 1
        if beats[0] == count:
            action()

    return on_heartbeat


# --- 執行中 ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("change", "error_code"),
    [
        (_revoke, RunErrorCode.SCOPE_REVOKED),
        (_disable, RunErrorCode.TARGET_DISABLED),
        (_revoke_creator, RunErrorCode.CREATOR_KEY_REVOKED),
    ],
    ids=["revoked", "disabled", "creator-revoked"],
)
def test_a_running_scan_stops_when_its_authorization_is_withdrawn(
    make_runner: Callable[..., ContainerRunner],
    log: list[str],
    clock: FakeClock,
    guard: GuardDouble,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    tmp_path: Path,
    change: Change,
    error_code: RunErrorCode,
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    clock.at(6, lambda: change(queue_engine, world, scannable))

    report = _report(make_runner())

    assert (report.run_status, _error(queue_seed, report)) == (R.FAILED, error_code.value)
    assert without_renewals(log)[3:] == [
        "policy:blocked",
        "stop",
        "remove",
        "policy:removed",
        "run:failed",
    ]
    assert clock.now < 12  # 在容器自己結束之前停止
    assert not (tmp_path / "runs" / str(report.run_id) / "manifest.json").exists()
    assert guard.policy_files() == []


def test_a_cancel_takes_precedence_over_a_revocation(
    make_runner: Callable[..., ContainerRunner],
    clock: FakeClock,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    scan = queue_seed.scan(world.operator_a, scannable)

    def both() -> None:
        _revoke(queue_engine, world, scannable)
        queue_seed.execute(
            "UPDATE scans SET cancel_requested_at = now() WHERE id = :id", id=scan.id
        )

    clock.at(6, both)

    assert _report(make_runner()).run_status is R.CANCELLED


# --- 建立容器之前 ------------------------------------------------------------------------------


def test_a_revocation_right_after_prepare_creates_no_container(
    make_runner: Callable[..., ContainerRunner],
    queue: ScanQueue,
    runtime: SpyRuntime,
    log: list[str],
    guard: GuardDouble,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    prepare_launch = queue.prepare_launch

    def revoked_after(lease: Lease, *, image_ref: str) -> Launch:
        launch = prepare_launch(lease, image_ref=image_ref)
        _revoke(queue_engine, world, scannable)
        return launch

    queue.prepare_launch = revoked_after  # type: ignore[method-assign]

    report = _report(make_runner())

    assert (report.run_status, _error(queue_seed, report)) == (R.FAILED, "SCOPE_REVOKED")
    assert runtime.created == []
    assert log == ["remove", "run:failed"]  # 沒有寫過 policy；刪除以名稱進行（不存在也算成功）
    assert guard.policy_files() == []


def test_a_revocation_before_the_container_is_created_stops_it(
    make_runner: Callable[..., ContainerRunner],
    runtime: SpyRuntime,
    log: list[str],
    guard: GuardDouble,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    tmp_path: Path,
) -> None:
    """policy 已寫好、還沒建立容器：建立前的心跳看到撤銷 → 不建立，policy 封鎖後刪除。"""
    queue_seed.scan(world.operator_a, scannable)
    revoke = _after_heartbeats(1, lambda: _revoke(queue_engine, world, scannable))

    report = _report(make_runner(on_heartbeat=revoke))

    assert (report.run_status, _error(queue_seed, report)) == (R.FAILED, "SCOPE_REVOKED")
    assert runtime.created == []
    assert log == ["policy:active", "policy:blocked", "remove", "policy:removed", "run:failed"]
    assert guard.policy_files() == []
    assert list((tmp_path / "secrets").iterdir()) == []


def test_a_lease_lost_before_the_container_is_created_creates_nothing(
    make_runner: Callable[..., ContainerRunner],
    runtime: SpyRuntime,
    guard: GuardDouble,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    tmp_path: Path,
) -> None:
    """凍結的 owner：對帳在它寫好 policy 之後結算，建立前的心跳讓它不建立容器（DoD 1）。"""
    queue_seed.scan(world.operator_a, scannable)
    expire = _after_heartbeats(
        1,
        lambda: queue_seed.execute(
            "UPDATE scanner_runs SET lease_expires_at = now() - interval '1 second'"
        ),
    )

    with pytest.raises(LeaseLostError):
        make_runner(on_heartbeat=expire).run_once(FAKE)

    assert runtime.created == []
    assert guard.policy_files() == []
    assert list((tmp_path / "secrets").iterdir()) == []


# --- in-process 的 FakeRunner ------------------------------------------------------------------


def test_the_in_process_runner_stops_a_revoked_run(
    queue_engine: Engine, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    clock = FakeClock()
    queue_seed.scan(world.operator_a, scannable)
    clock.at(6, lambda: _revoke(queue_engine, world, scannable))
    runner = FakeRunner(
        ScanQueue(sessionmaker(queue_engine, expire_on_commit=False), lab=LAB, clock=_now),
        owner=OWNER,
        script=FakeScript(hold_seconds=30),
        sleep=clock.sleep,
        monotonic=clock.monotonic,
    )

    report = runner.run_once()

    assert report is not None
    assert (report.run_status, _error(queue_seed, report)) == (R.FAILED, "SCOPE_REVOKED")
    assert clock.now <= 10
