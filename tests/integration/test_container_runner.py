"""容器版的 runner（docs/DECISIONS.md §14.6）：真的 DB 佇列加上記憶體中的容器 runtime。

每一步都經過佇列的轉換；容器一律刪除，secret 只在容器存在時存在。
每個測試用自己的資料庫（queue_database）。
"""

import stat
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import Engine, Row
from sqlalchemy.orm import Session, sessionmaker

from secscan.runner.domain.admission import (
    AUTH_HEADER_FILE,
    PROXY_FILE,
    SECRET_FILE,
    ContainerSpec,
)
from secscan.runner.domain.policy import ENGINE_POLICIES, ContainerPolicy
from secscan.runner.domain.runtime import RuntimeUnavailableError
from secscan.runner.service import ContainerRunner
from secscan.runner.workspace import CollectionLimits, Workspace, WorkspaceError
from secscan.scanners.domain.fake import FakeOutcome, FakeScript
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.catalog import ScanProfile, plan_runs
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus, ScanStatus
from secscan.scans.domain.model import Lease, NewScan
from secscan.scans.domain.request import BudgetRequest
from secscan.scans.queue import Launch, LeaseLostError, RunReport, ScanQueue
from secscan.scans.repository import ScanRepository
from secscan.scans.service import ScanService
from secscan.security.secret_cipher import SecretCipher
from secscan.worker.service import Worker
from tests.guard_support import ENDPOINT, GuardDouble
from tests.integration.api_support import DEFAULT_SECRET, LAB, Scannable, Seeder, World
from tests.runner_fakes import FakeClock, FakeContainerRuntime
from tests.secret_support import shared_cipher

pytestmark = pytest.mark.integration

OWNER = "runner-container-1"
FAKE = frozenset({ScanEngine.FAKE})
PREFLIGHT = frozenset({ScanEngine.PREFLIGHT})
POLICY = ContainerPolicy(
    scan_network="secscan_scan_net",
    runs_volume="secscan_runs",
    secrets_volume="secscan_run_secrets",
)
R = RunStatus
S = ScanStatus


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


@pytest.fixture
def make_runner(
    queue: ScanQueue,
    runtime: FakeContainerRuntime,
    workspace: Workspace,
    clock: FakeClock,
    guard: GuardDouble,
) -> Callable[..., ContainerRunner]:
    def factory(**overrides: Any) -> ContainerRunner:
        options: dict[str, Any] = {
            "owner": OWNER,
            "policy": POLICY,
            "script": FakeScript(hold_seconds=3),
            "cipher": shared_cipher(),
            "guard": guard.channel(),
            "endpoint": ENDPOINT,
            "sleep": clock.sleep,
            "monotonic": clock.monotonic,
        }
        options.update(overrides)
        return ContainerRunner(queue, runtime, workspace, **options)

    return factory


def _run(seed: Seeder, run_id: UUID) -> Row[Any]:
    [row] = seed.query(
        "SELECT status, error_code, container_name, image_ref, lease_owner FROM scanner_runs "
        "WHERE id = :id",
        id=run_id,
    )
    return row


def _events(seed: Seeder, scan_id: UUID) -> list[str]:
    rows = seed.query(
        "SELECT event_type, payload FROM scan_events WHERE scan_id = :id ORDER BY sequence",
        id=scan_id,
    )
    return [
        f"{row.event_type}:{row.payload.get('status', 'requested')}"
        for row in rows
        if row.event_type != "scan.created"
    ]


def _mount_targets(spec: ContainerSpec) -> list[object]:
    host = spec.body["HostConfig"]
    assert isinstance(host, dict)
    mounts = host["Mounts"]
    assert isinstance(mounts, list)
    return [mount["Target"] for mount in mounts if isinstance(mount, dict)]


def _report(runner: ContainerRunner, engines: frozenset[ScanEngine] = FAKE) -> RunReport:
    report = runner.run_once(engines)
    assert report is not None
    return report


def _authenticated(seed: Seeder, world: World, scannable: Scannable) -> None:
    """綁定 auth profile：第一個 run 是 preflight，target 的 secret 注入它的容器（§16.5）。"""
    seed.scan(world.operator_a, scannable, auth_profile_id=scannable.profile.id)


# --- 成功 ----------------------------------------------------------------------------------


def test_a_fake_run_goes_through_a_container_and_the_worker(
    make_runner: Callable[..., ContainerRunner],
    runtime: FakeContainerRuntime,
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    workspace: Workspace,
    tmp_path: Path,
) -> None:
    scan = queue_seed.scan(world.operator_a, scannable)

    report = _report(make_runner())

    assert (report.run_status, report.scan_status) == (R.COLLECTED, S.COLLECTING)
    [spec] = runtime.created
    assert spec.name == f"secscan-run-{report.run_id}"
    assert runtime.removed == [spec.name]
    assert runtime.containers == {}
    run = _run(queue_seed, report.run_id)
    assert (run.container_name, run.image_ref) == (spec.name, spec.body["Image"])
    assert (tmp_path / "runs" / str(report.run_id) / "manifest.json").exists()
    assert list((tmp_path / "secrets").iterdir()) == []

    [parsed] = Worker(queue, owner="worker-1").drain()

    assert (parsed.run_status, parsed.scan_status) == (R.SUCCEEDED, S.COMPLETED)
    assert _events(queue_seed, scan.id) == [
        "run.status:preparing",
        "scan.status:preparing",
        "run.status:running",
        "scan.status:running",
        "run.status:collecting",
        "scan.status:collecting",
        "run.status:collected",
        "run.status:normalizing",
        "scan.status:normalizing",
        "run.status:succeeded",
        "scan.status:completed",
    ]


def test_no_work_means_no_container(
    make_runner: Callable[..., ContainerRunner], runtime: FakeContainerRuntime
) -> None:
    runner = make_runner()

    assert runner.run_once(FAKE) is None
    assert runner.run_once(frozenset()) is None
    assert runtime.created == []


def test_heartbeats_keep_the_lease_and_the_instance_alive(
    make_runner: Callable[..., ContainerRunner],
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    beats: list[float] = []

    report = _report(
        make_runner(script=FakeScript(hold_seconds=40), on_heartbeat=lambda: beats.append(1))
    )

    # lease 是 30 秒：停留 40 秒仍然成功，代表期間有延長。寫 policy 之前心跳一次（guard 的
    # renew_until 以它為準，docs/DECISIONS.md §15.7），建立容器之前再一次（§17.2），啟動後立刻
    # 一次，之後每 5 秒一次（第 0 到 40 秒共 9 次；心跳在查狀態之前），收集之前再心跳一次。
    assert report.run_status is R.COLLECTED
    assert len(beats) == 12


# --- secret --------------------------------------------------------------------------------


def test_the_secret_exists_only_while_the_container_does(
    make_runner: Callable[..., ContainerRunner],
    runtime: FakeContainerRuntime,
    clock: FakeClock,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    tmp_path: Path,
) -> None:
    _authenticated(queue_seed, world, scannable)
    seen: list[tuple[str, str, int]] = []

    def look() -> None:
        for name in (SECRET_FILE, AUTH_HEADER_FILE):
            [secret] = (tmp_path / "secrets").glob(f"*/{name}")
            mode = stat.S_IMODE(secret.stat().st_mode)
            seen.append((name, secret.read_text(encoding="utf-8"), mode))

    clock.at(1, look)
    report = _report(make_runner(), PREFLIGHT)

    assert seen == [
        (SECRET_FILE, DEFAULT_SECRET, 0o400),
        (AUTH_HEADER_FILE, f"Authorization: Bearer {DEFAULT_SECRET}", 0o400),
    ]
    assert list((tmp_path / "secrets").iterdir()) == []
    [spec] = runtime.created
    assert DEFAULT_SECRET not in str(spec.body)
    assert _mount_targets(spec)[-1] == "/scan/secret"
    assert report.run_status is R.COLLECTED


def test_an_anonymous_scan_gets_only_the_proxy_url(
    make_runner: Callable[..., ContainerRunner],
    runtime: FakeContainerRuntime,
    clock: FakeClock,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    tmp_path: Path,
) -> None:
    """secret 目錄一律掛載（proxy-url，docs/DECISIONS.md §15.7）；沒有認證就沒有 target-auth。"""
    queue_seed.scan(world.operator_a, scannable, auth_profile_id=None)
    seen: list[list[str]] = []
    clock.at(
        1,
        lambda: seen.extend(
            sorted(p.name for p in d.iterdir()) for d in (tmp_path / "secrets").iterdir()
        ),
    )

    _report(make_runner())

    [spec] = runtime.created
    assert _mount_targets(spec) == ["/scan/in", "/scan/out", "/scan/secret"]
    assert seen == [[PROXY_FILE]]


@pytest.mark.parametrize("cipher", ["other-keys", "none"])
def test_an_unreadable_secret_fails_before_any_container(
    make_runner: Callable[..., ContainerRunner],
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    tmp_path: Path,
    cipher: str,
) -> None:
    _authenticated(queue_seed, world, scannable)
    other = SecretCipher.from_setting(Fernet.generate_key().decode())

    report = _report(make_runner(cipher=other if cipher == "other-keys" else None), PREFLIGHT)

    # 之後的 fake run 還在排隊（它也會因為解不開 secret 而失敗）。
    assert (report.run_status, report.scan_status) == (R.FAILED, S.RUNNING)
    assert _run(queue_seed, report.run_id).error_code == RunErrorCode.SECRET_UNAVAILABLE
    assert runtime.created == []
    assert list((tmp_path / "secrets").iterdir()) == []


# --- 失敗、逾時、取消 ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("script", "out_of_memory", "code"),
    [
        (FakeScript(outcome=FakeOutcome.FAIL), False, RunErrorCode.ENGINE_FAILED),
        (FakeScript(hold_seconds=2), True, RunErrorCode.RESOURCE_LIMIT_EXCEEDED),
    ],
)
def test_a_failing_container_fails_the_run(
    make_runner: Callable[..., ContainerRunner],
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    script: FakeScript,
    out_of_memory: bool,
    code: RunErrorCode,
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    runtime.out_of_memory = out_of_memory

    report = _report(make_runner(script=script))

    assert (report.run_status, report.scan_status) == (R.FAILED, S.FAILED)
    assert _run(queue_seed, report.run_id).error_code == code
    assert runtime.containers == {}


def test_the_time_limit_stops_the_container(
    make_runner: Callable[..., ContainerRunner],
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    queue_seed.scan(world.operator_a, scannable, budget=BudgetRequest(max_duration_seconds=10))

    report = _report(make_runner(script=FakeScript(hold_seconds=60)))

    assert (report.run_status, report.scan_status) == (R.TIMED_OUT, S.TIMED_OUT)
    assert _run(queue_seed, report.run_id).error_code == RunErrorCode.TIME_LIMIT_EXCEEDED
    assert len(runtime.stopped) == 1
    assert runtime.containers == {}


def test_a_cancel_stops_the_container_before_it_is_confirmed(
    make_runner: Callable[..., ContainerRunner],
    runtime: FakeContainerRuntime,
    clock: FakeClock,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    scan = queue_seed.scan(world.operator_a, scannable)

    def cancel() -> None:
        with Session(queue_engine, expire_on_commit=False) as session, session.begin():
            ScanService(session, lab=LAB).cancel(
                world.operator_a.principal, scan.id, request_id=None
            )

    clock.at(6, cancel)
    report = _report(make_runner(script=FakeScript(hold_seconds=60)))

    assert (report.run_status, report.scan_status) == (R.CANCELLED, S.CANCELLED)
    assert len(runtime.stopped) == 1
    assert runtime.containers == {}
    # 取消在心跳時看到，最多再等 5 秒（ARCHITECTURE.md §9 的目標是 10 秒內停止新的出站）。
    assert clock.now <= 6 + 5 + 1
    # API 記下取消（scan 已是 cancelling）；runner 在心跳時看到，先轉到 cancelling 再停止容器。
    assert _events(queue_seed, scan.id)[-5:] == [
        "scan.cancel_requested:requested",
        "scan.status:cancelling",
        "run.status:cancelling",
        "run.status:cancelled",
        "scan.status:cancelled",
    ]


def test_a_cancel_seen_by_prepare_needs_no_container(
    make_runner: Callable[..., ContainerRunner],
    runtime: FakeContainerRuntime,
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """認領之後、prepare 之前才要求取消：prepare 看到取消，不建立容器。"""
    scan = queue_seed.scan(world.operator_a, scannable)
    prepare_launch = queue.prepare_launch

    def cancel_first(lease: Lease, *, image_ref: str) -> Launch:
        queue_seed.execute(
            "UPDATE scans SET cancel_requested_at = now() WHERE id = :id", id=scan.id
        )
        return prepare_launch(lease, image_ref=image_ref)

    monkeypatch.setattr(queue, "prepare_launch", cancel_first)

    report = _report(make_runner())

    assert (report.run_status, report.scan_status) == (R.CANCELLED, S.CANCELLED)
    assert runtime.created == []


def test_a_refused_gate_starts_nothing(
    make_runner: Callable[..., ContainerRunner],
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    queue_seed.execute("UPDATE targets SET enabled = false WHERE id = :id", id=scannable.target.id)

    report = _report(make_runner())

    assert (report.run_status, report.scan_status) == (R.FAILED, S.FAILED)
    assert _run(queue_seed, report.run_id).error_code == RunErrorCode.TARGET_DISABLED
    assert runtime.created == []


def test_a_stopping_runner_interrupts_the_run_after_removing_the_container(
    make_runner: Callable[..., ContainerRunner],
    runtime: FakeContainerRuntime,
    clock: FakeClock,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    stopping: list[bool] = []
    clock.at(2, lambda: stopping.append(True))

    report = _report(
        make_runner(script=FakeScript(hold_seconds=60), stop_requested=lambda: bool(stopping))
    )

    assert (report.run_status, report.scan_status) == (R.INTERRUPTED, S.INTERRUPTED)
    assert _run(queue_seed, report.run_id).error_code == RunErrorCode.RUNNER_STOPPED
    assert runtime.containers == {}


def test_a_lost_lease_stops_the_container_and_leaves_the_run(
    make_runner: Callable[..., ContainerRunner],
    runtime: FakeContainerRuntime,
    clock: FakeClock,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    tmp_path: Path,
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    clock.at(
        3,
        lambda: queue_seed.execute(
            "UPDATE scanner_runs SET lease_expires_at = now() - interval '1 second' "
            "WHERE lease_owner = :owner",
            owner=OWNER,
        ),
    )

    with pytest.raises(LeaseLostError):
        make_runner(script=FakeScript(hold_seconds=60)).run_once(FAKE)

    assert len(runtime.stopped) == 1
    assert runtime.containers == {}
    assert list((tmp_path / "secrets").iterdir()) == []
    [row] = queue_seed.query("SELECT status FROM scanner_runs")
    assert row.status == "running"


# --- 拒絕與 Docker 的錯誤 -------------------------------------------------------------------


def test_a_rejected_plan_never_reaches_docker(
    make_runner: Callable[..., ContainerRunner],
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    tmp_path: Path,
) -> None:
    queue_seed.scan(world.operator_a, scannable)

    report = _report(make_runner(engine_policies={}))

    assert (report.run_status, report.scan_status) == (R.FAILED, S.FAILED)
    assert _run(queue_seed, report.run_id).error_code == RunErrorCode.PLAN_REJECTED
    assert runtime.created == []
    assert list((tmp_path / "secrets").iterdir()) == []
    # 沒有流量：之後的 run 不必保守扣掉這個 run 分到的預算（docs/DECISIONS.md §16.4）。
    [usage] = queue_seed.query(
        "SELECT requests_sent, traffic_seconds FROM scanner_runs WHERE id = :id",
        id=report.run_id,
    )
    assert tuple(usage) == (0, 0)


@pytest.mark.parametrize("operation", ["create", "start"])
def test_docker_errors_before_the_start_fail_the_run(
    make_runner: Callable[..., ContainerRunner],
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    tmp_path: Path,
    operation: str,
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    runtime.failing.add(operation)

    report = _report(make_runner())

    assert (report.run_status, report.scan_status) == (R.FAILED, S.FAILED)
    assert _run(queue_seed, report.run_id).error_code == RunErrorCode.RUNTIME_UNAVAILABLE
    assert runtime.containers == {}
    assert list((tmp_path / "secrets").iterdir()) == []


def test_a_vanished_container_fails_the_run(
    make_runner: Callable[..., ContainerRunner],
    runtime: FakeContainerRuntime,
    clock: FakeClock,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    clock.at(2, runtime.containers.clear)

    report = _report(make_runner(script=FakeScript(hold_seconds=60)))

    assert _run(queue_seed, report.run_id).error_code == RunErrorCode.RUNTIME_UNAVAILABLE


def test_docker_lost_mid_run_leaves_the_run_for_reconciliation(
    make_runner: Callable[..., ContainerRunner],
    runtime: FakeContainerRuntime,
    clock: FakeClock,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    tmp_path: Path,
) -> None:
    """無法確認容器已停止：不標成任何結束的狀態（T13 的容器對帳處理），secret 仍然刪除。"""
    queue_seed.scan(world.operator_a, scannable)
    clock.at(2, lambda: runtime.failing.update({"state", "stop", "remove"}))

    with pytest.raises(RuntimeUnavailableError):
        make_runner(script=FakeScript(hold_seconds=60)).run_once(FAKE)

    [row] = queue_seed.query("SELECT status FROM scanner_runs")
    assert row.status == "running"
    assert list((tmp_path / "secrets").iterdir()) == []


def test_rejected_output_fails_the_run(
    make_runner: Callable[..., ContainerRunner],
    clock: FakeClock,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    tmp_path: Path,
) -> None:
    queue_seed.scan(world.operator_a, scannable)

    def plant() -> None:
        [out] = (tmp_path / "runs").glob("*/out")
        (out / "steal").symlink_to(tmp_path / "secrets")

    clock.at(1, plant)
    report = _report(make_runner())

    assert (report.run_status, report.scan_status) == (R.FAILED, S.FAILED)
    assert _run(queue_seed, report.run_id).error_code == RunErrorCode.ARTIFACT_REJECTED


def test_only_the_requested_engines_are_claimed(
    make_runner: Callable[..., ContainerRunner],
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    queue_seed.scan(world.operator_a, scannable)

    assert make_runner().run_once(frozenset({ScanEngine.ZAP})) is None
    assert runtime.created == []


def test_engine_policies_default_to_the_shared_table() -> None:
    assert ScanEngine.FAKE in ENGINE_POLICIES


# --- 審查後補上 -------------------------------------------------------------------------------


def test_the_first_heartbeat_comes_right_after_the_start(
    make_runner: Callable[..., ContainerRunner],
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    """lease 從認領起算：建立與啟動容器很慢時，等到第 5 秒才心跳可能已經過期（審查發現）。"""
    queue_seed.scan(world.operator_a, scannable)
    beats: list[int] = []

    report = _report(
        make_runner(script=FakeScript(hold_seconds=1), on_heartbeat=lambda: beats.append(1))
    )

    # 寫 policy 之前、建立容器之前（§17.2）、啟動之後立刻、收集之前各一次。
    assert report.run_status is R.COLLECTED
    assert len(beats) == 4


@pytest.mark.parametrize("volume", ["runs", "secrets"])
def test_an_unwritable_volume_fails_the_run_without_a_container(
    make_runner: Callable[..., ContainerRunner],
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    tmp_path: Path,
    volume: str,
) -> None:
    """權限錯誤或磁碟滿：run 失敗、不建立容器、不留 secret；runner 不會因此結束（審查發現）。"""
    queue_seed.scan(world.operator_a, scannable)
    (tmp_path / volume).chmod(0o500)
    try:
        report = _report(make_runner())
    finally:
        (tmp_path / volume).chmod(0o700)

    assert (report.run_status, report.scan_status) == (R.FAILED, S.FAILED)
    assert _run(queue_seed, report.run_id).error_code == RunErrorCode.WORKSPACE_UNAVAILABLE
    assert runtime.created == []
    assert list((tmp_path / "secrets").iterdir()) == []


@pytest.mark.parametrize("operation", ["start", "state"])
def test_an_unexpected_error_still_removes_the_container_and_the_secret(
    make_runner: Callable[..., ContainerRunner],
    runtime: FakeContainerRuntime,
    clock: FakeClock,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    """程式錯誤一樣往外拋，但容器與 secret 先清掉（審查發現：啟動之前的例外原本不清理）。"""
    queue_seed.scan(world.operator_a, scannable)

    def broken(_name: str) -> None:
        raise KeyError("State")

    if operation == "start":
        monkeypatch.setattr(runtime, "start", broken)
    else:
        clock.at(2, lambda: monkeypatch.setattr(runtime, "state", broken))

    with pytest.raises(KeyError):
        make_runner(script=FakeScript(hold_seconds=60)).run_once(FAKE)

    assert runtime.containers == {}
    assert list((tmp_path / "secrets").iterdir()) == []


def test_a_brief_docker_error_is_retried(
    make_runner: Callable[..., ContainerRunner],
    runtime: FakeContainerRuntime,
    clock: FakeClock,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    """socket-proxy 一次逾時不放棄整個 run（審查發現）。"""
    queue_seed.scan(world.operator_a, scannable)
    clock.at(2, lambda: runtime.failing.add("state"))
    clock.at(4, lambda: runtime.failing.discard("state"))

    report = _report(make_runner(script=FakeScript(hold_seconds=6)))

    assert report.run_status is R.COLLECTED


def test_docker_lost_but_the_container_removed_interrupts_the_run(
    make_runner: Callable[..., ContainerRunner],
    runtime: FakeContainerRuntime,
    clock: FakeClock,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    """查不到狀態，但刪除容器成功：容器確定已停止，可以標成 interrupted（審查發現）。"""
    queue_seed.scan(world.operator_a, scannable)
    clock.at(2, lambda: runtime.failing.add("state"))

    report = _report(make_runner(script=FakeScript(hold_seconds=60)))

    assert (report.run_status, report.scan_status) == (R.INTERRUPTED, S.INTERRUPTED)
    assert _run(queue_seed, report.run_id).error_code == RunErrorCode.RUNTIME_UNAVAILABLE
    assert runtime.containers == {}


def test_output_over_the_limits_stops_the_container(
    queue: ScanQueue,
    runtime: FakeContainerRuntime,
    clock: FakeClock,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    tmp_path: Path,
) -> None:
    """out/ 沒有磁碟配額：執行中就檢查用量，超過時停止容器（審查發現）。"""
    queue_seed.scan(world.operator_a, scannable)
    for name in ("runs", "secrets"):
        (tmp_path / name).mkdir()
    small = Workspace(
        tmp_path / "runs", tmp_path / "secrets", limits=CollectionLimits(max_total_bytes=4)
    )

    def flood() -> None:
        [out] = (tmp_path / "runs").glob("*/out")
        (out / "flood").write_bytes(b"x" * 5)

    clock.at(2, flood)
    runner = ContainerRunner(
        queue,
        runtime,
        small,
        owner=OWNER,
        policy=POLICY,
        script=FakeScript(hold_seconds=60),
        cipher=shared_cipher(),
        guard=GuardDouble.create(tmp_path).channel(),
        endpoint=ENDPOINT,
        sleep=clock.sleep,
        monotonic=clock.monotonic,
    )

    report = _report(runner)

    assert (report.run_status, report.scan_status) == (R.FAILED, S.FAILED)
    assert _run(queue_seed, report.run_id).error_code == RunErrorCode.ARTIFACT_REJECTED
    assert len(runtime.stopped) == 1
    assert clock.now <= 4
    assert runtime.containers == {}


def test_a_manifest_that_cannot_be_written_fails_the_run(
    make_runner: Callable[..., ContainerRunner],
    clock: FakeClock,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    tmp_path: Path,
) -> None:
    queue_seed.scan(world.operator_a, scannable)

    def occupy() -> None:
        [run_dir] = (tmp_path / "runs").iterdir()
        (run_dir / "manifest.json").write_bytes(b"{}")

    clock.at(1, occupy)
    report = _report(make_runner())

    assert _run(queue_seed, report.run_id).error_code == RunErrorCode.WORKSPACE_UNAVAILABLE


def test_engines_without_a_planner_are_rejected_before_recording_a_container(
    make_runner: Callable[..., ContainerRunner],
    runtime: FakeContainerRuntime,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    """目前只有 fake 有 plan：其他引擎的 run 不能拿到 fake 的映像與指令（審查發現）。"""
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

    report = make_runner().run_once(frozenset({ScanEngine.ZAP}))

    assert report is not None
    assert (report.run_status, report.scan_status) == (R.FAILED, S.FAILED)
    run = _run(queue_seed, report.run_id)
    assert (run.error_code, run.container_name, run.image_ref) == ("PLAN_REJECTED", None, None)
    assert runtime.created == []


def test_a_failed_stop_is_finished_by_the_forced_removal(
    make_runner: Callable[..., ContainerRunner],
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    queue_seed.scan(world.operator_a, scannable, budget=BudgetRequest(max_duration_seconds=3))
    runtime.failing.add("stop")

    report = _report(make_runner(script=FakeScript(hold_seconds=60)))

    assert (report.run_status, report.scan_status) == (R.TIMED_OUT, S.TIMED_OUT)
    assert runtime.containers == {}


def test_a_secret_that_cannot_be_deleted_does_not_fail_the_run(
    make_runner: Callable[..., ContainerRunner],
    workspace: Workspace,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """刪不掉的 secret 留給下次啟動時清除（記在 log），run 照常完成。"""
    queue_seed.scan(world.operator_a, scannable)

    def stuck(_run_id: UUID) -> None:
        raise WorkspaceError("無法刪除 secret（EBUSY）")

    monkeypatch.setattr(workspace, "discard_secrets", stuck)

    assert _report(make_runner()).run_status is R.COLLECTED


def test_a_lease_lost_before_collecting_leaves_the_run(
    make_runner: Callable[..., ContainerRunner],
    runtime: FakeContainerRuntime,
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    advance = queue.advance

    def expire_after_collecting(lease: Lease, to: R, **options: Any) -> Any:
        progress = advance(lease, to, **options)
        if to is R.COLLECTING:
            queue_seed.execute(
                "UPDATE scanner_runs SET lease_expires_at = now() - interval '1 second' "
                "WHERE id = :id",
                id=lease.run_id,
            )
        return progress

    monkeypatch.setattr(queue, "advance", expire_after_collecting)

    with pytest.raises(LeaseLostError):
        make_runner().run_once(FAKE)

    [row] = queue_seed.query("SELECT status FROM scanner_runs")
    assert row.status == "collecting"
    assert runtime.containers == {}


def test_the_lease_is_renewed_before_collecting(
    make_runner: Callable[..., ContainerRunner],
    workspace: Workspace,
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """收集可能要計算大量檔案的 hash：開始之前先延長 lease，不靠監看時最後一次的心跳。"""
    queue_seed.scan(world.operator_a, scannable)
    advance = queue.advance
    remaining: list[float] = []

    def nearly_expired(lease: Lease, to: R, **options: Any) -> Any:
        progress = advance(lease, to, **options)
        if to is R.COLLECTING:
            queue_seed.execute(
                "UPDATE scanner_runs SET lease_expires_at = now() + interval '2 seconds' "
                "WHERE id = :id",
                id=lease.run_id,
            )
        return progress

    collect = workspace.collect

    def measure(run_id: UUID) -> Any:
        [row] = queue_seed.query(
            "SELECT extract(epoch FROM lease_expires_at - clock_timestamp()) AS left "
            "FROM scanner_runs WHERE id = :id",
            id=run_id,
        )
        remaining.append(float(row.left))
        return collect(run_id)

    monkeypatch.setattr(queue, "advance", nearly_expired)
    monkeypatch.setattr(workspace, "collect", measure)

    assert _report(make_runner()).run_status is R.COLLECTED
    [left] = remaining
    assert left > 20
