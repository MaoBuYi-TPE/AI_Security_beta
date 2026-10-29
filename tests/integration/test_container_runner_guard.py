"""runner 與 egress guard 的整合（docs/DECISIONS.md §15.7）：真的 DB 佇列、記憶體中的容器 runtime、
tmp 中的 policy 與 status 目錄。

一個 spy 把容器的操作、policy 的寫入與 run 的轉換記在同一個有序的 log，確認：
- 建立容器之前 policy 已經寫好（內容正確）；每次心跳都續約，不超過 lease。
- 每條停止的路徑都先封鎖再 stop；取消是封鎖 → cancelling → stop。
- 先刪容器、再刪 secret，確認容器已刪除才刪 policy；刪不掉就保留 blocked。
- guard 不可用時不建立容器（failed）；執行中 guard 中斷、重啟或續約失敗 → interrupted。
每個測試用自己的資料庫（queue_database）。
"""

import stat
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.guard.domain.credentials import token_digest
from secscan.guard.domain.policy import Policy, PolicyState
from secscan.runner.domain.admission import PROXY_FILE, ContainerSpec
from secscan.runner.domain.policy import ContainerPolicy
from secscan.runner.domain.runtime import RuntimeUnavailableError
from secscan.runner.guard import GuardChannel, GuardUnavailableError
from secscan.runner.service import ContainerRunner
from secscan.runner.workspace import Workspace
from secscan.scanners.domain.fake import FAKE_MAX_WALL_CLOCK_SECONDS, FakeScript
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus, ScanStatus
from secscan.scans.domain.model import Lease
from secscan.scans.domain.request import BudgetRequest
from secscan.scans.queue import LEASE_DURATION, LeaseLostError, Progress, RunReport, ScanQueue
from tests.guard_support import ENDPOINT, GuardDouble
from tests.integration.api_support import LAB, Scannable, Seeder, World
from tests.runner_fakes import FakeClock, FakeContainerRuntime
from tests.secret_support import shared_cipher

pytestmark = pytest.mark.integration

OWNER = "runner-guard-1"
FAKE = frozenset({ScanEngine.FAKE})
POLICY = ContainerPolicy(
    scan_network="secscan_scan_net",
    runs_volume="secscan_runs",
    secrets_volume="secscan_run_secrets",
)
R = RunStatus
S = ScanStatus


class SpyRuntime(FakeContainerRuntime):
    log: list[str]

    def create(self, spec: ContainerSpec) -> None:
        self.log.append("create")
        super().create(spec)

    def start(self, name: str) -> None:
        self.log.append("start")
        super().start(name)

    def stop(self, name: str, *, grace_seconds: int) -> None:
        self.log.append("stop")
        super().stop(name, grace_seconds=grace_seconds)

    def remove(self, name: str) -> None:
        self.log.append("remove")
        super().remove(name)


class SpyChannel(GuardChannel):
    def __init__(self, double: GuardDouble, log: list[str]) -> None:
        super().__init__(
            double.policies,
            double.status_dir,
            telemetry_dir=double.telemetry,
            listen=ENDPOINT.listen,
        )
        self.log = log
        self.fail_states: set[PolicyState] = set()
        self.fail_renewal = False
        self.fail_remove = False
        self.written: list[Policy] = []

    def write(self, policy: Policy) -> None:
        renewal = bool(self.written) and policy.state is PolicyState.ACTIVE
        if policy.state in self.fail_states or (renewal and self.fail_renewal):
            raise GuardUnavailableError("無法寫入 guard 的 policy（EACCES）")
        super().write(policy)
        self.written.append(policy)
        self.log.append("renew" if renewal else f"policy:{policy.state.value}")

    def remove(self, run_id: UUID) -> None:
        if self.fail_remove:
            raise GuardUnavailableError("無法刪除 guard 的 policy（EBUSY）")
        super().remove(run_id)
        self.log.append("policy:removed")


@pytest.fixture
def log() -> list[str]:
    return []


@pytest.fixture
def queue(queue_engine: Engine, log: list[str]) -> ScanQueue:
    queue = ScanQueue(
        sessionmaker(queue_engine, expire_on_commit=False), lab=LAB, clock=lambda: datetime.now(UTC)
    )
    advance = queue.advance

    def logged(lease: Lease, to: RunStatus, *, error_code: RunErrorCode | None = None) -> Progress:
        log.append(f"run:{to.value}")
        return advance(lease, to, error_code=error_code)

    queue.advance = logged  # type: ignore[method-assign]
    return queue


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


def _error(seed: Seeder, run_id: UUID) -> str | None:
    [row] = seed.query("SELECT error_code FROM scanner_runs WHERE id = :id", id=run_id)
    error: str | None = row.error_code
    return error


def _without_renewals(log: list[str]) -> list[str]:
    return [entry for entry in log if entry != "renew"]


# --- 啟動 -------------------------------------------------------------------------------------


def test_the_policy_is_in_place_before_the_container_exists(
    make_runner: Callable[..., ContainerRunner],
    log: list[str],
    channel: SpyChannel,
    clock: FakeClock,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    tmp_path: Path,
) -> None:
    scan = queue_seed.scan(world.operator_a, scannable)
    started = time.time()
    seen: dict[str, Any] = {}

    def look() -> None:
        [proxy] = (tmp_path / "secrets").glob(f"*/{PROXY_FILE}")
        seen["proxy"] = proxy.read_text(encoding="utf-8")
        seen["mode"] = stat.S_IMODE(proxy.stat().st_mode)

    clock.at(1, look)
    report = _report(make_runner())

    assert _without_renewals(log)[:3] == ["policy:active", "create", "start"]
    first = channel.written[0]
    assert first.run_id == report.run_id
    assert first.scan_id == scan.id
    assert first.scope.origins == (scannable.target.origin,)
    assert first.scope.ips == scannable.grant.scope.ips
    assert first.scope.paths == scannable.grant.scope.paths
    assert first.scope.methods == scannable.grant.scope.methods
    wall_clock = min(scan.budget.max_duration_seconds, FAKE_MAX_WALL_CLOCK_SECONDS)
    assert started - 1 <= first.not_after - wall_clock <= time.time()
    assert first.not_after <= scannable.grant.window.valid_until.timestamp()
    assert first.renew_until <= time.time() + LEASE_DURATION.total_seconds()
    token = seen["proxy"].removeprefix("http://").split("@")[0].split(":", 1)[1]
    assert seen["proxy"] == f"http://{report.run_id}:{token}@{ENDPOINT.listen}"
    assert token_digest(token) == first.token_sha256
    assert seen["mode"] == 0o400
    assert token not in str(channel.written)


def test_heartbeats_renew_the_policy_within_the_lease(
    make_runner: Callable[..., ContainerRunner],
    log: list[str],
    channel: SpyChannel,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    queue_seed.scan(world.operator_a, scannable)

    report = _report(make_runner())

    assert report.run_status is R.COLLECTED
    renewals = [policy for policy in channel.written if policy.state is PolicyState.ACTIVE][1:]
    assert len(renewals) == log.count("renew") >= 3  # 啟動後立刻一次，之後每 5 秒
    assert all(policy.renew_until <= time.time() + 30 for policy in renewals)
    assert [policy.not_after for policy in renewals] == [channel.written[0].not_after] * len(
        renewals
    )


def test_after_a_normal_run_the_policy_is_blocked_then_removed(
    make_runner: Callable[..., ContainerRunner],
    log: list[str],
    guard: GuardDouble,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    tmp_path: Path,
) -> None:
    queue_seed.scan(world.operator_a, scannable)

    _report(make_runner(script=FakeScript(hold_seconds=1)))

    assert _without_renewals(log)[-5:] == [
        "policy:blocked",
        "remove",
        "policy:removed",
        "run:collecting",
        "run:collected",
    ]
    assert guard.policy_files() == []
    assert list((tmp_path / "secrets").iterdir()) == []


# --- 停止的順序 -------------------------------------------------------------------------------


def test_a_cancel_blocks_the_guard_before_anything_else(
    make_runner: Callable[..., ContainerRunner],
    log: list[str],
    clock: FakeClock,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    scan = queue_seed.scan(world.operator_a, scannable)
    clock.at(
        6,
        lambda: queue_seed.execute(
            "UPDATE scans SET cancel_requested_at = now() WHERE id = :id", id=scan.id
        ),
    )

    report = _report(make_runner())

    assert report.run_status is R.CANCELLED
    assert _without_renewals(log)[3:] == [
        "policy:blocked",
        "run:cancelling",
        "stop",
        "remove",
        "policy:removed",
        "run:cancelled",
    ]


@pytest.mark.parametrize("ending", ["timeout", "runner_stop"])
def test_every_stop_blocks_first(
    make_runner: Callable[..., ContainerRunner],
    log: list[str],
    clock: FakeClock,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    ending: str,
) -> None:
    if ending == "timeout":
        queue_seed.scan(world.operator_a, scannable, budget=BudgetRequest(max_duration_seconds=8))
        runner = make_runner(script=FakeScript(hold_seconds=300))
    else:
        queue_seed.scan(world.operator_a, scannable)
        runner = make_runner(stop_requested=lambda: clock.now >= 3)

    report = _report(runner)

    stopping = _without_renewals(log)
    index = stopping.index("stop")
    assert stopping[index - 1] == "policy:blocked"
    assert stopping[index + 1 : index + 3] == ["remove", "policy:removed"]
    assert report.run_status in {R.TIMED_OUT, R.INTERRUPTED}


def test_a_lost_lease_blocks_and_keeps_the_policy_blocked_while_the_container_stays(
    make_runner: Callable[..., ContainerRunner],
    runtime: SpyRuntime,
    guard: GuardDouble,
    log: list[str],
    clock: FakeClock,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    """lease 失效、Docker 也刪不掉容器：policy 保持 blocked（T13 的對帳之前，出站都被擋下）。"""
    queue_seed.scan(world.operator_a, scannable)
    clock.at(
        6,
        lambda: queue_seed.execute(
            "UPDATE scanner_runs SET lease_expires_at = now() - interval '1 second'"
        ),
    )
    clock.at(6, lambda: runtime.failing.add("remove"))

    with pytest.raises(LeaseLostError):
        make_runner().run_once(FAKE)

    stopping = _without_renewals(log)
    assert stopping[stopping.index("stop") - 1] == "policy:blocked"
    [name] = guard.policy_files()
    policy = guard.policy(UUID(name.removesuffix(".json")))
    assert policy is not None
    assert policy.state is PolicyState.BLOCKED


def test_a_failed_block_still_stops_the_container(
    make_runner: Callable[..., ContainerRunner],
    channel: SpyChannel,
    runtime: SpyRuntime,
    clock: FakeClock,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    scan = queue_seed.scan(world.operator_a, scannable)
    channel.fail_states.add(PolicyState.BLOCKED)
    clock.at(
        6,
        lambda: queue_seed.execute(
            "UPDATE scans SET cancel_requested_at = now() WHERE id = :id", id=scan.id
        ),
    )

    report = _report(make_runner())

    assert report.run_status is R.CANCELLED
    assert runtime.stopped
    assert runtime.containers == {}


def test_a_policy_that_cannot_be_removed_is_left_for_the_next_start(
    make_runner: Callable[..., ContainerRunner],
    channel: SpyChannel,
    guard: GuardDouble,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    channel.fail_remove = True

    report = _report(make_runner(script=FakeScript(hold_seconds=1)))

    assert report.run_status is R.COLLECTED
    leftover = guard.policy(report.run_id)
    assert leftover is not None
    assert leftover.state is PolicyState.BLOCKED


# --- guard 不可用 -----------------------------------------------------------------------------


@pytest.mark.parametrize("change", ["stop", "vanish", "stale"])
def test_an_unavailable_guard_starts_nothing(
    make_runner: Callable[..., ContainerRunner],
    runtime: SpyRuntime,
    guard: GuardDouble,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    tmp_path: Path,
    change: str,
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    if change == "stop":
        guard.stop()
    elif change == "vanish":
        guard.vanish()
    else:
        guard.write_status(guard.status(updated_at=int(time.time()) - 3600))

    report = _report(make_runner())

    assert (report.run_status, report.scan_status) == (R.FAILED, S.FAILED)
    assert _error(queue_seed, report.run_id) == RunErrorCode.GUARD_UNAVAILABLE
    assert runtime.created == []
    assert guard.policy_files() == []
    assert list((tmp_path / "secrets").iterdir()) == []


def test_a_policy_that_cannot_be_written_starts_nothing(
    make_runner: Callable[..., ContainerRunner],
    runtime: SpyRuntime,
    channel: SpyChannel,
    guard: GuardDouble,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    tmp_path: Path,
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    channel.fail_states.add(PolicyState.ACTIVE)

    report = _report(make_runner())

    assert report.run_status is R.FAILED
    assert _error(queue_seed, report.run_id) == RunErrorCode.GUARD_UNAVAILABLE
    assert runtime.created == []
    assert list((tmp_path / "secrets").iterdir()) == []


@pytest.mark.parametrize("change", ["stop", "restart", "stale", "renewal_fails"])
def test_losing_the_guard_mid_run_interrupts_the_run(
    make_runner: Callable[..., ContainerRunner],
    runtime: SpyRuntime,
    channel: SpyChannel,
    guard: GuardDouble,
    log: list[str],
    clock: FakeClock,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    tmp_path: Path,
    change: str,
) -> None:
    """guard 中斷、重啟（可能漏掉請求）或續約失敗：停止容器 → interrupted，不當成零告警。"""
    queue_seed.scan(world.operator_a, scannable)
    actions: dict[str, Callable[[], None]] = {
        "stop": guard.stop,
        "restart": guard.restart,
        "stale": lambda: guard.write_status(guard.status(updated_at=int(time.time()) - 3600)),
        "renewal_fails": lambda: setattr(channel, "fail_renewal", True),
    }
    clock.at(6, actions[change])

    report = _report(make_runner())

    assert (report.run_status, report.scan_status) == (R.INTERRUPTED, S.INTERRUPTED)
    assert _error(queue_seed, report.run_id) == RunErrorCode.GUARD_UNAVAILABLE
    stopping = _without_renewals(log)
    assert stopping[stopping.index("stop") - 1] == "policy:blocked"
    assert runtime.containers == {}
    assert guard.policy_files() == []
    assert list((tmp_path / "secrets").iterdir()) == []


def test_a_cancel_seen_by_the_first_heartbeat_starts_nothing(
    make_runner: Callable[..., ContainerRunner],
    runtime: SpyRuntime,
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """prepare 之後、建立容器之前才要求取消：不建立容器。"""
    scan = queue_seed.scan(world.operator_a, scannable)
    prepare = queue.prepare_launch

    def then_cancel(lease: Lease, *, image_ref: str) -> Any:
        launch = prepare(lease, image_ref=image_ref)
        queue_seed.execute(
            "UPDATE scans SET cancel_requested_at = now() WHERE id = :id", id=scan.id
        )
        return launch

    monkeypatch.setattr(queue, "prepare_launch", then_cancel)

    report = _report(make_runner())

    assert report.run_status is R.CANCELLED
    assert runtime.created == []


def test_a_lease_lost_before_the_start_starts_nothing(
    make_runner: Callable[..., ContainerRunner],
    runtime: SpyRuntime,
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    prepare = queue.prepare_launch

    def then_expire(lease: Lease, *, image_ref: str) -> Any:
        launch = prepare(lease, image_ref=image_ref)
        queue_seed.execute("UPDATE scanner_runs SET lease_expires_at = now() - interval '1 second'")
        return launch

    monkeypatch.setattr(queue, "prepare_launch", then_expire)

    with pytest.raises(LeaseLostError):
        make_runner().run_once(FAKE)

    assert runtime.created == []
    assert list((tmp_path / "secrets").iterdir()) == []


def test_docker_lost_after_the_guard_was_blocked_keeps_it_blocked(
    make_runner: Callable[..., ContainerRunner],
    runtime: SpyRuntime,
    guard: GuardDouble,
    clock: FakeClock,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    clock.at(2, lambda: runtime.failing.update({"state", "remove"}))

    with pytest.raises(RuntimeUnavailableError):
        make_runner().run_once(FAKE)

    [name] = guard.policy_files()
    policy = guard.policy(UUID(name.removesuffix(".json")))
    assert policy is not None
    assert policy.state is PolicyState.BLOCKED


# --- 共享預算與用量（docs/DECISIONS.md §16.4）-----------------------------------------------


def _usage(seed: Seeder, run_id: UUID) -> tuple[Any, ...]:
    [row] = seed.query(
        "SELECT requests_allotted, requests_sent, requests_denied, traffic_seconds "
        "FROM scanner_runs WHERE id = :id",
        id=run_id,
    )
    return tuple(row)


def test_an_exhausted_budget_blocks_then_stops_the_container(
    make_runner: Callable[..., ContainerRunner],
    channel: SpyChannel,
    guard: GuardDouble,
    log: list[str],
    clock: FakeClock,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    scan = queue_seed.scan(world.operator_a, scannable)
    allotted = scan.budget.max_requests

    def exhaust() -> None:
        policy = channel.written[0]
        guard.write_summary(policy.run_id, policy.scan_id, forwarded=allotted, exhausted=True)

    clock.at(2, exhaust)
    report = _report(make_runner(script=FakeScript(hold_seconds=300)))

    assert report.run_status is R.TIMED_OUT
    assert _error(queue_seed, report.run_id) == RunErrorCode.BUDGET_EXHAUSTED
    stopping = _without_renewals(log)
    assert stopping[stopping.index("stop") - 1] == "policy:blocked"
    sent, traffic = _usage(queue_seed, report.run_id)[1], _usage(queue_seed, report.run_id)[3]
    assert sent == allotted
    assert 5 <= traffic < 30  # 下一次心跳（5 秒）就停止，不等到 300 秒


def test_usage_is_written_back_from_the_guard_summary(
    make_runner: Callable[..., ContainerRunner],
    channel: SpyChannel,
    guard: GuardDouble,
    clock: FakeClock,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    scan = queue_seed.scan(world.operator_a, scannable)

    def record() -> None:
        policy = channel.written[0]
        guard.write_summary(policy.run_id, policy.scan_id, forwarded=3, denied={"PATH_EXCLUDED": 2})

    clock.at(4, record)
    report = _report(make_runner())

    assert report.run_status is R.COLLECTED
    allotted, sent, denied, traffic = _usage(queue_seed, report.run_id)
    assert (allotted, sent, denied) == (scan.budget.max_requests, 3, 2)
    assert 12 <= traffic <= 20  # 腳本執行 12 秒


def test_a_run_without_a_summary_sent_nothing(
    make_runner: Callable[..., ContainerRunner],
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    """guard 每轉送一個請求都先寫 summary：同一個 guard（boot_id 相同）沒有 summary 就是 0。"""
    queue_seed.scan(world.operator_a, scannable)

    report = _report(make_runner())

    assert _usage(queue_seed, report.run_id)[1:3] == (0, 0)


@pytest.mark.parametrize("change", ["restart", "corrupt"])
def test_unknown_usage_is_left_for_the_conservative_count(
    make_runner: Callable[..., ContainerRunner],
    channel: SpyChannel,
    guard: GuardDouble,
    clock: FakeClock,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    change: str,
) -> None:
    """guard 重啟過（telemetry 可能不完整）或 summary 讀不出來：轉送數留空，之後的 run 以分到的
    數量扣除（不以 0 冒充）。"""
    queue_seed.scan(world.operator_a, scannable)

    def corrupt() -> None:
        policy = channel.written[0]
        (guard.telemetry / f"{policy.run_id}.summary.json").write_bytes(b"{")

    clock.at(6, guard.restart if change == "restart" else corrupt)
    report = _report(make_runner())

    assert _usage(queue_seed, report.run_id)[1:3] == (None, None)


def test_runs_that_never_started_used_nothing(
    make_runner: Callable[..., ContainerRunner],
    guard: GuardDouble,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    guard.stop()

    report = _report(make_runner())

    assert report.run_status is R.FAILED
    assert _usage(queue_seed, report.run_id)[1:] == (0, 0, 0)


def test_usage_of_a_container_that_may_still_run_is_unknown(
    make_runner: Callable[..., ContainerRunner],
    runtime: SpyRuntime,
    channel: SpyChannel,
    guard: GuardDouble,
    clock: FakeClock,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    """刪不掉容器：它之後可能還在送（審查發現），當下的 summary 不是最終值，留空。"""
    queue_seed.scan(world.operator_a, scannable)

    def record_then_lose_docker() -> None:
        policy = channel.written[0]
        guard.write_summary(policy.run_id, policy.scan_id, forwarded=1)
        runtime.failing.update({"state", "remove"})

    clock.at(2, record_then_lose_docker)

    with pytest.raises(RuntimeUnavailableError):
        make_runner().run_once(FAKE)

    run_id = channel.written[0].run_id
    assert _usage(queue_seed, run_id)[1:3] == (None, None)


def test_a_summary_from_another_guard_boot_is_not_trusted(
    make_runner: Callable[..., ContainerRunner],
    channel: SpyChannel,
    guard: GuardDouble,
    clock: FakeClock,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    """guard 在 run 中重啟、telemetry 沒有保留：新的 guard 從 0 開始計（審查發現），留空。"""
    queue_seed.scan(world.operator_a, scannable)

    def other_boot() -> None:
        policy = channel.written[0]
        guard.write_summary(policy.run_id, policy.scan_id, forwarded=1, boot_id=uuid4())

    clock.at(4, other_boot)
    report = _report(make_runner())

    assert _usage(queue_seed, report.run_id)[1:3] == (None, None)
