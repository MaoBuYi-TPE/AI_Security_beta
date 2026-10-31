"""runner 的整合測試共用的 spy：把容器的操作、policy 的寫入與 run 的轉換記在同一個有序的 log。

- SpyRuntime：記憶體中的容器 runtime（tests/runner_fakes.py），記下 create、start、stop、remove。
- SpyChannel：真的 policy 目錄（GuardDouble 的 tmp），記下每次寫入的狀態；可以讓寫入、續約或刪除
  失敗。續約記成 renew，其他寫入記成 policy:<state>。
- logged_queue：真的 DB 佇列，advance 時記下 run:<status>，對帳結算時記下 run:settled。
- abandon：runner 被 SIGKILL 時留下的狀態（不執行任何清理）：DB 是 running、容器執行中、policy 是
  active、secret 還在。
"""

import time
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.guard.domain.policy import GuardPolicyVersion, Policy, PolicyState
from secscan.runner.domain.admission import PROXY_FILE, ContainerSpec, build_container
from secscan.runner.domain.policy import ContainerPolicy
from secscan.runner.egress import RunEgress
from secscan.runner.guard import GuardChannel, GuardUnavailableError
from secscan.runner.workspace import Workspace
from secscan.scanners.domain.fake import FAKE_IMAGE, FakeScript, plan_fake_run
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.domain.model import Lease
from secscan.scans.queue import Progress, ScanQueue
from secscan.targets.domain import LabNetwork
from tests.guard_support import ENDPOINT, GuardDouble
from tests.runner_fakes import FakeContainerRuntime

POLICY = ContainerPolicy(
    scan_network="secscan_scan_net",
    runs_volume="secscan_runs",
    secrets_volume="secscan_run_secrets",
)


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


def logged_queue(
    engine: Engine,
    log: list[str],
    *,
    lab: LabNetwork,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> ScanQueue:
    queue = ScanQueue(sessionmaker(engine, expire_on_commit=False), lab=lab, clock=clock)
    advance = queue.advance

    def logged(lease: Lease, to: RunStatus, *, error_code: RunErrorCode | None = None) -> Progress:
        log.append(f"run:{to.value}")
        return advance(lease, to, error_code=error_code)

    queue.advance = logged  # type: ignore[method-assign]
    settle = queue.settle_container

    def logged_settle(run_id: UUID) -> bool:
        settled = settle(run_id)
        if settled:
            log.append("run:settled")
        return settled

    queue.settle_container = logged_settle  # type: ignore[method-assign]
    return queue


def without_renewals(log: list[str]) -> list[str]:
    return [entry for entry in log if entry != "renew"]


def orphan_spec(lease: Lease) -> ContainerSpec:
    """孤兒容器：fake 的映像，停留 300 秒（對帳之前不會自己結束）。"""
    plan = plan_fake_run(
        run_id=lease.run_id,
        scan_id=lease.scan_id,
        script=FakeScript(hold_seconds=300),
        target_auth=False,
        max_duration_seconds=300,
    )
    return build_container(plan, policy=POLICY)


def abandon(
    queue: ScanQueue,
    runtime: FakeContainerRuntime,
    workspace: Workspace,
    channel: GuardChannel,
    lease: Lease,
) -> None:
    """認領之後的 run 開始執行、然後 runner 被 SIGKILL：不執行任何清理（lease 由測試讓它過期）。"""
    launch = queue.prepare_launch(lease, image_ref=str(FAKE_IMAGE))
    assert launch.egress is not None
    egress = RunEgress.open(
        channel,
        policy_version=GuardPolicyVersion.STRICT,
        lease=lease,
        egress=launch.egress,
        endpoint=ENDPOINT,
        now=time.time(),
        wall_clock_seconds=300,
        renew_until=time.time() + 30,
    )
    workspace.write_secrets(lease.run_id, {PROXY_FILE: egress.proxy_url})
    egress.activate()
    spec = orphan_spec(lease)
    runtime.create(spec)
    runtime.start(spec.name)
