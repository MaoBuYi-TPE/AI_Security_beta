"""runner 的整合測試共用的 spy：把容器的操作、policy 的寫入與 run 的轉換記在同一個有序的 log。

- SpyRuntime：記憶體中的容器 runtime（tests/runner_fakes.py），記下 create、start、stop、remove。
- SpyChannel：真的 policy 目錄（GuardDouble 的 tmp），記下每次寫入的狀態；可以讓寫入、續約或刪除
  失敗。續約記成 renew，其他寫入記成 policy:<state>。
- logged_queue：真的 DB 佇列，advance 時記下 run:<status>。
"""

from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.guard.domain.policy import Policy, PolicyState
from secscan.runner.domain.admission import ContainerSpec
from secscan.runner.domain.policy import ContainerPolicy
from secscan.runner.guard import GuardChannel, GuardUnavailableError
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
    return queue


def without_renewals(log: list[str]) -> list[str]:
    return [entry for entry in log if entry != "renew"]
