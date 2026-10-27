"""容器版的 runner（docs/DECISIONS.md §14.6）：認領 → prepare → 建立容器 → 監看 → 收集。

每一步都經過佇列的轉換與事件；容器一律以名稱 secscan-run-<run_id> 建立與刪除。
- prepare_launch 先在 DB 記下容器與映像，才呼叫 create（之後的對帳一定找得到它）。
- target 的 secret 在建立容器之前才解密（整個專案只有這裡呼叫 reveal），寫成 0400 的檔案、唯讀掛進
  容器；容器刪除之後立刻刪除，不論結果。
- 監看時每秒查一次容器的狀態，每 5 秒以內心跳一次：要求取消就停止容器 → cancelled；超過時間
  上限 → timed_out；lease 失效就停止容器並放手（無法 fencing）；runner 要停止 → interrupted。
- 容器結束之後才收集 out/（runner 不解析內容，只計算 hash）。
"""

import logging
import time
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from enum import StrEnum

from secscan.auth_profiles.domain.model import StoredSecret
from secscan.runner.domain.admission import ContainerSpec, PlanRejectedError, build_container
from secscan.runner.domain.policy import ENGINE_POLICIES, ContainerPolicy, EnginePolicy
from secscan.runner.domain.runtime import ContainerRuntime, ContainerState, RuntimeUnavailableError
from secscan.runner.workspace import ArtifactRejectedError, Workspace, WorkspaceError
from secscan.scanners.domain.fake import FAKE_IMAGE, FakeScript, plan_fake_run
from secscan.scanners.domain.plan import ExecutionPlan
from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.domain.model import Lease
from secscan.scans.queue import HEARTBEAT_INTERVAL, Launch, LeaseLostError, RunReport, ScanQueue
from secscan.security.secret_cipher import SecretCipher, SecretUnreadableError

logger = logging.getLogger(__name__)

# 停止容器時先送 SIGTERM，寬限之後 SIGKILL（容器以 Init 執行，訊號會傳到工具）。
STOP_GRACE_SECONDS = 5
POLL_SECONDS = 1.0


class _Ending(StrEnum):
    EXITED = "exited"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    STOPPED = "stopped"


@dataclass(frozen=True, slots=True)
class _Outcome:
    ending: _Ending
    state: ContainerState | None = None


class _SecretUnavailableError(Exception):
    """沒有解密的金鑰，或密文解不開（不含任何秘密）。"""


class ContainerRunner:
    def __init__(
        self,
        queue: ScanQueue,
        runtime: ContainerRuntime,
        workspace: Workspace,
        *,
        owner: str,
        policy: ContainerPolicy,
        script: FakeScript,
        cipher: SecretCipher | None,
        engine_policies: Mapping[Engine, EnginePolicy] = ENGINE_POLICIES,
        stop_requested: Callable[[], bool] = lambda: False,
        on_heartbeat: Callable[[], None] = lambda: None,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._queue = queue
        self._runtime = runtime
        self._workspace = workspace
        self._owner = owner
        self._policy = policy
        self._script = script
        self._cipher = cipher
        self._engine_policies = engine_policies
        self._stop_requested = stop_requested
        self._on_heartbeat = on_heartbeat
        self._sleep = sleep
        self._monotonic = monotonic

    def run_once(self, engines: Collection[Engine]) -> RunReport | None:
        """處理一個排隊中的 run；沒有工作時回 None。

        lease 失效時拋 LeaseLostError；監看途中 Docker 不可用時拋 RuntimeUnavailableError（容器是否
        已停止無法確認，run 留給 T13 的容器對帳）。兩種情形都已盡力刪除容器與 secret。
        """
        if not engines:
            return None
        lease = self._queue.claim(self._owner, engines)
        if lease is None:
            return None
        launch = self._queue.prepare_launch(lease, image_ref=str(FAKE_IMAGE))
        if launch.progress.run_status is RunStatus.CANCELLING:
            return self._advance(lease, RunStatus.CANCELLED)
        if launch.progress.run_status is not RunStatus.RUNNING:
            return RunReport.of(lease, launch.progress)
        try:
            plan = self._plan(lease, launch)
            spec = build_container(plan, policy=self._policy, engines=self._engine_policies)
        except PlanRejectedError as exc:
            logger.warning("ExecutionPlan 被拒絕：run %s，%s", lease.run_id, exc.reason.value)
            return self._fail(lease, RunErrorCode.PLAN_REJECTED)
        return self._execute(lease, launch, plan, spec)

    def _plan(self, lease: Lease, launch: Launch) -> ExecutionPlan:
        return plan_fake_run(
            run_id=lease.run_id,
            scan_id=lease.scan_id,
            script=self._script,
            target_auth=launch.secret is not None,
            max_duration_seconds=launch.max_duration_seconds,
        )

    def _execute(
        self, lease: Lease, launch: Launch, plan: ExecutionPlan, spec: ContainerSpec
    ) -> RunReport:
        try:
            self._start(lease, launch.secret, plan, spec)
        except _SecretUnavailableError:
            self._cleanup(lease, spec.name)
            return self._fail(lease, RunErrorCode.SECRET_UNAVAILABLE)
        except (RuntimeUnavailableError, WorkspaceError) as exc:
            logger.warning("無法啟動容器：run %s，%s", lease.run_id, exc)
            self._cleanup(lease, spec.name)
            return self._fail(lease, RunErrorCode.RUNTIME_UNAVAILABLE)
        try:
            outcome = self._supervise(lease, spec.name, plan.limits.wall_clock_seconds)
        finally:
            self._cleanup(lease, spec.name)
        return self._conclude(lease, outcome)

    def _start(
        self, lease: Lease, secret: StoredSecret | None, plan: ExecutionPlan, spec: ContainerSpec
    ) -> None:
        if secret is not None:
            self._workspace.write_secret(lease.run_id, self._reveal(secret))
        self._workspace.prepare(lease.run_id, plan.inputs)
        self._runtime.create(spec)
        self._runtime.start(spec.name)

    def _reveal(self, secret: StoredSecret) -> str:
        """解密綁定版本的密文（整個專案只有這裡呼叫 reveal；docs/DECISIONS.md §12.2）。"""
        if self._cipher is None:
            raise _SecretUnavailableError
        try:
            return self._cipher.reveal(secret.token, context=secret.context)
        except SecretUnreadableError:
            raise _SecretUnavailableError from None

    def _supervise(self, lease: Lease, name: str, wall_clock_seconds: int) -> _Outcome:
        started = last_beat = self._monotonic()
        while True:
            state = self._runtime.state(name)
            if state is None or not state.running:
                return _Outcome(_Ending.EXITED, state)
            now = self._monotonic()
            if self._stop_requested():
                self._runtime.stop(name, grace_seconds=STOP_GRACE_SECONDS)
                return _Outcome(_Ending.STOPPED)
            if now - started >= wall_clock_seconds:
                self._runtime.stop(name, grace_seconds=STOP_GRACE_SECONDS)
                return _Outcome(_Ending.TIMED_OUT)
            if now - last_beat >= HEARTBEAT_INTERVAL.total_seconds():
                last_beat = now
                if self._beat(lease, name):
                    return _Outcome(_Ending.CANCELLED)
            self._sleep(POLL_SECONDS)

    def _beat(self, lease: Lease, name: str) -> bool:
        """延長 lease；回傳是否要求取消（是就先轉到 cancelling，再停止容器）。"""
        heartbeat = self._queue.heartbeat(lease)
        self._on_heartbeat()
        if not heartbeat.valid:
            self._runtime.stop(name, grace_seconds=STOP_GRACE_SECONDS)
            raise LeaseLostError("lease 已過期：已停止容器，交給對帳處理")
        if not heartbeat.cancel_requested:
            return False
        # T11／T13：在停止容器之前，先把 guard 的 policy 改成 blocked。
        self._queue.advance(lease, RunStatus.CANCELLING)
        self._runtime.stop(name, grace_seconds=STOP_GRACE_SECONDS)
        return True

    def _cleanup(self, lease: Lease, name: str) -> None:
        """刪除容器與 secret；Docker 不可用時仍刪除 secret，並記下容器可能還在。"""
        try:
            self._runtime.remove(name)
        except RuntimeUnavailableError as exc:
            logger.error("無法刪除容器 %s（%s）：留給 T13 的對帳", name, exc)
        finally:
            self._workspace.discard_secret(lease.run_id)

    def _conclude(self, lease: Lease, outcome: _Outcome) -> RunReport:
        if outcome.ending is _Ending.CANCELLED:
            return self._advance(lease, RunStatus.CANCELLED)
        if outcome.ending is _Ending.TIMED_OUT:
            return self._advance(lease, RunStatus.TIMED_OUT, RunErrorCode.TIME_LIMIT_EXCEEDED)
        if outcome.ending is _Ending.STOPPED:
            return self._advance(lease, RunStatus.INTERRUPTED, RunErrorCode.RUNNER_STOPPED)
        state = outcome.state
        if state is None:
            return self._fail(lease, RunErrorCode.RUNTIME_UNAVAILABLE)
        if state.oom_killed:
            return self._fail(lease, RunErrorCode.RESOURCE_LIMIT_EXCEEDED)
        if state.exit_code != 0:
            return self._fail(lease, RunErrorCode.ENGINE_FAILED)
        self._queue.advance(lease, RunStatus.COLLECTING)
        try:
            self._workspace.collect(lease.run_id)
        except ArtifactRejectedError as exc:
            logger.warning("輸出被拒絕：run %s，%s", lease.run_id, exc.issue.value)
            return self._fail(lease, RunErrorCode.ARTIFACT_REJECTED)
        return self._advance(lease, RunStatus.COLLECTED)

    def _fail(self, lease: Lease, error_code: RunErrorCode) -> RunReport:
        return self._advance(lease, RunStatus.FAILED, error_code)

    def _advance(
        self, lease: Lease, to: RunStatus, error_code: RunErrorCode | None = None
    ) -> RunReport:
        return RunReport.of(lease, self._queue.advance(lease, to, error_code=error_code))
