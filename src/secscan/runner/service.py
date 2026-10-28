"""容器版的 runner（docs/DECISIONS.md §14.6）：認領 → prepare → 建立容器 → 監看 → 收集。

每一步都經過佇列的轉換與事件；容器一律以名稱 secscan-run-<run_id> 建立與刪除。
- prepare_launch 先在 DB 記下容器與映像，才呼叫 create（之後的對帳一定找得到它）。
- target 的 secret 在建立容器之前才解密（整個專案只有這裡呼叫 reveal），寫成 0400 的檔案、唯讀掛進
  容器；容器與 secret 在 finally 中刪除：任何結果、任何例外都一樣（審查後補上）。
- 監看時每秒查一次容器的狀態與 out/ 的用量，啟動後立刻、之後每 5 秒心跳一次：要求取消就停止容器
  → cancelled；超過時間上限 → timed_out；out/ 超過上限 → failed；lease 失效就停止容器並放手
  （無法 fencing）；runner 要停止 → interrupted。查不到容器的狀態時重試，連續失敗才放棄。
- 宣稱容器已停止的結果（取消、逾時、中斷…）都要確認容器已刪除；刪不掉就不轉換，留給 T13 的對帳。
- 容器結束之後才收集 out/（runner 不解析內容，只計算 hash）。
"""

import logging
import time
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from secscan.auth_profiles.domain.model import StoredSecret
from secscan.runner.domain.admission import ContainerSpec, PlanRejectedError, build_container
from secscan.runner.domain.policy import ENGINE_POLICIES, ContainerPolicy, EnginePolicy
from secscan.runner.domain.runtime import ContainerRuntime, ContainerState, RuntimeUnavailableError
from secscan.runner.workspace import ArtifactRejectedError, Workspace, WorkspaceError
from secscan.scanners.domain.fake import FAKE_IMAGE, FakeScript, plan_fake_run
from secscan.scanners.domain.plan import ExecutionPlan, ImageReference
from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.domain.model import Lease
from secscan.scans.queue import HEARTBEAT_INTERVAL, Launch, LeaseLostError, RunReport, ScanQueue
from secscan.security.secret_cipher import SecretCipher, SecretUnreadableError

logger = logging.getLogger(__name__)

# 停止容器時先送 SIGTERM，寬限之後 SIGKILL（容器以 Init 執行，訊號會傳到工具）。
STOP_GRACE_SECONDS = 5
POLL_SECONDS = 1.0
# 連續幾次查不到容器的狀態才放棄（socket-proxy 或 Docker 的暫時錯誤不放棄整個 run）。
MAX_STATE_FAILURES = 3
# 有 plan 的引擎與它的映像。M3 起加入 ZAP 時，在這裡與 _plan 一起加。
ENGINE_IMAGES: Mapping[Engine, ImageReference] = MappingProxyType({Engine.FAKE: FAKE_IMAGE})


class _Ending(StrEnum):
    EXITED = "exited"
    NOT_STARTED = "not_started"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    STOPPED = "stopped"
    REJECTED = "rejected"
    LOST = "lost"


# 容器可能還在執行的結果：要確認容器已刪除，才能宣稱已停止。
_NEEDS_REMOVAL = frozenset(
    {_Ending.CANCELLED, _Ending.TIMED_OUT, _Ending.STOPPED, _Ending.REJECTED, _Ending.LOST}
)


# 容器被 runner 停止的結果，以及 run 要轉到的狀態。
_STOPPED_ENDINGS: Mapping[_Ending, tuple[RunStatus, RunErrorCode | None]] = MappingProxyType(
    {
        _Ending.CANCELLED: (RunStatus.CANCELLED, None),
        _Ending.TIMED_OUT: (RunStatus.TIMED_OUT, RunErrorCode.TIME_LIMIT_EXCEEDED),
        _Ending.STOPPED: (RunStatus.INTERRUPTED, RunErrorCode.RUNNER_STOPPED),
        _Ending.REJECTED: (RunStatus.FAILED, RunErrorCode.ARTIFACT_REJECTED),
        _Ending.LOST: (RunStatus.INTERRUPTED, RunErrorCode.RUNTIME_UNAVAILABLE),
    }
)


@dataclass(frozen=True, slots=True)
class _Outcome:
    ending: _Ending
    state: ContainerState | None = None
    error_code: RunErrorCode | None = None


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

        lease 失效時拋 LeaseLostError；無法確認容器已停止時拋 RuntimeUnavailableError（run 留給
        T13 的容器對帳）。兩種情形，以及任何未預期的例外，都已盡力刪除容器與 secret。
        """
        if not engines:
            return None
        lease = self._queue.claim(self._owner, engines)
        if lease is None:
            return None
        image = ENGINE_IMAGES.get(lease.engine)
        if image is None:
            logger.warning("引擎 %s 沒有 plan：run %s", lease.engine.value, lease.run_id)
            return self._fail(lease, RunErrorCode.PLAN_REJECTED)
        launch = self._queue.prepare_launch(lease, image_ref=str(image))
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
            outcome = self._start(lease, launch.secret, plan, spec)
            if outcome is None:
                outcome = self._supervise(lease, spec.name, plan.limits.wall_clock_seconds)
        finally:
            removed = self._cleanup(lease, spec.name)
        if outcome.ending in _NEEDS_REMOVAL and not removed:
            raise RuntimeUnavailableError("無法確認容器已停止：run 留給對帳")
        return self._conclude(lease, outcome)

    def _start(
        self, lease: Lease, secret: StoredSecret | None, plan: ExecutionPlan, spec: ContainerSpec
    ) -> _Outcome | None:
        """寫入 secret 與輸入檔、建立並啟動容器；失敗時回傳原因（還沒有任何流量）。"""
        try:
            if secret is not None:
                self._workspace.write_secret(lease.run_id, self._reveal(secret))
            self._workspace.prepare(lease.run_id, plan.inputs)
        except _SecretUnavailableError:
            return _Outcome(_Ending.NOT_STARTED, error_code=RunErrorCode.SECRET_UNAVAILABLE)
        except WorkspaceError as exc:
            logger.error("工作目錄不可用：run %s，%s", lease.run_id, exc)
            return _Outcome(_Ending.NOT_STARTED, error_code=RunErrorCode.WORKSPACE_UNAVAILABLE)
        try:
            self._runtime.create(spec)
            self._runtime.start(spec.name)
        except RuntimeUnavailableError as exc:
            logger.warning("無法啟動容器：run %s，%s", lease.run_id, exc)
            return _Outcome(_Ending.NOT_STARTED, error_code=RunErrorCode.RUNTIME_UNAVAILABLE)
        return None

    def _reveal(self, secret: StoredSecret) -> str:
        """解密綁定版本的密文（整個專案只有這裡呼叫 reveal；docs/DECISIONS.md §12.2）。"""
        if self._cipher is None:
            raise _SecretUnavailableError
        try:
            return self._cipher.reveal(secret.token, context=secret.context)
        except SecretUnreadableError:
            raise _SecretUnavailableError from None

    def _supervise(self, lease: Lease, name: str, wall_clock_seconds: int) -> _Outcome:
        started = self._monotonic()
        # 啟動後立刻心跳一次：lease 從認領起算，建立與啟動容器可能花掉不少時間（審查發現）。
        last_beat = started - HEARTBEAT_INTERVAL.total_seconds()
        failures = 0
        while True:
            now = self._monotonic()
            if now - last_beat >= HEARTBEAT_INTERVAL.total_seconds():
                last_beat = now
                if self._beat(lease, name):
                    return _Outcome(_Ending.CANCELLED)
            try:
                outcome = self._step(lease, name, elapsed=now - started, limit=wall_clock_seconds)
            except RuntimeUnavailableError as exc:
                failures += 1
                logger.warning("查不到容器 %s 的狀態（第 %d 次）：%s", name, failures, exc)
                if failures >= MAX_STATE_FAILURES:
                    return _Outcome(_Ending.LOST)
                outcome = None
            else:
                failures = 0
            if outcome is not None:
                return outcome
            self._sleep(POLL_SECONDS)

    def _step(self, lease: Lease, name: str, *, elapsed: float, limit: int) -> _Outcome | None:
        """查一次容器的狀態與 out/ 的用量；需要結束時停止容器並回傳結果。"""
        state = self._runtime.state(name)
        if state is None or not state.running:
            return _Outcome(_Ending.EXITED, state)
        if self._stop_requested():
            return self._stopping(name, _Ending.STOPPED)
        if elapsed >= limit:
            return self._stopping(name, _Ending.TIMED_OUT)
        try:
            self._workspace.check_output(lease.run_id)
        except (ArtifactRejectedError, WorkspaceError) as exc:
            logger.warning("輸出超過上限：run %s，%s", lease.run_id, exc)
            return self._stopping(name, _Ending.REJECTED)
        return None

    def _stopping(self, name: str, ending: _Ending) -> _Outcome:
        self._stop(name)
        return _Outcome(ending)

    def _stop(self, name: str) -> None:
        """停止容器；失敗時由之後的強制刪除處理（刪不掉就不宣稱已停止）。"""
        try:
            self._runtime.stop(name, grace_seconds=STOP_GRACE_SECONDS)
        except RuntimeUnavailableError as exc:
            logger.warning("無法停止容器 %s（%s）：改由強制刪除處理", name, exc)

    def _beat(self, lease: Lease, name: str) -> bool:
        """延長 lease；回傳是否要求取消（是就先轉到 cancelling，再停止容器）。"""
        heartbeat = self._queue.heartbeat(lease)
        self._on_heartbeat()
        if not heartbeat.valid:
            self._stop(name)
            raise LeaseLostError("lease 已過期：已停止容器，交給對帳處理")
        if not heartbeat.cancel_requested:
            return False
        # T11／T13：在停止容器之前，先把 guard 的 policy 改成 blocked。
        self._queue.advance(lease, RunStatus.CANCELLING)
        self._stop(name)
        return True

    def _cleanup(self, lease: Lease, name: str) -> bool:
        """刪除容器與 secret；回傳容器是否確定已不存在（Docker 不可用時是 False）。"""
        try:
            self._runtime.remove(name)
        except RuntimeUnavailableError as exc:
            logger.error("無法刪除容器 %s（%s）：留給 T13 的對帳", name, exc)
            return False
        finally:
            try:
                self._workspace.discard_secret(lease.run_id)
            except WorkspaceError as exc:
                logger.error("無法刪除 run %s 的 secret（%s）：下次啟動時清除", lease.run_id, exc)
        return True

    def _conclude(self, lease: Lease, outcome: _Outcome) -> RunReport:
        if outcome.ending is _Ending.NOT_STARTED:
            return self._fail(lease, outcome.error_code or RunErrorCode.RUNTIME_UNAVAILABLE)
        if outcome.ending is _Ending.EXITED:
            return self._exited(lease, outcome.state)
        status, error_code = _STOPPED_ENDINGS[outcome.ending]
        return self._advance(lease, status, error_code)

    def _exited(self, lease: Lease, state: ContainerState | None) -> RunReport:
        if state is None:
            return self._fail(lease, RunErrorCode.RUNTIME_UNAVAILABLE)
        if state.oom_killed:
            return self._fail(lease, RunErrorCode.RESOURCE_LIMIT_EXCEEDED)
        if state.exit_code != 0:
            return self._fail(lease, RunErrorCode.ENGINE_FAILED)
        self._queue.advance(lease, RunStatus.COLLECTING)
        if not self._queue.heartbeat(lease).valid:
            raise LeaseLostError("lease 已過期：不收集，交給對帳處理")
        self._on_heartbeat()
        try:
            self._workspace.collect(lease.run_id)
        except ArtifactRejectedError as exc:
            logger.warning("輸出被拒絕：run %s，%s", lease.run_id, exc.issue.value)
            return self._fail(lease, RunErrorCode.ARTIFACT_REJECTED)
        except WorkspaceError as exc:
            logger.error("無法收集輸出：run %s，%s", lease.run_id, exc)
            return self._fail(lease, RunErrorCode.WORKSPACE_UNAVAILABLE)
        return self._advance(lease, RunStatus.COLLECTED)

    def _fail(self, lease: Lease, error_code: RunErrorCode) -> RunReport:
        return self._advance(lease, RunStatus.FAILED, error_code)

    def _advance(
        self, lease: Lease, to: RunStatus, error_code: RunErrorCode | None = None
    ) -> RunReport:
        return RunReport.of(lease, self._queue.advance(lease, to, error_code=error_code))
