"""容器版的 runner（docs/DECISIONS.md §14.6）：認領 → prepare → 建立容器 → 監看 → 收集。

每一步都經過佇列的轉換與事件；容器一律以名稱 secscan-run-<run_id> 建立與刪除。
- prepare_launch 先在 DB 記下容器與映像，才呼叫 create（之後的對帳一定找得到它）。
- target 的 secret 在建立容器之前才解密（整個專案只有這裡呼叫 reveal），寫成 0400 的檔案、唯讀掛進
  容器；容器與 secret 在 finally 中刪除：任何結果、任何例外都一樣（審查後補上）。
- egress guard（docs/DECISIONS.md §15.7）：guard 不可用就不建立容器；建立之前寫好 policy、發給容器
  proxy-url；每次 DB 心跳成功之後續約。每條停止的路徑都先封鎖 guard；容器確認刪除之後才刪 policy。
  執行中 guard 中斷、重啟或續約失敗 → interrupted。
- 建立容器之前再心跳一次（§17.2）：lease 已失效就不建立（凍結的 owner 在對帳之後醒來）。
- 監看時每秒查一次容器的狀態與 out/ 的用量，啟動後立刻、之後每 5 秒心跳一次：要求取消就停止容器
  → cancelled；授權撤回（grant、target、建立者的 key，§17.5）→ failed；超過時間上限 → timed_out；
  out/ 超過上限 → failed；lease 失效就停止容器並放手（無法 fencing）；runner 要停止 → interrupted。
  查不到容器的狀態時重試，連續失敗才放棄。
- 宣稱容器已停止的結果（取消、逾時、中斷…）都要確認容器已刪除；刪不掉就不轉換，留給容器的對帳
  （runner/reconciler.py）。確認刪除時和用量一起記下（container_removed_at）。
- 容器結束之後才收集 out/（runner 不解析內容，只計算 hash）。
"""

import logging
import math
import time
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from uuid import UUID

from secscan.auth_profiles.domain.credentials import (
    SecretValue,
    header_line,
    masking_values,
)
from secscan.auth_profiles.domain.model import StoredSecret
from secscan.guard.domain.policy import GuardPolicyVersion
from secscan.runner.domain.admission import (
    AUTH_HEADER_FILE,
    PROXY_FILE,
    SECRET_FILE,
    ContainerSpec,
    PlanRejectedError,
    build_container,
)
from secscan.runner.domain.policy import ENGINE_POLICIES, ContainerPolicy, EnginePolicy
from secscan.runner.domain.runtime import ContainerRuntime, ContainerState, RuntimeUnavailableError
from secscan.runner.egress import GuardEndpoint, RunEgress
from secscan.runner.guard import GuardChannel, GuardUnavailableError
from secscan.runner.plans import ENGINE_IMAGES, RunPlanner, secret_files
from secscan.runner.workspace import ArtifactRejectedError, Workspace, WorkspaceError
from secscan.scanners.domain.fake import FakeScript
from secscan.scanners.domain.plan import ExecutionPlan, plan_hash
from secscan.scanners.domain.profiles import zap_definition_sha256
from secscan.scanners.domain.zap.plan import PlanWindowTooSmallError
from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.domain.model import Lease
from secscan.scans.queue import (
    HEARTBEAT_INTERVAL,
    LEASE_DURATION,
    EgressScope,
    Launch,
    LeaseLostError,
    RunReport,
    RunUsage,
    ScanQueue,
)
from secscan.security.secret_cipher import SecretCipher, SecretUnreadableError
from secscan.security.secret_masking import PROXY_TOKEN_MARK, TARGET_SECRET_MARK, SecretMasker

logger = logging.getLogger(__name__)

# 停止容器時先送 SIGTERM，寬限之後 SIGKILL（容器以 Init 執行，訊號會傳到工具）。
STOP_GRACE_SECONDS = 5
POLL_SECONDS = 1.0
# 連續幾次查不到容器的狀態才放棄（socket-proxy 或 Docker 的暫時錯誤不放棄整個 run）。
MAX_STATE_FAILURES = 3


class _Ending(StrEnum):
    EXITED = "exited"
    NOT_STARTED = "not_started"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    STOPPED = "stopped"
    REJECTED = "rejected"
    LOST = "lost"
    GUARD_LOST = "guard_lost"
    BUDGET_EXHAUSTED = "budget_exhausted"
    # 授權撤回（docs/DECISIONS.md §17.5）：錯誤碼在 _Outcome.error_code。
    REVOKED = "revoked"


# 容器可能還在執行的結果：要確認容器已刪除，才能宣稱已停止。
_NEEDS_REMOVAL = frozenset(
    {
        _Ending.CANCELLED,
        _Ending.TIMED_OUT,
        _Ending.STOPPED,
        _Ending.REJECTED,
        _Ending.LOST,
        _Ending.GUARD_LOST,
        _Ending.BUDGET_EXHAUSTED,
        _Ending.REVOKED,
    }
)


# 容器被 runner 停止的結果，以及 run 要轉到的狀態。guard 中斷和 Docker 中斷一樣是基礎設施的問題：
# 已經送出的流量無法確認，標成 interrupted（不當成零告警）。
_STOPPED_ENDINGS: Mapping[_Ending, tuple[RunStatus, RunErrorCode | None]] = MappingProxyType(
    {
        _Ending.CANCELLED: (RunStatus.CANCELLED, None),
        _Ending.TIMED_OUT: (RunStatus.TIMED_OUT, RunErrorCode.TIME_LIMIT_EXCEEDED),
        _Ending.STOPPED: (RunStatus.INTERRUPTED, RunErrorCode.RUNNER_STOPPED),
        _Ending.REJECTED: (RunStatus.FAILED, RunErrorCode.ARTIFACT_REJECTED),
        _Ending.LOST: (RunStatus.INTERRUPTED, RunErrorCode.RUNTIME_UNAVAILABLE),
        _Ending.GUARD_LOST: (RunStatus.INTERRUPTED, RunErrorCode.GUARD_UNAVAILABLE),
        # guard 的 summary 說已轉送到上限（docs/DECISIONS.md §16.4）：之後的請求都會被拒絕。
        _Ending.BUDGET_EXHAUSTED: (RunStatus.TIMED_OUT, RunErrorCode.BUDGET_EXHAUSTED),
    }
)


@dataclass(frozen=True, slots=True)
class _Outcome:
    ending: _Ending
    state: ContainerState | None = None
    error_code: RunErrorCode | None = None


@dataclass(slots=True)
class _Attempt:
    """執行中的一個 run：容器名稱，以及開始之後才有的出站設定、guard 的 boot_id 與容器啟動的時間
    （monotonic）。
    """

    lease: Lease
    name: str
    egress: RunEgress | None = None
    boot_id: UUID | None = None
    started_at: float | None = None
    # 呼叫過 create：之後即使回錯誤，容器也可能已經建立、甚至已經啟動（例如 client 逾時）。
    create_called: bool = False
    # 收集輸出時要遮掉的目標 secret（§19.5）：只留在記憶體。secret 檔在收集之前就刪掉了，不第二次
    # 解密（換金鑰時可能失敗）。
    secrets: tuple[str, ...] = field(default=(), repr=False)


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
        guard: GuardChannel,
        endpoint: GuardEndpoint,
        guard_policy_version: GuardPolicyVersion,
        engine_policies: Mapping[Engine, EnginePolicy] = ENGINE_POLICIES,
        stop_requested: Callable[[], bool] = lambda: False,
        on_heartbeat: Callable[[], None] = lambda: None,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._queue = queue
        self._runtime = runtime
        self._workspace = workspace
        self._owner = owner
        self._policy = policy
        self._planner = RunPlanner(script=script, clock=clock)
        self._cipher = cipher
        self._guard = guard
        self._endpoint = endpoint
        self._guard_policy_version = guard_policy_version
        self._engine_policies = engine_policies
        self._stop_requested = stop_requested
        self._on_heartbeat = on_heartbeat
        self._sleep = sleep
        self._monotonic = monotonic
        self._clock = clock

    def run_once(self, engines: Collection[Engine]) -> RunReport | None:
        """處理一個排隊中的 run；沒有工作時回 None。

        lease 失效時拋 LeaseLostError；無法確認容器已停止時拋 RuntimeUnavailableError（run 留給
        容器的對帳）。兩種情形，以及任何未預期的例外，都已盡力刪除容器與 secret，guard 的
        policy 保持 blocked。
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
        if launch.progress.run_status is not RunStatus.RUNNING or launch.egress is None:
            return RunReport.of(lease, launch.progress)
        try:
            plan = self._planner.plan(lease, launch, image_ref=str(image))
            spec = build_container(plan, policy=self._policy, engines=self._engine_policies)
        except PlanRejectedError as exc:
            logger.warning("ExecutionPlan 被拒絕：run %s，%s", lease.run_id, exc.reason.value)
            return self._never_started(lease, RunErrorCode.PLAN_REJECTED)
        except PlanWindowTooSmallError:
            logger.warning("剩下的時間、請求數或 grant 的期限不夠執行：run %s", lease.run_id)
            return self._never_started(lease, RunErrorCode.BUDGET_EXHAUSTED)
        self._record_plan(lease, launch, plan)
        return self._execute(_Attempt(lease, spec.name), launch.secret, launch.egress, plan, spec)

    def _record_plan(self, lease: Lease, launch: Launch, plan: ExecutionPlan) -> None:
        """建立容器之前記下實際執行的內容（§20.2）：之後不收集的 run 也查得到版本。"""
        profile = launch.scan_profile
        definition = (
            zap_definition_sha256(profile)
            if lease.engine is Engine.ZAP and profile is not None
            else None
        )
        self._queue.record_plan(
            lease,
            plan_hash=plan_hash(plan),
            profile_definition_sha256=definition,
            guard_policy_version=self._guard_policy_version,
        )

    def _never_started(self, lease: Lease, error_code: RunErrorCode) -> RunReport:
        """沒有流量，也從未建立容器。"""
        self._queue.record_usage(lease, RunUsage(0, 0, 0), container_removed=True)
        return self._fail(lease, error_code)

    def _execute(
        self,
        attempt: _Attempt,
        secret: StoredSecret | None,
        egress: EgressScope,
        plan: ExecutionPlan,
        spec: ContainerSpec,
    ) -> RunReport:
        try:
            outcome = self._start(attempt, secret, egress, plan, spec)
            if outcome is None:
                outcome = self._supervise(attempt, plan.limits.wall_clock_seconds)
        finally:
            removed = self._cleanup(attempt)
        self._queue.record_usage(
            attempt.lease,
            self._usage(attempt, outcome, removed=removed),
            container_removed=removed,
        )
        unconfirmed = outcome.ending in _NEEDS_REMOVAL or (
            outcome.ending is _Ending.NOT_STARTED and attempt.create_called
        )
        if unconfirmed and not removed:
            raise RuntimeUnavailableError("無法確認容器已停止：run 留給對帳")
        return self._conclude(attempt, outcome, plan)

    # --- 啟動 ---------------------------------------------------------------------------------

    def _start(
        self,
        attempt: _Attempt,
        secret: StoredSecret | None,
        egress: EgressScope,
        plan: ExecutionPlan,
        spec: ContainerSpec,
    ) -> _Outcome | None:
        """guard 可用 → 心跳 → secret 與輸入檔 → policy → 心跳 → 建立並啟動容器；失敗時回傳原因
        （還沒有任何流量）。
        """
        admitted = self._admit(attempt, egress, plan.limits.wall_clock_seconds)
        if isinstance(admitted, _Outcome):
            return admitted
        attempt.egress = admitted
        outcome = self._provision(attempt, admitted, secret, plan) or self._confirm(attempt.lease)
        if outcome is not None:
            return outcome
        try:
            attempt.create_called = True
            self._runtime.create(spec)
            self._runtime.start(spec.name)
            attempt.started_at = self._monotonic()
        except RuntimeUnavailableError as exc:
            logger.warning("無法啟動容器：run %s，%s", attempt.lease.run_id, exc)
            return _Outcome(_Ending.NOT_STARTED, error_code=RunErrorCode.RUNTIME_UNAVAILABLE)
        return None

    def _admit(
        self, attempt: _Attempt, egress: EgressScope, wall_clock_seconds: int
    ) -> _Outcome | RunEgress:
        """guard 可用、lease 仍有效、沒有要求取消、授權仍有效，才產生這個 run 的出站設定。"""
        lease = attempt.lease
        health = self._guard.health()
        if not health.available:
            issue = health.issue.value if health.issue is not None else "?"
            logger.warning("egress guard 不可用（%s）：run %s 不啟動", issue, lease.run_id)
            return _Outcome(_Ending.NOT_STARTED, error_code=RunErrorCode.GUARD_UNAVAILABLE)
        now = self._clock()
        renew_until = now + LEASE_DURATION.total_seconds()
        outcome = self._confirm(lease)
        if outcome is not None:
            return outcome
        attempt.boot_id = health.boot_id
        return RunEgress.open(
            self._guard,
            lease=lease,
            policy_version=self._guard_policy_version,
            egress=egress,
            endpoint=self._endpoint,
            now=now,
            wall_clock_seconds=wall_clock_seconds,
            renew_until=renew_until,
        )

    def _confirm(self, lease: Lease) -> _Outcome | None:
        """建立容器之前的心跳：lease 失效 → LeaseLostError（不建立容器）；要求取消 → cancelling；
        授權撤回 → 不啟動（該錯誤碼）。
        """
        heartbeat = self._queue.heartbeat(lease)
        self._on_heartbeat()
        if not heartbeat.valid:
            raise LeaseLostError("lease 已過期：沒有建立容器")
        if heartbeat.cancel_requested:
            self._queue.advance(lease, RunStatus.CANCELLING)
            return _Outcome(_Ending.CANCELLED)
        if heartbeat.stop_reason is not None:
            logger.warning(
                "run %s 的授權已不再有效（%s）：不啟動", lease.run_id, heartbeat.stop_reason
            )
            return _Outcome(_Ending.NOT_STARTED, error_code=heartbeat.stop_reason)
        return None

    def _provision(
        self, attempt: _Attempt, egress: RunEgress, secret: StoredSecret | None, plan: ExecutionPlan
    ) -> _Outcome | None:
        """secret 檔（proxy-url、target-auth）、輸入檔，最後是 guard 的 policy。"""
        lease = attempt.lease
        try:
            files = {PROXY_FILE: egress.proxy_url, **secret_files(plan, egress)}
            if secret is not None:
                value = SecretValue(self._reveal(secret))
                files[SECRET_FILE] = value.value
                files[AUTH_HEADER_FILE] = header_line(secret.credential, value).value
                attempt.secrets = masking_values(secret.credential, value)
            self._workspace.write_secrets(lease.run_id, files)
            self._workspace.prepare(lease.run_id, plan.inputs)
        except _SecretUnavailableError:
            return _Outcome(_Ending.NOT_STARTED, error_code=RunErrorCode.SECRET_UNAVAILABLE)
        except WorkspaceError as exc:
            logger.error("工作目錄不可用：run %s，%s", lease.run_id, exc)
            return _Outcome(_Ending.NOT_STARTED, error_code=RunErrorCode.WORKSPACE_UNAVAILABLE)
        try:
            egress.activate()
        except GuardUnavailableError as exc:
            logger.error("無法寫入 guard 的 policy：run %s，%s", lease.run_id, exc)
            return _Outcome(_Ending.NOT_STARTED, error_code=RunErrorCode.GUARD_UNAVAILABLE)
        return None

    def _reveal(self, secret: StoredSecret) -> str:
        """解密綁定版本的密文（整個專案只有這裡呼叫 reveal；docs/DECISIONS.md §12.2）。"""
        if self._cipher is None:
            raise _SecretUnavailableError
        try:
            return self._cipher.reveal(secret.token, context=secret.context)
        except SecretUnreadableError:
            raise _SecretUnavailableError from None

    # --- 監看 ---------------------------------------------------------------------------------

    def _supervise(self, attempt: _Attempt, wall_clock_seconds: int) -> _Outcome:
        started = self._monotonic()
        # 啟動後立刻心跳一次：lease 從認領起算，建立與啟動容器可能花掉不少時間（審查發現）。
        last_beat = started - HEARTBEAT_INTERVAL.total_seconds()
        failures = 0
        while True:
            now = self._monotonic()
            if now - last_beat >= HEARTBEAT_INTERVAL.total_seconds():
                last_beat = now
                stopped = self._beat(attempt)
                if stopped is not None:
                    return stopped
            try:
                outcome = self._step(attempt, elapsed=now - started, limit=wall_clock_seconds)
            except RuntimeUnavailableError as exc:
                failures += 1
                logger.warning("查不到容器 %s 的狀態（第 %d 次）：%s", attempt.name, failures, exc)
                if failures >= MAX_STATE_FAILURES:
                    return _Outcome(_Ending.LOST)
                outcome = None
            else:
                failures = 0
            if outcome is not None:
                return outcome
            self._sleep(POLL_SECONDS)

    def _step(self, attempt: _Attempt, *, elapsed: float, limit: int) -> _Outcome | None:
        """查一次容器的狀態與 out/ 的用量；需要結束時停止容器並回傳結果。"""
        state = self._runtime.state(attempt.name)
        if state is None or not state.running:
            return _Outcome(_Ending.EXITED, state)
        if self._stop_requested():
            return self._stopping(attempt, _Ending.STOPPED)
        if elapsed >= limit:
            return self._stopping(attempt, _Ending.TIMED_OUT)
        try:
            self._workspace.check_output(attempt.lease.run_id)
        except (ArtifactRejectedError, WorkspaceError) as exc:
            logger.warning("輸出超過上限：run %s，%s", attempt.lease.run_id, exc)
            return self._stopping(attempt, _Ending.REJECTED)
        return None

    def _stopping(self, attempt: _Attempt, ending: _Ending) -> _Outcome:
        self._stop(attempt)
        return _Outcome(ending)

    def _stop(self, attempt: _Attempt) -> None:
        """先封鎖 guard（容器之後送出的請求都被拒絕），再停止容器；停止失敗時由強制刪除處理。"""
        self._block(attempt)
        try:
            self._runtime.stop(attempt.name, grace_seconds=STOP_GRACE_SECONDS)
        except RuntimeUnavailableError as exc:
            logger.warning("無法停止容器 %s（%s）：改由強制刪除處理", attempt.name, exc)

    def _block(self, attempt: _Attempt) -> None:
        if attempt.egress is None:
            return
        try:
            attempt.egress.block()
        except GuardUnavailableError as exc:
            # renew_until 仍會在 lease 到期時讓 guard 停止放行（dead-man switch）。
            logger.error("無法封鎖 run %s 的 guard policy（%s）", attempt.lease.run_id, exc)

    def _beat(self, attempt: _Attempt) -> _Outcome | None:
        """延長 lease 並續約 guard 的 policy；需要停止時停止容器並回傳結果。

        順序：lease 失效 → 要求取消 → 授權撤回（§17.5）→ 續約 → 預算用盡。
        """
        lease = attempt.lease
        renew_until = self._clock() + LEASE_DURATION.total_seconds()
        heartbeat = self._queue.heartbeat(lease)
        self._on_heartbeat()
        if not heartbeat.valid:
            self._stop(attempt)
            raise LeaseLostError("lease 已過期：已停止容器，交給對帳處理")
        if heartbeat.cancel_requested:
            # 取消：封鎖 guard → cancelling → 停止容器（docs/DECISIONS.md §15.7）。
            self._block(attempt)
            self._queue.advance(lease, RunStatus.CANCELLING)
            self._stop(attempt)
            return _Outcome(_Ending.CANCELLED)
        if heartbeat.stop_reason is not None:
            logger.warning(
                "run %s 的授權已不再有效（%s）：停止", lease.run_id, heartbeat.stop_reason
            )
            self._stop(attempt)
            return _Outcome(_Ending.REVOKED, error_code=heartbeat.stop_reason)
        if not self._renewed(attempt, renew_until):
            self._stop(attempt)
            return _Outcome(_Ending.GUARD_LOST)
        ending = self._telemetry_stop(attempt)
        if ending is not None:
            self._stop(attempt)
            return _Outcome(ending)
        return None

    def _telemetry_stop(self, attempt: _Attempt) -> _Ending | None:
        """可解析的摘要若與本 run 政策不符，先封鎖再停止；預算仍由 guard 強制。"""
        try:
            summary = self._guard.summary(attempt.lease.run_id)
        except GuardUnavailableError as exc:
            logger.warning("讀不到 run %s 的 telemetry（%s）", attempt.lease.run_id, exc)
            return None
        if summary is None:
            return None
        if (
            attempt.egress is None
            or summary.scan_id != attempt.lease.scan_id
            or summary.boot_id != attempt.boot_id
            or summary.policy_version is not attempt.egress.policy.policy_version
        ):
            logger.error("run %s 的 telemetry 政策或身分不符：停止", attempt.lease.run_id)
            return _Ending.GUARD_LOST
        return _Ending.BUDGET_EXHAUSTED if summary.exhausted else None

    def _renewed(self, attempt: _Attempt, renew_until: float) -> bool:
        """guard 仍可用、沒有重啟過（boot_id 相同），而且續約寫得出去。"""
        health = self._guard.health()
        if not health.available or health.boot_id != attempt.boot_id or attempt.egress is None:
            logger.error("egress guard 中斷或重啟過：run %s 停止", attempt.lease.run_id)
            return False
        try:
            attempt.egress.renew(renew_until)
        except GuardUnavailableError as exc:
            logger.error("無法續約 run %s 的 guard policy（%s）", attempt.lease.run_id, exc)
            return False
        return True

    # --- 清理與結果 ---------------------------------------------------------------------------

    def _cleanup(self, attempt: _Attempt) -> bool:
        """封鎖 → 刪除容器 → 刪除 secret → 確認容器已刪除才刪 policy（否則保留 blocked）。

        回傳容器是否確定已不存在（Docker 不可用時是 False）。
        """
        self._block(attempt)
        run_id = attempt.lease.run_id
        try:
            self._runtime.remove(attempt.name)
        except RuntimeUnavailableError as exc:
            logger.error("無法刪除容器 %s（%s）：留給容器的對帳", attempt.name, exc)
            return False
        finally:
            try:
                self._workspace.discard_secrets(run_id)
            except WorkspaceError as exc:
                logger.error("無法刪除 run %s 的 secret（%s）：下次啟動時清除", run_id, exc)
        if attempt.egress is not None:
            try:
                attempt.egress.discard()
            except GuardUnavailableError as exc:
                logger.error("無法刪除 run %s 的 guard policy（%s）：下次啟動時清除", run_id, exc)
        return True

    def _usage(self, attempt: _Attempt, outcome: _Outcome, *, removed: bool) -> RunUsage:
        """run 用掉的預算（docs/DECISIONS.md §16.4），在最後一次轉換之前寫入。

        - 沒寫過 policy：沒有任何流量，0。
        - 有 summary：以 guard 記下的為準（超過分到的數量就是不可信，留空）。
        - 沒有 summary：guard 每轉送一個請求都先寫 summary，所以同一個 guard（boot_id 相同、沒有
          中斷）就是 0；guard 重啟或中斷過則留空，之後的 run 以分到的數量扣除。
        - 容器沒確認刪除（之後可能還在送），或 summary 是另一個 guard 寫的（重啟之後從 0 開始計）：
          留空（審查發現）。
        """
        seconds = (
            0 if attempt.started_at is None else math.ceil(self._monotonic() - attempt.started_at)
        )
        egress = attempt.egress
        if egress is None or not egress.activated:
            return RunUsage(requests_sent=0, requests_denied=0, traffic_seconds=seconds)
        run_id = attempt.lease.run_id
        unknown = RunUsage(requests_sent=None, requests_denied=None, traffic_seconds=seconds)
        if not removed or outcome.ending is _Ending.GUARD_LOST:
            return unknown
        try:
            summary = self._guard.summary(run_id)
        except GuardUnavailableError as exc:
            logger.error("讀不到 run %s 的 telemetry（%s）：用量留空", run_id, exc)
            return unknown
        if summary is None:
            same_guard = self._guard.health().boot_id == attempt.boot_id
            return RunUsage(0, 0, seconds) if same_guard else unknown
        if (
            summary.scan_id != attempt.lease.scan_id
            or summary.boot_id != attempt.boot_id
            or summary.forwarded > egress.policy.budget.max_requests
            or summary.policy_version is not egress.policy.policy_version
        ):
            logger.error("run %s 的 telemetry 和 policy 不符：用量留空", run_id)
            return unknown
        return RunUsage(summary.forwarded, summary.denied_total, seconds)

    def _conclude(self, attempt: _Attempt, outcome: _Outcome, plan: ExecutionPlan) -> RunReport:
        lease = attempt.lease
        if outcome.ending in (_Ending.NOT_STARTED, _Ending.REVOKED):
            return self._fail(lease, outcome.error_code or RunErrorCode.RUNTIME_UNAVAILABLE)
        if outcome.ending is _Ending.EXITED:
            return self._exited(attempt, outcome.state, plan)
        status, error_code = _STOPPED_ENDINGS[outcome.ending]
        return self._advance(lease, status, error_code)

    def _exited(
        self, attempt: _Attempt, state: ContainerState | None, plan: ExecutionPlan
    ) -> RunReport:
        """退出碼在引擎的收集清單中（zap 的 AF 有警告是 2，§18.1）才收集；語意由 parser 判斷。"""
        lease = attempt.lease
        if state is None or state.exit_code is None:
            return self._fail(lease, RunErrorCode.RUNTIME_UNAVAILABLE)
        if state.oom_killed:
            return self._fail(lease, RunErrorCode.RESOURCE_LIMIT_EXCEEDED)
        if state.exit_code not in self._engine_policies[plan.engine].collect_exit_codes:
            return self._fail(lease, RunErrorCode.ENGINE_FAILED)
        self._queue.advance(lease, RunStatus.COLLECTING)
        self._beat_collecting(lease)
        try:
            self._workspace.collect(
                lease.run_id,
                exit_code=state.exit_code,
                inputs=plan.inputs,
                masker=self._masker(attempt, plan),
                on_progress=self._collecting_progress(lease),
            )
        except ArtifactRejectedError as exc:
            logger.warning("輸出被拒絕：run %s，%s", lease.run_id, exc.issue.value)
            return self._fail(lease, RunErrorCode.ARTIFACT_REJECTED)
        except WorkspaceError as exc:
            logger.error("無法收集輸出：run %s，%s", lease.run_id, exc)
            return self._fail(lease, RunErrorCode.WORKSPACE_UNAVAILABLE)
        return self._advance(lease, RunStatus.COLLECTED)

    def _masker(self, attempt: _Attempt, plan: ExecutionPlan) -> SecretMasker | None:
        """引擎宣告 redact_outputs 時，以這個 run 的 secret 遮罩輸出（§19.5）。"""
        if not self._engine_policies[plan.engine].redact_outputs:
            return None
        egress = attempt.egress
        return SecretMasker.of(
            {
                TARGET_SECRET_MARK: attempt.secrets,
                PROXY_TOKEN_MARK: egress.masking_values() if egress is not None else (),
            }
        )

    def _beat_collecting(self, lease: Lease) -> None:
        if not self._queue.heartbeat(lease).valid:
            raise LeaseLostError("lease 已過期：不收集，交給對帳處理")
        self._on_heartbeat()

    def _collecting_progress(self, lease: Lease) -> Callable[[], None]:
        """遮罩大檔可能超過 lease 的長度：處理的過程中依心跳的間隔延長 lease。"""
        last_beat = self._monotonic()

        def progress() -> None:
            nonlocal last_beat
            now = self._monotonic()
            if now - last_beat >= HEARTBEAT_INTERVAL.total_seconds():
                last_beat = now
                self._beat_collecting(lease)

        return progress

    def _fail(self, lease: Lease, error_code: RunErrorCode) -> RunReport:
        return self._advance(lease, RunStatus.FAILED, error_code)

    def _advance(
        self, lease: Lease, to: RunStatus, error_code: RunErrorCode | None = None
    ) -> RunReport:
        return RunReport.of(lease, self._queue.advance(lease, to, error_code=error_code))
