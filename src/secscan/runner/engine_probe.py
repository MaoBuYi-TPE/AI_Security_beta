"""執行容器驗證的 capability probe（docs/DECISIONS.md §18.8；ARCHITECTURE §5）。

環境的 probe（probe.py）只確認映像在本機；這裡實際以和掃描相同的強化設定（同一套
build_container：uid 10001、唯讀 rootfs、tmpfs）啟動 zap 的映像，確認版本、必要的 add-on 與
規則白名單、輸出能寫出。
- 非阻塞：runner 的迴圈每圈呼叫 step 前進一步（建立與啟動、查狀態、讀結果、刪除），probe 期間
  其他引擎照常認領；zap 在驗證通過之前是 ENGINE_PROBE_PENDING。
- 每次用新的 id（workspace 的目錄不會重用）；secret 目錄是空的（不需要 proxy：probe 不送請求，
  也不寫 guard 的 policy）。容器確認刪除之後才刪 secret 目錄：刪不掉時，runner 下次啟動依證據
  的清理（§17.4）以它找回容器。
- 有牆鐘上限；結果以映像快取（同一個程序不再執行），失敗以退避重試。
輸出都是不可信的資料：以 workspace.read_output 讀取（有大小上限），由 evaluate_probe 判斷。
"""

import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from uuid import UUID, uuid4

from secscan.runner.domain.admission import PlanRejectedError, build_container
from secscan.runner.domain.policy import ENGINE_POLICIES, ContainerPolicy, EnginePolicy
from secscan.runner.domain.runtime import ContainerRuntime, RuntimeUnavailableError
from secscan.runner.service import STOP_GRACE_SECONDS
from secscan.runner.workspace import ArtifactRejectedError, Workspace, WorkspaceError
from secscan.scanners.domain.instances import Capabilities, CapabilityIssue, EngineCapability
from secscan.scanners.domain.zap.policy import ZAP_IMAGE
from secscan.scanners.domain.zap.probe import (
    MAX_PROBE_OUTPUT_BYTES,
    PROBE_WALL_CLOCK_SECONDS,
    ProbeIssue,
    ProbeResult,
    evaluate_probe,
    plan_zap_probe,
)
from secscan.scanners.domain.zap.script import PLUGINS_FILE, PROBE_REPORT_FILE
from secscan.scans.domain.catalog import Engine

logger = logging.getLogger(__name__)

PROBE_RETRY_SECONDS = 600.0
_ISSUES: Mapping[ProbeIssue, CapabilityIssue] = MappingProxyType(
    {
        ProbeIssue.FAILED: CapabilityIssue.ENGINE_PROBE_FAILED,
        ProbeIssue.INCOMPATIBLE: CapabilityIssue.ENGINE_INCOMPATIBLE,
    }
)


@dataclass(frozen=True, slots=True)
class _Running:
    probe_id: UUID
    name: str
    started_at: float


class EngineProber:
    def __init__(
        self,
        runtime: ContainerRuntime,
        workspace: Workspace,
        policy: ContainerPolicy,
        *,
        engines: Mapping[Engine, EnginePolicy] = ENGINE_POLICIES,
        monotonic: Callable[[], float] = time.monotonic,
        new_id: Callable[[], UUID] = uuid4,
    ) -> None:
        self._runtime = runtime
        self._workspace = workspace
        self._policy = policy
        self._engines = engines
        self._monotonic = monotonic
        self._new_id = new_id
        self._verified: ProbeResult | None = None
        self._failure: CapabilityIssue | None = None
        self._failed_at: float | None = None
        self._running: _Running | None = None

    @property
    def running(self) -> bool:
        return self._running is not None

    def apply(self, capabilities: Capabilities) -> Capabilities:
        """zap 的映像與環境都可用時，只有 probe 通過才可用（帶著版本）；其他原因照原樣回報。"""
        return Capabilities(engines=tuple(self._applied(item) for item in capabilities.engines))

    def step(self, capabilities: Capabilities) -> None:
        if self._running is not None:
            self._check(self._running)
        elif self._due() and _ready(capabilities):
            self._start()

    def close(self) -> None:
        """runner 停止：刪除執行中的 probe 容器（不記結果）。"""
        if self._running is not None:
            self._finish(self._running)

    def _applied(self, item: EngineCapability) -> EngineCapability:
        if item.engine is not Engine.ZAP or item.issue is not None:
            return item
        if self._verified is not None:
            return replace(item, version=self._verified.version)
        return replace(item, issue=self._failure or CapabilityIssue.ENGINE_PROBE_PENDING)

    def _due(self) -> bool:
        if self._verified is not None:
            return False
        return self._failed_at is None or (
            self._monotonic() - self._failed_at >= PROBE_RETRY_SECONDS
        )

    def _start(self) -> None:
        probe_id = self._new_id()
        plan = plan_zap_probe(probe_id)
        running: _Running | None = None
        try:
            spec = build_container(plan, policy=self._policy, engines=self._engines)
            self._workspace.prepare(probe_id, plan.inputs)
            self._workspace.create_secret_dir(probe_id)
            running = _Running(probe_id, spec.name, self._monotonic())
            self._runtime.create(spec)
            self._runtime.start(spec.name)
        except (PlanRejectedError, WorkspaceError, RuntimeUnavailableError) as exc:
            logger.warning("zap 的 probe 無法啟動（%s）", type(exc).__name__)
            if running is not None:
                self._finish(running)
            self._record(ProbeResult(ProbeIssue.FAILED))
            return
        self._running = running
        logger.info("zap 的 probe 已啟動（%s）", ZAP_IMAGE.tag)

    def _check(self, running: _Running) -> None:
        try:
            state = self._runtime.state(running.name)
        except RuntimeUnavailableError:
            # 暫時查不到：還在期限內就下一圈再查。
            if not self._expired(running):
                return
            state = None
        if (
            state is not None
            and state.running
            and not self._expired(running)
            and self._within_limits(running)
        ):
            return
        if state is None or state.running or state.exit_code is None:
            self._stop(running)
            result = ProbeResult(ProbeIssue.FAILED)
        else:
            result = evaluate_probe(
                exit_code=state.exit_code,
                plugins=self._output(running, PLUGINS_FILE),
                report=self._output(running, PROBE_REPORT_FILE),
            )
        self._finish(running)
        self._record(result)

    def _within_limits(self, running: _Running) -> bool:
        """和掃描相同的用量檢查（條目數、深度、大小）：超過就停止，不等牆鐘的上限。"""
        try:
            self._workspace.check_output(running.probe_id)
        except (ArtifactRejectedError, WorkspaceError) as exc:
            logger.warning("zap 的 probe 的輸出不符合規則（%s）：停止", type(exc).__name__)
            return False
        return True

    def _expired(self, running: _Running) -> bool:
        return self._monotonic() - running.started_at > PROBE_WALL_CLOCK_SECONDS

    def _stop(self, running: _Running) -> None:
        try:
            self._runtime.stop(running.name, grace_seconds=STOP_GRACE_SECONDS)
        except RuntimeUnavailableError as exc:
            logger.warning("無法停止 zap 的 probe（%s）：改由強制刪除處理", exc)

    def _output(self, running: _Running, name: str) -> bytes | None:
        return self._workspace.read_output(running.probe_id, name, max_bytes=MAX_PROBE_OUTPUT_BYTES)

    def _finish(self, running: _Running) -> None:
        """刪除容器；確認刪除之後才刪 secret 目錄（刪不掉時留給下次啟動的清理）。"""
        self._running = None
        try:
            self._runtime.remove(running.name)
        except RuntimeUnavailableError as exc:
            logger.error("無法刪除 zap 的 probe 容器（%s）：下次啟動時清除", exc)
            return
        try:
            self._workspace.discard_secrets(running.probe_id)
        except WorkspaceError as exc:
            logger.error("無法刪除 zap 的 probe 的 secret 目錄（%s）", exc)

    def _record(self, result: ProbeResult) -> None:
        if result.issue is None:
            self._verified, self._failure, self._failed_at = result, None, None
            logger.info("zap 的 probe 通過（%s）", result.version)
            return
        self._failure = _ISSUES[result.issue]
        self._failed_at = self._monotonic()
        logger.warning("zap 的 probe 不通過（%s）：%s 秒後重試", result.issue, PROBE_RETRY_SECONDS)


def _ready(capabilities: Capabilities) -> bool:
    """zap 的映像在、環境可用（probe.py 沒有回報任何原因）。"""
    return any(
        item.engine is Engine.ZAP and item.issue is None and item.image == str(ZAP_IMAGE)
        for item in capabilities.engines
    )
