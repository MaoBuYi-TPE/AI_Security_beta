"""runner 的常駐迴圈（docs/DECISIONS.md §14.6、§14.7）。

- 啟動時：清掉上一個 runner 留下的 secret（沒有其他存活的 runner 時）、刪掉過期的心跳列、
  probe 一次（也確認兩個 volume 可寫）。
- 每圈寫心跳（含最近一次 probe 的結果），只認領 probe 通過的引擎；probe 每 60 秒重做一次。
- lease 失效或監看途中 Docker 不可用時記下、重新 probe，繼續處理下一個（run 留給 T13 的對帳）。
  DB 錯誤直接往外拋：程序結束，由 compose 重啟。
"""

import logging
import time
from collections.abc import Callable, Mapping

from secscan.runner.domain.policy import ENGINE_POLICIES, ContainerPolicy, EnginePolicy
from secscan.runner.domain.runtime import ContainerRuntime, RuntimeUnavailableError
from secscan.runner.probe import probe
from secscan.runner.service import ContainerRunner
from secscan.runner.workspace import Workspace
from secscan.scanners.domain.instances import Capabilities
from secscan.scanners.service import Fleet
from secscan.scans.domain.catalog import Engine
from secscan.scans.queue import LeaseLostError, RunReport

logger = logging.getLogger(__name__)

PROBE_EVERY_SECONDS = 60.0


class RunnerLoop:
    def __init__(
        self,
        fleet: Fleet,
        *,
        runtime: ContainerRuntime,
        workspace: Workspace,
        policy: ContainerPolicy,
        engines: Mapping[Engine, EnginePolicy] = ENGINE_POLICIES,
        stop_requested: Callable[[], bool],
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        poll_seconds: float,
    ) -> None:
        self._fleet = fleet
        self._runtime = runtime
        self._workspace = workspace
        self._policy = policy
        self._engines = engines
        self._stop_requested = stop_requested
        self._sleep = sleep
        self._monotonic = monotonic
        self._poll_seconds = poll_seconds
        self._runner: ContainerRunner | None = None
        self._capabilities = Capabilities(engines=())
        self._probed_at = 0.0
        self.failures = 0

    @property
    def available_engines(self) -> frozenset[Engine]:
        """最近一次 probe 通過的引擎。"""
        return self._capabilities.available_engines

    def attach(self, runner: ContainerRunner) -> None:
        """runner 的心跳要回呼 beat()，所以兩者分開建立。"""
        self._runner = runner

    def beat(self) -> None:
        self._fleet.beat(self._capabilities)

    def run(
        self, *, once: bool = False, on_report: Callable[[RunReport], None] | None = None
    ) -> list[RunReport]:
        """處理排隊中的 run，直到要求停止（once：最多處理一個，沒有工作就回來）。"""
        if self._runner is None:
            raise RuntimeError("先以 attach() 指定 runner")
        self._sweep()
        self._fleet.prune()
        self._probe()
        reports: list[RunReport] = []
        while not self._stop_requested():
            if self._monotonic() - self._probed_at >= PROBE_EVERY_SECONDS:
                self._probe()
            self.beat()
            report = self._run_one(self._runner)
            if report is not None:
                reports.append(report)
                if on_report is not None:
                    on_report(report)
            if once:
                break
            if report is None:
                self._sleep(self._poll_seconds)
        return reports

    def _sweep(self) -> None:
        """刪除上一個 runner 留下的 secret；還有其他存活的 runner 時不刪（可能正在使用）。"""
        if self._fleet.others_alive():
            logger.warning("還有其他存活的 runner：不清除 secret 目錄")
            return
        removed = self._workspace.sweep_secrets()
        if removed:
            logger.warning("已刪除上一個 runner 留下的 %d 個 secret 目錄", removed)

    def _probe(self) -> None:
        self._capabilities = probe(
            self._runtime,
            self._policy,
            self._engines,
            volumes_writable=self._workspace.writable(),
        )
        self._probed_at = self._monotonic()
        for item in self._capabilities.engines:
            if item.issue is not None:
                logger.warning("引擎 %s 不可用：%s", item.engine.value, item.issue.value)

    def _run_one(self, runner: ContainerRunner) -> RunReport | None:
        try:
            return runner.run_once(self._capabilities.available_engines)
        except LeaseLostError:
            logger.warning("lease 已失效：已停止容器，run 留給對帳")
        except RuntimeUnavailableError as exc:
            logger.error("Docker 不可用（%s）：run 留給對帳，重新 probe", exc)
            self._probe()
        self.failures += 1
        return None
