"""runner 內的容器對帳（docs/DECISIONS.md §17.2、§17.4）。

lease 過期不代表容器已經停止（ARCHITECTURE.md §9）。依 DB 記下的容器名稱（socket-proxy 不放行
list），每個待處理的 run：
1. 封鎖 guard 的 policy（讀回、改成 blocked；失敗只記 log：policy 早已過期，§17.1）。
2. 刪除 secret。
3. inspect 並核對 label：是這個 run 的容器就強制刪除；404 是已不存在；label 不符就不動那個容器
   （證明這個 run 的容器不存在），記 ERROR。
4. 確認之後才在 DB 結算（runner 階段 → interrupted LEASE_EXPIRED），最後刪除 policy。
Docker 出錯時不結算、policy 保持 blocked，下一輪再處理。Docker 本身可用（version 有回應）、只有
這個容器刪不掉時，延後它、繼續處理其他的（不讓一個壞掉的容器擋住整個佇列），每個 run 只記一次
ERROR；Docker 不可用時這一輪就停，同一段中斷只記一次。

啟動時另外依證據清理 policy 與 secret 目錄：只處理已結算或 DB 沒有的 run，不再刪除全部
（舊的做法會在容器確認刪除之前刪掉孤兒容器的 policy）。
"""

import logging
from collections.abc import Collection
from enum import StrEnum
from uuid import UUID

from secscan.runner.domain.admission import container_name
from secscan.runner.domain.runtime import (
    ContainerConflictError,
    ContainerRuntime,
    RuntimeUnavailableError,
)
from secscan.runner.guard import GuardChannel, GuardUnavailableError
from secscan.runner.plans import ENGINE_IMAGES
from secscan.runner.workspace import Workspace, WorkspaceError
from secscan.scans.domain.catalog import Engine
from secscan.scans.queue import ScanQueue

logger = logging.getLogger(__name__)

# 每輪最多處理的待處理容器（升級之前的歷史 run 也會逐輪確認）。
BATCH = 20
# policy 目錄的暫存檔可能是另一個 runner 正在寫的：超過這個時間才刪。
TEMPORARY_GRACE_SECONDS = 60.0


class _Removal(StrEnum):
    GONE = "gone"  # 這個 run 的容器已不存在（刪除了、404，或同名的不是它）
    DEFERRED = "deferred"  # 409（刪除進行中）或只有這個容器出錯：下一輪再確認
    DOCKER_DOWN = "docker_down"


class ContainerReconciler:
    def __init__(
        self,
        queue: ScanQueue,
        runtime: ContainerRuntime,
        workspace: Workspace,
        guard: GuardChannel,
        *,
        engines: Collection[Engine] = frozenset(ENGINE_IMAGES),
        batch: int = BATCH,
    ) -> None:
        self._queue = queue
        self._runtime = runtime
        self._workspace = workspace
        self._guard = guard
        self._engines = engines
        self._batch = batch
        self._docker_down = False
        # 刪不掉容器的 run（已記過 ERROR）；確認刪除之後移除。
        self._stuck: set[UUID] = set()

    def reconcile(self) -> int:
        """結算 lease 過期的 run；回傳結算的數量。

        沒有容器、或容器已確認刪除的先結算（不必呼叫 Docker）；再逐一處理待處理的容器。
        """
        settled = self._queue.reconcile_expired_runner(self._engines)
        for item in self._queue.pending_containers(self._batch):
            removal = self._dispose(item.run_id, item.name)
            if removal is _Removal.DOCKER_DOWN:
                break
            if removal is _Removal.GONE and self._queue.settle_container(item.run_id):
                logger.warning("run %s 的容器已確認不存在：已結算", item.run_id)
                self._discard_policy(item.run_id)
                settled += 1
        return settled

    def sweep_orphans(self) -> int:
        """啟動時依證據清理（§17.4）：已結算或 DB 沒有的 run 留下的 policy、secret 與容器。

        容器還沒確認刪除、或 lease 還有效的 run 跳過（由對帳或 owner 處理）。刪不掉容器就保留
        blocked 的 policy，下次啟動再處理。回傳清理的 run 數。
        """
        try:
            self._guard.sweep_temporary(older_than=TEMPORARY_GRACE_SECONDS)
            found = self._guard.policy_runs() | self._workspace.secret_runs()
        except (GuardUnavailableError, WorkspaceError) as exc:
            # 不讓 runner 因此無法啟動：留下的檔案下次啟動再清，對帳照常進行。
            logger.error("無法列出留下的 policy 或 secret（%s）：跳過這次清理", exc)
            return 0
        cleaned = 0
        for run_id in sorted(found - self._queue.unsettled_runs(found)):
            removal = self._dispose(run_id, container_name(run_id))
            if removal is _Removal.DOCKER_DOWN:
                break
            if removal is _Removal.GONE:
                self._discard_policy(run_id)
                cleaned += 1
        if cleaned:
            logger.warning("已清理上一個 runner 留下的 %d 個 run", cleaned)
        return cleaned

    def _dispose(self, run_id: UUID, name: str) -> _Removal:
        """封鎖 → 刪除 secret → 刪除容器（DoD 3：先封鎖 guard，再回收容器）。"""
        try:
            self._guard.block(run_id)
        except GuardUnavailableError as exc:
            # policy 已過期（renew_until ≤ lease 到期，§17.1）：仍然刪除容器。
            logger.error("無法封鎖 run %s 的 guard policy（%s）：仍刪除容器", run_id, exc)
        try:
            self._workspace.discard_secrets(run_id)
        except WorkspaceError as exc:
            logger.error("無法刪除 run %s 的 secret（%s）", run_id, exc)
        return self._remove(run_id, name)

    def _remove(self, run_id: UUID, name: str) -> _Removal:
        try:
            state = self._runtime.state(name)
            if state is not None and state.run_label == run_id:
                self._runtime.remove(name)
            elif state is not None:
                logger.error("容器 %s 沒有 run %s 的 label：不刪除它", name, run_id)
        except ContainerConflictError as exc:
            logger.warning("容器 %s 正在刪除（%s）：下一輪再確認", name, exc)
            return _Removal.DEFERRED
        except RuntimeUnavailableError as exc:
            return self._failed(run_id, name, exc)
        self._docker_available()
        self._stuck.discard(run_id)
        return _Removal.GONE

    def _failed(self, run_id: UUID, name: str, exc: RuntimeUnavailableError) -> _Removal:
        """Docker 本身可用就只是這個容器的問題：延後它、繼續處理其他的；否則這一輪停止。"""
        try:
            self._runtime.version()
        except RuntimeUnavailableError:
            if not self._docker_down:
                logger.warning("Docker 不可用（%s）：容器的對帳延到下一輪", exc)
            self._docker_down = True
            return _Removal.DOCKER_DOWN
        self._docker_available()
        if run_id not in self._stuck:
            logger.error("無法確認容器 %s 已刪除（%s）：run %s 留到下一輪", name, exc, run_id)
            self._stuck.add(run_id)
        return _Removal.DEFERRED

    def _docker_available(self) -> None:
        if self._docker_down:
            logger.info("Docker 已恢復：繼續容器的對帳")
        self._docker_down = False

    def _discard_policy(self, run_id: UUID) -> None:
        try:
            self._guard.remove(run_id)
        except GuardUnavailableError as exc:
            logger.error("無法刪除 run %s 的 guard policy（%s）：下次啟動時清除", run_id, exc)
