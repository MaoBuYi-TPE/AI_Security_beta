"""worker（docs/DECISIONS.md §14.6、§16.5）：解析收集好的輸出。

先把 lease 過期的 normalizing 退回 collected（解析不送流量，可以重試），再認領 collected 的 run。
- fake：沒有東西可以解析。
- preflight：讀帶認證與匿名的回應，依 §12.5 判斷（scanners.domain.preflight.evaluate），在 run
  結束之前寫入結果。沒有 artifact 的讀取器（in-process）或沒有輸出時是 not_executed。
M3 起依引擎呼叫 parser（輸出一律當成不可信的資料）。
"""

from collections.abc import Callable

from secscan.scanners.domain.preflight import (
    ANONYMOUS_OUTPUT,
    AUTHENTICATED_OUTPUT,
    MAX_RESPONSE_BYTES,
    evaluate,
)
from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.lifecycle import RunStatus
from secscan.scans.domain.model import Lease
from secscan.scans.domain.preflight import PreflightResult
from secscan.scans.queue import RunReport, ScanQueue
from secscan.worker.artifacts import ArtifactReader

ENGINES = frozenset({Engine.FAKE, Engine.PREFLIGHT})


class Worker:
    def __init__(
        self,
        queue: ScanQueue,
        *,
        owner: str,
        artifacts: ArtifactReader | None = None,
        engines: frozenset[Engine] = ENGINES,
    ) -> None:
        self._queue = queue
        self._owner = owner
        self._artifacts = artifacts
        self._engines = engines

    def drain(
        self,
        *,
        limit: int | None = None,
        on_report: Callable[[RunReport], None] | None = None,
    ) -> list[RunReport]:
        """對帳之後處理所有等待解析的 run（或 limit 個）。"""
        self._queue.reconcile_expired_parsing(self._engines)
        reports: list[RunReport] = []
        while limit is None or len(reports) < limit:
            lease = self._queue.claim_collected(self._owner, self._engines)
            if lease is None:
                break
            if lease.engine is Engine.PREFLIGHT:
                self._queue.record_preflight(lease, self._preflight(lease))
            report = RunReport.of(lease, self._queue.advance(lease, RunStatus.SUCCEEDED))
            reports.append(report)
            if on_report is not None:
                on_report(report)
        return reports

    def _preflight(self, lease: Lease) -> PreflightResult:
        definition = self._queue.bound_preflight(lease)
        if definition is None or self._artifacts is None:
            return PreflightResult.NOT_EXECUTED
        authenticated, anonymous = (
            self._artifacts.read(lease.run_id, name, max_bytes=MAX_RESPONSE_BYTES)
            for name in (AUTHENTICATED_OUTPUT, ANONYMOUS_OUTPUT)
        )
        return evaluate(definition, authenticated, anonymous)
