"""worker（docs/DECISIONS.md §14.6）：解析收集好的輸出。T10 只有 fake：沒有東西可以解析。

先把 lease 過期的 normalizing 退回 collected（解析不送流量，可以重試），再認領 collected 的 run。
M3 起依引擎呼叫 parser（輸出一律當成不可信的資料）。
"""

from collections.abc import Callable

from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.lifecycle import RunStatus
from secscan.scans.queue import RunReport, ScanQueue

ENGINES = frozenset({Engine.FAKE})


class Worker:
    def __init__(
        self, queue: ScanQueue, *, owner: str, engines: frozenset[Engine] = ENGINES
    ) -> None:
        self._queue = queue
        self._owner = owner
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
            report = RunReport.of(lease, self._queue.advance(lease, RunStatus.SUCCEEDED))
            reports.append(report)
            if on_report is not None:
                on_report(report)
        return reports
