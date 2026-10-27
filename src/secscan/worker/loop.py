"""worker 的常駐迴圈（docs/DECISIONS.md §14.6、§14.7）：每圈寫心跳，再處理等待解析的 run。"""

import time
from collections.abc import Callable

from secscan.scanners.domain.instances import Capabilities
from secscan.scanners.service import Fleet
from secscan.scans.queue import RunReport
from secscan.worker.service import Worker


class WorkerLoop:
    def __init__(
        self,
        worker: Worker,
        fleet: Fleet,
        *,
        stop_requested: Callable[[], bool],
        sleep: Callable[[float], None] = time.sleep,
        poll_seconds: float,
    ) -> None:
        self._worker = worker
        self._fleet = fleet
        self._stop_requested = stop_requested
        self._sleep = sleep
        self._poll_seconds = poll_seconds

    def run(
        self, *, once: bool = False, on_report: Callable[[RunReport], None] | None = None
    ) -> list[RunReport]:
        """處理到要求停止（once：最多處理一個，沒有工作就回來）。"""
        self._fleet.prune()
        reports: list[RunReport] = []
        while not self._stop_requested():
            self._fleet.beat(Capabilities(engines=()))
            batch = self._worker.drain(limit=1 if once else None, on_report=on_report)
            reports.extend(batch)
            if once:
                break
            if not batch:
                self._sleep(self._poll_seconds)
        return reports
