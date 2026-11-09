"""worker 的常駐迴圈（docs/DECISIONS.md §14.6、§14.7）。

每圈寫心跳，處理等待解析的 run，再處理一份報告（T21）。報告內容與人工複測摘錄的到期清除
（docs/DECISIONS.md §30.5）在開始時與之後每 10 分鐘執行一次。
"""

import logging
import time
from collections.abc import Callable

from secscan.scanners.domain.instances import Capabilities
from secscan.scanners.service import Fleet
from secscan.scans.queue import RunReport
from secscan.worker.reports import ReportWorker
from secscan.worker.retention import PURGE_EVERY_SECONDS, ContentRetention
from secscan.worker.service import Worker

logger = logging.getLogger(__name__)


class WorkerLoop:
    def __init__(
        self,
        worker: Worker,
        fleet: Fleet,
        *,
        stop_requested: Callable[[], bool],
        sleep: Callable[[float], None] = time.sleep,
        poll_seconds: float,
        reports: ReportWorker | None = None,
        retention: ContentRetention | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._worker = worker
        self._reports = reports
        self._retention = retention
        self._monotonic = monotonic
        self._purged_at: float | None = None
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
            self._beat()
            self._purge_if_due()
            batch = self._worker.drain(
                limit=1 if once else None, on_report=on_report, on_heartbeat=self._beat
            )
            reports.extend(batch)
            # 每圈先處理 run，再處理一份報告（T21）：解析不會被大量的報告請求餓死。
            generated = self._reports.drain(limit=1) if self._reports is not None else 0
            if once:
                break
            if not batch and not generated:
                self._sleep(self._poll_seconds)
        return reports

    def _purge_if_due(self) -> None:
        if self._retention is None:
            return
        now = self._monotonic()
        if self._purged_at is not None and now - self._purged_at < PURGE_EVERY_SECONDS:
            return
        self._purged_at = now
        purged = self._retention.purge()
        if purged.reports or purged.excerpts:
            logger.info(
                "已清除到期的內容：報告 %s 份、人工複測摘錄 %s 段", purged.reports, purged.excerpts
            )

    def _beat(self) -> None:
        self._fleet.beat(Capabilities(engines=()))
