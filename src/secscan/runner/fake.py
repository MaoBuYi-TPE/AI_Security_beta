"""fake 引擎的 runner（docs/DECISIONS.md §13.7）。

不連任何位址、不啟動容器：結果由腳本決定（成功或失敗），可以在 running 停留一段時間，期間定期
心跳、檢查取消。它同時扮演 worker：收集之後認領自己這個 collected 的 run 完成解析。
每一步都經過佇列的轉換與事件；回應中這些 scan 的 fixture 為 true。
"""

import time
from collections.abc import Callable

from secscan.scanners.domain.fake import FakeOutcome, FakeScript
from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.domain.model import Lease
from secscan.scans.domain.preflight import PreflightResult
from secscan.scans.queue import (
    HEARTBEAT_INTERVAL,
    Heartbeat,
    LeaseLostError,
    Progress,
    RunReport,
    ScanQueue,
)

# preflight 的 run 也在這裡處理：in-process 不送任何流量，結果一律 not_executed（§16.5）。
ENGINES = frozenset({Engine.FAKE, Engine.PREFLIGHT})


class FakeRunner:
    def __init__(
        self,
        queue: ScanQueue,
        *,
        owner: str,
        script: FakeScript,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._queue = queue
        self._owner = owner
        self._script = script
        self._sleep = sleep
        self._monotonic = monotonic

    def reconcile(self) -> int:
        """lease 過期的 fake run：fake 不發流量，lease 過期就可以確定它已停止。"""
        return self._queue.reconcile_expired(ENGINES)

    def drain(
        self,
        *,
        limit: int | None = None,
        on_report: Callable[[RunReport], None] | None = None,
    ) -> list[RunReport]:
        """先解析留下的 collected，再處理排隊中的 run，直到沒有工作（或處理了 limit 個）。"""
        reports: list[RunReport] = []

        def keep(report: RunReport) -> None:
            reports.append(report)
            if on_report is not None:
                on_report(report)

        for parsed in self.normalize_collected():
            keep(parsed)
        processed = 0
        while limit is None or processed < limit:
            ran = self.run_once()
            if ran is None:
                break
            keep(ran)
            processed += 1
        return reports

    def normalize_collected(self) -> list[RunReport]:
        """worker 的工作：解析所有等待中的 fake run（例如解析中斷、對帳退回 collected 的）。"""
        reports = []
        while (lease := self._queue.claim_collected(self._owner, ENGINES)) is not None:
            reports.append(self._normalize(lease))
        return reports

    def run_once(self) -> RunReport | None:
        """處理一個排隊中的 fake run；沒有工作時回 None。lease 失效時拋出 LeaseLostError。"""
        lease = self._queue.claim(self._owner, ENGINES)
        if lease is None:
            return None
        progress = self._queue.prepare(lease)
        if progress.run_status is RunStatus.CANCELLING:
            return self._advance(lease, RunStatus.CANCELLED)
        if progress.run_status is not RunStatus.RUNNING:
            return _report(lease, progress)
        if lease.engine is Engine.PREFLIGHT:
            return self._collect(lease)
        held = self._hold(lease)
        if held.cancel_requested:
            self._queue.advance(lease, RunStatus.CANCELLING)
            return self._advance(lease, RunStatus.CANCELLED)
        if held.stop_reason is not None:
            # 授權撤回（docs/DECISIONS.md §17.5）。
            return self._advance(lease, RunStatus.FAILED, held.stop_reason)
        if self._script.outcome is FakeOutcome.FAIL:
            return self._advance(lease, RunStatus.FAILED, RunErrorCode.ENGINE_FAILED)
        return self._collect(lease)

    def _collect(self, lease: Lease) -> RunReport:
        self._queue.advance(lease, RunStatus.COLLECTING)
        collected = self._advance(lease, RunStatus.COLLECTED)
        parsing = self._queue.claim_collected(self._owner, ENGINES, run_id=lease.run_id)
        if parsing is None:
            return collected
        return self._normalize(parsing)

    def _normalize(self, lease: Lease) -> RunReport:
        if lease.engine is Engine.PREFLIGHT:
            self._queue.record_preflight(lease, PreflightResult.NOT_EXECUTED)
        return self._advance(lease, RunStatus.SUCCEEDED)

    def _hold(self, lease: Lease) -> Heartbeat:
        """在 running 停留 hold_seconds，每 5 秒以內心跳一次；被要求取消或授權撤回時提早回傳那次
        心跳。
        """
        deadline = self._monotonic() + self._script.hold_seconds
        while (remaining := deadline - self._monotonic()) > 0:
            self._sleep(min(HEARTBEAT_INTERVAL.total_seconds(), remaining))
            heartbeat = self._queue.heartbeat(lease)
            if not heartbeat.valid:
                raise LeaseLostError("lease 已過期：停止執行，交給對帳處理")
            if heartbeat.cancel_requested or heartbeat.stop_reason is not None:
                return heartbeat
        return Heartbeat(valid=True, cancel_requested=False)

    def _advance(
        self, lease: Lease, to: RunStatus, error_code: RunErrorCode | None = None
    ) -> RunReport:
        return _report(lease, self._queue.advance(lease, to, error_code=error_code))


def _report(lease: Lease, progress: Progress) -> RunReport:
    return RunReport.of(lease, progress)
