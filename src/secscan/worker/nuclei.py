"""worker 解析 nuclei 的輸出（T18；docs/DECISIONS.md §19.7、§23）：讀檔 → 判定（純函式）→ 入庫。

已經寫入判定就直接用它（重試時輸出可能已不能用，且不能重複寫入）。沒有 volume 或讀不到 manifest 時
沒有輸出可以判斷：OUTPUT_INVALID。匿名掃描：沒有綁定的 auth profile，guard_traffic 不帶 probe。
nuclei 的 budget/牆鐘逾時由 runner 以 BUDGET_EXHAUSTED/TIME_LIMIT 處理（開始收集之前），所以這裡
time_limit_reached 一律 False。
"""

import logging
from collections.abc import Callable
from dataclasses import replace

from secscan.guard.domain.telemetry import RunSummary
from secscan.scanners.domain.nuclei.plan import RESULTS_NAME
from secscan.scanners.domain.nuclei.results import MAX_REPORT_BYTES, NucleiOutput, interpret
from secscan.scans.domain.coverage import Exchange
from secscan.scans.domain.model import Lease
from secscan.scans.domain.observation import ArtifactKind, ArtifactRecord, RunOutcome
from secscan.scans.domain.traffic import guard_traffic
from secscan.scans.queue import ResultContext, ScanQueue
from secscan.worker.artifacts import ArtifactReader, RunManifest
from secscan.worker.telemetry import TelemetryReader

logger = logging.getLogger(__name__)


class NucleiParser:
    def __init__(
        self,
        queue: ScanQueue,
        artifacts: ArtifactReader | None,
        telemetry: TelemetryReader | None,
    ) -> None:
        self._queue = queue
        self._artifacts = artifacts
        self._telemetry = telemetry

    def parse(self, lease: Lease, keepalive: Callable[[], None]) -> RunOutcome:
        context = self._queue.result_context(lease)
        if context.stored is not None:
            return context.stored
        manifest = self._artifacts.manifest(lease.run_id) if self._artifacts is not None else None
        exchanges = summary = None
        if self._telemetry is not None:
            exchanges = self._telemetry.exchanges(lease.run_id)
            summary = _of_scan(self._telemetry.summary(lease.run_id), lease)
        output = self._output(lease, context, manifest, exchanges)
        keepalive()
        traffic = guard_traffic(summary, exchanges, probe=None)
        parsed = replace(interpret(output), traffic=traffic)
        keepalive()
        self._queue.record_results(
            lease,
            parsed,
            _records(manifest),
            exit_code=output.exit_code,
            report_path=RESULTS_NAME,
        )
        return parsed.outcome

    def _output(
        self,
        lease: Lease,
        context: ResultContext,
        manifest: RunManifest | None,
        exchanges: tuple[Exchange, ...] | None,
    ) -> NucleiOutput:
        report = None
        if self._artifacts is not None and manifest is not None:
            report = self._artifacts.read(lease.run_id, RESULTS_NAME, max_bytes=MAX_REPORT_BYTES)
        return NucleiOutput(
            exit_code=manifest.exit_code if manifest is not None else None,
            report=report,
            report_listed=manifest is not None and manifest.lists(RESULTS_NAME),
            origin=context.origin,
            rules=context.rules,
            forwarded=context.requests_sent,
            exchanges=exchanges,
            time_limit_reached=False,
        )


def _of_scan(summary: RunSummary | None, lease: Lease) -> RunSummary | None:
    """guard 的 summary 屬於這個 scan 才使用（檔名已是 run_id，decode 時比對過）。"""
    if summary is not None and summary.scan_id != lease.scan_id:
        logger.warning("run %s 的 summary 屬於其他 scan：不使用", lease.run_id)
        return None
    return summary


def _records(manifest: RunManifest | None) -> tuple[ArtifactRecord, ...]:
    if manifest is None:
        return ()
    inputs = tuple(
        ArtifactRecord(ArtifactKind.INPUT, item.path, item.sha256, item.size)
        for item in manifest.inputs
    )
    outputs = tuple(
        ArtifactRecord(ArtifactKind.OUTPUT, item.path, item.sha256, item.size, item.redactions)
        for item in manifest.files
    )
    return inputs + outputs
