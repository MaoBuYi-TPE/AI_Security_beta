"""worker 解析 zap 的輸出（docs/DECISIONS.md §19.7）：讀檔 → 判定（純函式）→ 結果入庫。

已經寫入判定就直接用它：解析寫入之後、run 結束之前中斷，重試時輸出可能已不能用，而且不能重複寫入。
沒有 volume 的 worker（in-process）或讀不到 manifest 時沒有輸出可以判斷：OUTPUT_INVALID。
"""

from collections.abc import Callable

from secscan.scanners.domain.zap.report import MAX_REPORT_BYTES
from secscan.scanners.domain.zap.results import ZapOutput, interpret
from secscan.scanners.domain.zap.script import LOG_FILE, REPORT_FILE
from secscan.scans.domain.model import Lease
from secscan.scans.domain.observation import ArtifactKind, ArtifactRecord, RunOutcome
from secscan.scans.queue import ResultContext, ScanQueue
from secscan.worker.artifacts import ArtifactReader, RunManifest
from secscan.worker.telemetry import TelemetryReader

# AF 的進度加上 stderr：正常的情況只有幾 KB。
MAX_LOG_BYTES = 8 * 1024 * 1024


class ZapParser:
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
        output = self._output(lease, context, manifest)
        keepalive()
        parsed = interpret(output)
        keepalive()
        self._queue.record_results(
            lease,
            parsed,
            _records(manifest),
            exit_code=output.exit_code,
            report_path=REPORT_FILE,
        )
        return parsed.outcome

    def _output(
        self, lease: Lease, context: ResultContext, manifest: RunManifest | None
    ) -> ZapOutput:
        report = log = None
        if self._artifacts is not None and manifest is not None:
            report = self._artifacts.read(lease.run_id, REPORT_FILE, max_bytes=MAX_REPORT_BYTES)
            log = self._artifacts.read(lease.run_id, LOG_FILE, max_bytes=MAX_LOG_BYTES)
        exchanges = self._telemetry.exchanges(lease.run_id) if self._telemetry is not None else None
        return ZapOutput(
            exit_code=manifest.exit_code if manifest is not None else None,
            report=report,
            report_listed=manifest is not None and manifest.lists(REPORT_FILE),
            log=log,
            origin=context.origin,
            rules=context.rules,
            forwarded=context.requests_sent,
            exchanges=exchanges,
        )


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
