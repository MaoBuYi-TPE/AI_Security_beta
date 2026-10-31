"""worker 解析 zap 的輸出（docs/DECISIONS.md §19.7）：讀檔 → 判定（純函式）→ 結果入庫。

已經寫入判定就直接用它：解析寫入之後、run 結束之前中斷，重試時輸出可能已不能用，而且不能重複寫入。
沒有 volume 的 worker（in-process）或讀不到 manifest 時沒有輸出可以判斷：OUTPUT_INVALID。
guard 的 summary 與 telemetry 的明細（§20.3）不論判定都一起寫入：telemetry 之後會被刪除。
"""

import logging
from collections.abc import Callable
from dataclasses import replace

from secscan.scanners.domain.zap.report import MAX_REPORT_BYTES
from secscan.scanners.domain.zap.results import ZapOutput, interpret
from secscan.scanners.domain.zap.script import LOG_FILE, REPORT_FILE
from secscan.scans.domain.model import Lease
from secscan.scans.domain.observation import ArtifactKind, ArtifactRecord, RunOutcome
from secscan.scans.domain.traffic import guard_traffic
from secscan.scans.queue import ResultContext, ScanQueue
from secscan.worker.artifacts import ArtifactReader, RunManifest
from secscan.worker.evidence import TelemetryEvidence

# AF 的進度加上 stderr：正常的情況只有幾 KB。
MAX_LOG_BYTES = 8 * 1024 * 1024

logger = logging.getLogger(__name__)


class ZapParser:
    def __init__(
        self,
        queue: ScanQueue,
        artifacts: ArtifactReader | None,
    ) -> None:
        self._queue = queue
        self._artifacts = artifacts

    def parse(
        self,
        lease: Lease,
        keepalive: Callable[[], None],
        *,
        context: ResultContext,
        evidence: TelemetryEvidence,
    ) -> RunOutcome:
        if context.stored is not None:
            return context.stored
        manifest = self._artifacts.manifest(lease.run_id) if self._artifacts is not None else None
        output = self._output(lease, context, manifest, evidence)
        keepalive()
        traffic = guard_traffic(
            evidence.summary, evidence.exchanges, probe=self._probe(lease), trusted=evidence.trusted
        )
        parsed = replace(interpret(output), traffic=traffic)
        keepalive()
        self._queue.record_results(
            lease,
            parsed,
            _records(manifest),
            exit_code=output.exit_code,
            report_path=REPORT_FILE,
        )
        return parsed.outcome

    def _probe(self, lease: Lease) -> tuple[str, str] | None:
        """綁定的 auth profile 的 preflight 端點：已知需要認證（§20.4）。"""
        preflight = self._queue.bound_preflight(lease)
        return None if preflight is None else (preflight.method, preflight.path)

    def _output(
        self,
        lease: Lease,
        context: ResultContext,
        manifest: RunManifest | None,
        evidence: TelemetryEvidence,
    ) -> ZapOutput:
        report = log = None
        if self._artifacts is not None and manifest is not None:
            report = self._artifacts.read(lease.run_id, REPORT_FILE, max_bytes=MAX_REPORT_BYTES)
            log = self._artifacts.read(lease.run_id, LOG_FILE, max_bytes=MAX_LOG_BYTES)
        return ZapOutput(
            exit_code=manifest.exit_code if manifest is not None else None,
            report=report,
            report_listed=manifest is not None and manifest.lists(REPORT_FILE),
            log=log,
            origin=context.origin,
            rules=context.rules,
            policy_version=context.policy_version,
            forwarded=context.requests_sent,
            exchanges=evidence.exchanges,
            telemetry_trusted=evidence.trusted,
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
