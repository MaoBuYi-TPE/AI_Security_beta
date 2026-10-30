"""worker（docs/DECISIONS.md §14.6、§16.5）：解析收集好的輸出。

先把 lease 過期的 normalizing 退回 collected（解析不送流量，可以重試；最多 3 次，§17.6），再認領
collected 的 run。單一 run 的非預期例外只記類別、繼續處理其他 run；DB 的錯誤讓程序結束。
- fake：沒有東西可以解析。
- preflight：讀帶認證與匿名的回應，依 §12.5 判斷（scanners.domain.preflight.evaluate），在 run
  結束之前寫入結果。沒有 artifact 的讀取器（in-process）或沒有輸出時是 not_executed。
- coverage（每個 run，§16.6）：guard 記下沒有轉送任何請求 → 已量測、涵蓋 0 個；有轉送而且讀得到
  完整的 telemetry → 對應到 operation；轉送數不明或 telemetry 不完整 → 不標記（沒有量測依據）。
  preflight 是平台的健檢探測，它的請求不算 coverage（已量測、涵蓋 0 個）。已經記錄過就跳過：
  寫入之後、轉成 succeeded 之前中斷，退回 collected 之後重試仍能完成。
M3 起依引擎呼叫 parser（輸出一律當成不可信的資料）。
"""

import logging
from collections.abc import Callable

from sqlalchemy.exc import SQLAlchemyError

from secscan.scanners.domain.preflight import (
    ANONYMOUS_OUTPUT,
    AUTHENTICATED_OUTPUT,
    MAX_RESPONSE_BYTES,
    evaluate,
)
from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.coverage import observed_operations
from secscan.scans.domain.lifecycle import RunStatus
from secscan.scans.domain.model import Lease
from secscan.scans.domain.preflight import PreflightResult
from secscan.scans.queue import LeaseLostError, RunReport, ScanQueue
from secscan.worker.artifacts import ArtifactReader
from secscan.worker.telemetry import TelemetryReader

ENGINES = frozenset({Engine.FAKE, Engine.PREFLIGHT})

logger = logging.getLogger(__name__)


class Worker:
    def __init__(
        self,
        queue: ScanQueue,
        *,
        owner: str,
        artifacts: ArtifactReader | None = None,
        telemetry: TelemetryReader | None = None,
        engines: frozenset[Engine] = ENGINES,
    ) -> None:
        self._queue = queue
        self._owner = owner
        self._artifacts = artifacts
        self._telemetry = telemetry
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
            try:
                report = self._normalize(lease)
            except LeaseLostError:
                # 解析太久或被對帳退回：這個 run 留給對帳，繼續處理其他的（審查發現：原本整個
                # worker 結束，重啟後又認領同一個 run）。
                logger.warning("run %s 的 lease 已失效：留給對帳", lease.run_id)
                continue
            except SQLAlchemyError:
                raise
            except Exception as exc:  # noqa: BLE001 - 單一 run 的錯誤不讓 worker 結束（§17.6）
                # 輸出是不可信的資料，例外的訊息可能含它的內容：只記類別。lease 過期之後重試。
                logger.error(
                    "解析 run %s 失敗（%s）：lease 過期之後重試", lease.run_id, type(exc).__name__
                )
                continue
            reports.append(report)
            if on_report is not None:
                on_report(report)
        return reports

    def _normalize(self, lease: Lease) -> RunReport:
        if lease.engine is Engine.PREFLIGHT:
            self._queue.record_preflight(lease, self._preflight(lease))
        self._coverage(lease)
        return RunReport.of(lease, self._queue.advance(lease, RunStatus.SUCCEEDED))

    def _preflight(self, lease: Lease) -> PreflightResult:
        definition = self._queue.bound_preflight(lease)
        if definition is None or self._artifacts is None:
            return PreflightResult.NOT_EXECUTED
        authenticated, anonymous = (
            self._artifacts.read(lease.run_id, name, max_bytes=MAX_RESPONSE_BYTES)
            for name in (AUTHENTICATED_OUTPUT, ANONYMOUS_OUTPUT)
        )
        return evaluate(definition, authenticated, anonymous)

    def _coverage(self, lease: Lease) -> None:
        inputs = self._queue.coverage_inputs(lease)
        if inputs.recorded:
            return
        if lease.engine is Engine.PREFLIGHT or inputs.requests_sent == 0:
            self._queue.record_coverage(lease, {})
            return
        if inputs.requests_sent is None or self._telemetry is None:
            return
        exchanges = self._telemetry.exchanges(lease.run_id)
        # summary 先寫、行後寫：中途失敗時行數可能比轉送數少一個，但不會更多（§16.3）。
        if exchanges is None or len(exchanges) > inputs.requests_sent:
            return
        self._queue.record_coverage(lease, observed_operations(inputs.operations, exchanges))
