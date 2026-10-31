"""worker（docs/DECISIONS.md §14.6、§16.5、§19.7）：解析收集好的輸出。

先把 lease 過期的 normalizing 退回 collected（解析不送流量，可以重試；最多 3 次，§17.6），再認領
collected 的 run。單一 run 的非預期例外只記類別、繼續處理其他 run；DB 的錯誤讓程序結束。
- fake：沒有東西可以解析。
- preflight：讀帶認證與匿名的回應，依 §12.5 判斷（scanners.domain.preflight.evaluate），在 run
  結束之前寫入結果。沒有 artifact 的讀取器（in-process）或沒有輸出時是 not_executed。
- coverage（每個 run，§16.6）：guard 記下沒有轉送任何請求 → 已量測、涵蓋 0 個；有轉送而且讀得到
  完整的 telemetry → 對應到 operation；轉送數不明或 telemetry 不完整 → 不標記（沒有量測依據）。
  preflight 是平台的健檢探測，它的請求不算 coverage（已量測、涵蓋 0 個）。已經記錄過就跳過：
  寫入之後、轉成 succeeded 之前中斷，退回 collected 之後重試仍能完成。
- zap（worker/zap.py）：讀輸出、判定（scanners.domain.zap.results）、結果入庫。輸出一律是不可信的
  資料，資料的問題都走判定；已經寫入判定就不再解析。
解析期間依心跳的間隔延長 lease（失效就留給對帳）並寫 fleet 的心跳。不看取消與授權：解析不送流量，
要求取消時解析照常完成，scan 由彙總成為 cancelled。
"""

import logging
import time
import traceback
from collections.abc import Callable
from pathlib import Path

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
from secscan.scans.domain.observation import RunOutcome
from secscan.scans.domain.preflight import PreflightResult
from secscan.scans.queue import HEARTBEAT_INTERVAL, LeaseLostError, RunReport, ScanQueue
from secscan.worker.artifacts import ArtifactReader
from secscan.worker.telemetry import TelemetryReader
from secscan.worker.zap import ZapParser

ENGINES = frozenset({Engine.FAKE, Engine.PREFLIGHT, Engine.ZAP})

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
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._queue = queue
        self._owner = owner
        self._artifacts = artifacts
        self._telemetry = telemetry
        self._engines = engines
        self._monotonic = monotonic
        self._zap = ZapParser(queue, artifacts, telemetry)

    def drain(
        self,
        *,
        limit: int | None = None,
        on_report: Callable[[RunReport], None] | None = None,
        on_heartbeat: Callable[[], None] = lambda: None,
    ) -> list[RunReport]:
        """對帳之後處理所有等待解析的 run（或 limit 個）。"""
        self._queue.reconcile_expired_parsing(self._engines)
        reports: list[RunReport] = []
        while limit is None or len(reports) < limit:
            lease = self._queue.claim_collected(self._owner, self._engines)
            if lease is None:
                break
            try:
                report = self._normalize(lease, self._keepalive(lease, on_heartbeat))
            except LeaseLostError:
                # 解析太久或被對帳退回：這個 run 留給對帳，繼續處理其他的（審查發現：原本整個
                # worker 結束，重啟後又認領同一個 run）。
                logger.warning("run %s 的 lease 已失效：留給對帳", lease.run_id)
                continue
            except SQLAlchemyError:
                raise
            except Exception as exc:  # noqa: BLE001 - 單一 run 的錯誤不讓 worker 結束（§17.6）
                # 輸出是不可信的資料，例外的訊息可能含它的內容：只記類別與最內層的位置。
                # lease 過期之後重試。
                logger.error(
                    "解析 run %s 失敗（%s，%s）：lease 過期之後重試",
                    lease.run_id,
                    type(exc).__name__,
                    _origin(exc),
                )
                continue
            reports.append(report)
            if on_report is not None:
                on_report(report)
        return reports

    def _normalize(self, lease: Lease, keepalive: Callable[[], None]) -> RunReport:
        outcome = RunOutcome(RunStatus.SUCCEEDED)
        if lease.engine is Engine.PREFLIGHT:
            self._queue.record_preflight(lease, self._preflight(lease))
        elif lease.engine is Engine.ZAP:
            outcome = self._zap.parse(lease, keepalive)
        keepalive()
        self._coverage(lease)
        keepalive()
        progress = self._queue.advance(lease, outcome.status, error_code=outcome.error_code)
        return RunReport.of(lease, progress)

    def _keepalive(self, lease: Lease, on_heartbeat: Callable[[], None]) -> Callable[[], None]:
        """步驟之間呼叫：過了心跳的間隔就延長 lease。只看 lease 是否有效（§19.7）。"""
        last_beat = self._monotonic()

        def keepalive() -> None:
            nonlocal last_beat
            moment = self._monotonic()
            if moment - last_beat < HEARTBEAT_INTERVAL.total_seconds():
                return
            last_beat = moment
            if not self._queue.heartbeat(lease).valid:
                raise LeaseLostError("lease 已過期：不再解析，交給對帳處理")
            on_heartbeat()

        return keepalive

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


def _origin(exc: BaseException) -> str:
    """例外最內層的「檔名:行號」（不含訊息與路徑）：確定性的程式錯誤才找得到位置。

    只用於捕捉到的例外，所以一定至少有一層 traceback。
    """
    frame = traceback.extract_tb(exc.__traceback__)[-1]
    return f"{Path(frame.filename).name}:{frame.lineno}"
