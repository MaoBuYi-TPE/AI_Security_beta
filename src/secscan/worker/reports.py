"""報告的 worker（T21；docs/DECISIONS.md §28.5）。報告只讀 DB，不需要 runs volume。

每次：對帳 lease 過期的報告 → 認領最舊的 queued → 在 REPEATABLE READ READ ONLY transaction 中
讀快照（每讀完一頁以另一個短 transaction 心跳）→ 以純函式渲染 → JSON 以 ReportDocumentV1 驗證 →
以 CONTENT_ENCRYPTION_KEYS 加密（context 綁定報告；docs/DECISIONS.md §30.4）→ fenced
transaction 寫入密文與期限（完成時間加 REPORT_RETENTION_DAYS）。單一報告的例外（含這份報告專屬的
DB 錯誤：內容違反 CHECK、核對失敗、快照查詢逾時）只記類別與位置（內容可能含不可信的資料），
立即釋放這一次嘗試（最多 3 次）；
連線中斷等其他 DB 錯誤讓程序結束（沿用 §17.6）。
"""

import logging
import traceback
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from secscan.reports.document_schema import ReportDocumentV1
from secscan.reports.domain.model import MAX_REPORT_BYTES, ReportFormat, report_context
from secscan.reports.domain.render import render
from secscan.reports.queue import LeaseLostError, ReportLease, ReportQueue
from secscan.reports.snapshot import SnapshotReader
from secscan.security.blob_cipher import BlobCipher

logger = logging.getLogger(__name__)
QUERY_CANCELED = "57014"


class ReportWorker:
    def __init__(
        self,
        sessions: sessionmaker[Session],
        *,
        owner: str,
        cipher: BlobCipher,
        retention: timedelta,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._sessions = sessions
        self._queue = ReportQueue(sessions)
        self._owner = owner
        self._cipher = cipher
        self._retention = retention
        self._clock = clock

    def drain(self, *, limit: int | None = None) -> int:
        """對帳之後處理報告（limit 是嘗試的份數，失敗的也算）；回傳完成的數量。"""
        self._queue.reconcile_expired()
        attempted = done = 0
        while limit is None or attempted < limit:
            lease = self._queue.claim(self._owner)
            if lease is None:
                break
            attempted += 1
            try:
                self._generate(lease)
            except LeaseLostError:
                logger.warning("報告 %s 的 lease 已失效：留給對帳", lease.report_id)
                continue
            except SQLAlchemyError as exc:
                if not _report_specific(exc):
                    raise
                self._failed(lease, exc)
                continue
            except Exception as exc:  # noqa: BLE001 - 單一報告的錯誤不讓 worker 結束（§17.6）
                self._failed(lease, exc)
                continue
            done += 1
        return done

    def _failed(self, lease: ReportLease, exc: BaseException) -> None:
        """只記類別與位置（內容可能含不可信的資料），立即釋放 lease。

        退回 queued，或用盡嘗試次數時 failed。
        """
        logger.error(
            "產生報告 %s 失敗（%s，%s）：釋放這一次嘗試",
            lease.report_id,
            type(exc).__name__,
            _origin(exc),
        )
        self._queue.release(lease)

    def _generate(self, lease: ReportLease) -> None:
        with self._sessions() as session:
            session.connection(execution_options={"isolation_level": "REPEATABLE READ"})
            session.execute(text("SET TRANSACTION READ ONLY"))
            snapshot = SnapshotReader(session).read(
                lease.report_id,
                lease.scan_id,
                lease.format,
                on_page=lambda: self._queue.heartbeat(lease),
            )
            session.rollback()
        self._queue.heartbeat(lease)
        generated_at = self._clock()
        rendered = render(snapshot, generated_at=generated_at)
        if lease.format is ReportFormat.JSON:
            ReportDocumentV1.model_validate_json(rendered.content)
        sealed = self._cipher.seal(
            rendered.content, context=report_context(lease.report_id), max_bytes=MAX_REPORT_BYTES
        )
        self._queue.heartbeat(lease)
        self._queue.complete(
            lease,
            rendered,
            sealed=sealed,
            data_as_of=snapshot.data_as_of,
            generated_at=generated_at,
            expires_at=generated_at + self._retention,
        )


def _report_specific(exc: SQLAlchemyError) -> bool:
    """只屬於這一份報告的 DB 錯誤（內容違反 CHECK、commit 時核對失敗、快照查詢逾時）：當成這一次
    嘗試失敗。連線中斷等其他 DB 錯誤仍讓程序結束（§17.6）。"""
    if isinstance(exc, IntegrityError):
        return True
    return isinstance(exc, DBAPIError) and getattr(exc.orig, "sqlstate", None) == QUERY_CANCELED


def _origin(exc: BaseException) -> str:
    frames = traceback.extract_tb(exc.__traceback__)
    if not frames:
        return "-"
    last = frames[-1]
    return f"{last.filename.rsplit('/', 1)[-1]}:{last.lineno}"
