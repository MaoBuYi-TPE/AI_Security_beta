"""報告的 worker（T21；docs/DECISIONS.md §28.5）。報告只讀 DB，不需要 runs volume。

每次：對帳 lease 過期的報告 → 認領最舊的 queued → 在 REPEATABLE READ READ ONLY transaction 中
讀快照（每讀完一頁以另一個短 transaction 心跳）→ 以純函式渲染 → JSON 以 ReportDocumentV1 驗證 →
fenced transaction 寫入內容。單一報告的例外只記類別與位置（內容可能含不可信的資料），等 lease
過期之後重試（最多 3 次）；DB 的錯誤讓程序結束（沿用 §17.6）。
"""

import logging
import traceback
from collections.abc import Callable
from datetime import UTC, datetime

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from secscan.reports.document_schema import ReportDocumentV1
from secscan.reports.domain.model import ReportFormat
from secscan.reports.domain.render import render
from secscan.reports.queue import LeaseLostError, ReportLease, ReportQueue
from secscan.reports.snapshot import SnapshotReader

logger = logging.getLogger(__name__)


class ReportWorker:
    def __init__(
        self,
        sessions: sessionmaker[Session],
        *,
        owner: str,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._sessions = sessions
        self._queue = ReportQueue(sessions)
        self._owner = owner
        self._clock = clock

    def drain(self, *, limit: int | None = None) -> int:
        """對帳之後產生報告（或 limit 份）；回傳完成的數量。"""
        self._queue.reconcile_expired()
        done = 0
        while limit is None or done < limit:
            lease = self._queue.claim(self._owner)
            if lease is None:
                break
            try:
                self._generate(lease)
            except LeaseLostError:
                logger.warning("報告 %s 的 lease 已失效：留給對帳", lease.report_id)
                continue
            except SQLAlchemyError:
                raise
            except Exception as exc:  # noqa: BLE001 - 單一報告的錯誤不讓 worker 結束（§17.6）
                logger.error(
                    "產生報告 %s 失敗（%s，%s）：lease 過期之後重試",
                    lease.report_id,
                    type(exc).__name__,
                    _origin(exc),
                )
                continue
            done += 1
        return done

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
        generated_at = self._clock()
        rendered = render(snapshot, generated_at=generated_at)
        if lease.format is ReportFormat.JSON:
            ReportDocumentV1.model_validate_json(rendered.content)
        self._queue.heartbeat(lease)
        self._queue.complete(
            lease, rendered, data_as_of=snapshot.data_as_of, generated_at=generated_at
        )


def _origin(exc: BaseException) -> str:
    frames = traceback.extract_tb(exc.__traceback__)
    if not frames:
        return "-"
    last = frames[-1]
    return f"{last.filename.rsplit('/', 1)[-1]}:{last.lineno}"
