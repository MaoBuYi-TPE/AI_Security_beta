"""報告測試的共用工具：加密好的內容與帶著測試金鑰的 worker（docs/DECISIONS.md §30.4）。"""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy.orm import Session, sessionmaker

from secscan.reports.domain.model import MAX_REPORT_BYTES, report_context
from secscan.reports.domain.render import Rendered
from secscan.reports.queue import ReportLease, ReportQueue
from secscan.worker.reports import ReportWorker
from tests.secret_support import shared_content_cipher

RETENTION = timedelta(days=30)


def seal(lease: ReportLease, rendered: Rendered) -> bytes:
    return shared_content_cipher().seal(
        rendered.content, context=report_context(lease.report_id), max_bytes=MAX_REPORT_BYTES
    )


def complete(queue: ReportQueue, lease: ReportLease, rendered: Rendered, *, at: datetime) -> None:
    """以測試的內容金鑰加密，寫入內容並轉成 succeeded（期限是 at 加 30 天）。"""
    queue.complete(
        lease,
        rendered,
        sealed=seal(lease, rendered),
        data_as_of=at,
        generated_at=at,
        expires_at=at + RETENTION,
    )


def report_worker(
    sessions: sessionmaker[Session],
    *,
    owner: str,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> ReportWorker:
    return ReportWorker(
        sessions, owner=owner, cipher=shared_content_cipher(), retention=RETENTION, clock=clock
    )


def opened(report_id: object, token: bytes) -> bytes:
    """DB 中的密文 → 明文（測試核對內容用；context 綁定這份報告）。"""
    return shared_content_cipher().unseal(
        bytes(token), context=report_context(UUID(str(report_id))), max_bytes=MAX_REPORT_BYTES
    )
