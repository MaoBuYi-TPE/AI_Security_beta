"""報告的工作佇列（docs/DECISIONS.md §28.5；比照 scans/queue.py 的 SKIP LOCKED 與 fencing）。

- 對帳：lease 過期的 generating，attempts < 3 退回 queued，否則 failed
  （REPORT_ATTEMPTS_EXHAUSTED）。
- 認領：最舊的 queued → generating（attempts +1、寫入 lease）。
- 心跳：仍持有、未過期的 lease 才能延長；否則拋 LeaseLostError。
- 完成：另一個 transaction 先以 SELECT … FOR UPDATE 鎖住仍持有 lease 的 generating 列（fencing），
  再寫入內容並轉成 succeeded；被重新認領的舊 worker 在這一步失敗。即使繞過，commit 時的雙向核對
  （v0018 的 deferred trigger）也會擋下。
"""

import hashlib
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import ColumnElement, func, insert, select, update
from sqlalchemy.orm import Session, sessionmaker

from secscan.reports.domain.model import (
    MAX_ATTEMPTS,
    ReportErrorCode,
    ReportFormat,
    ReportStatus,
)
from secscan.reports.domain.render import Rendered
from secscan.reports.models import ReportContentModel, ReportModel
from secscan.scans.leases import LeaseLostError
from secscan.scans.queue import LEASE_DURATION

__all__ = ["LeaseLostError", "ReportLease", "ReportQueue"]


@dataclass(frozen=True, slots=True)
class ReportLease:
    report_id: UUID
    owner: str
    scan_id: UUID
    format: ReportFormat


def _holds(lease: ReportLease) -> tuple[ColumnElement[bool], ...]:
    return (
        ReportModel.id == lease.report_id,
        ReportModel.lease_owner == lease.owner,
        ReportModel.status == ReportStatus.GENERATING.value,
        ReportModel.lease_expires_at > func.clock_timestamp(),
    )


class ReportQueue:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def reconcile_expired(self) -> int:
        with self._sessions.begin() as session:
            rows = session.execute(
                select(ReportModel.id, ReportModel.attempts)
                .where(
                    ReportModel.status == ReportStatus.GENERATING.value,
                    ReportModel.lease_expires_at <= func.clock_timestamp(),
                )
                .order_by(ReportModel.queue_position)
                .with_for_update(skip_locked=True)
            ).all()
            for row in rows:
                values: dict[str, object] = {
                    "lease_owner": None,
                    "lease_expires_at": None,
                    "heartbeat_at": None,
                }
                if row.attempts < MAX_ATTEMPTS:
                    values["status"] = ReportStatus.QUEUED.value
                else:
                    values |= {
                        "status": ReportStatus.FAILED.value,
                        "error_code": ReportErrorCode.ATTEMPTS_EXHAUSTED.value,
                        "finished_at": func.clock_timestamp(),
                    }
                session.execute(update(ReportModel).where(ReportModel.id == row.id).values(values))
            return len(rows)

    def claim(self, owner: str) -> ReportLease | None:
        with self._sessions.begin() as session:
            row = session.execute(
                select(ReportModel.id, ReportModel.scan_id, ReportModel.format)
                .where(ReportModel.status == ReportStatus.QUEUED.value)
                .order_by(ReportModel.queue_position)
                .limit(1)
                .with_for_update(skip_locked=True)
            ).first()
            if row is None:
                return None
            session.execute(
                update(ReportModel)
                .where(ReportModel.id == row.id)
                .values(
                    status=ReportStatus.GENERATING.value,
                    attempts=ReportModel.attempts + 1,
                    lease_owner=owner,
                    lease_expires_at=func.clock_timestamp() + LEASE_DURATION,
                    heartbeat_at=func.clock_timestamp(),
                )
            )
            return ReportLease(row.id, owner, row.scan_id, ReportFormat(row.format))

    def heartbeat(self, lease: ReportLease) -> None:
        with self._sessions.begin() as session:
            updated = session.execute(
                update(ReportModel)
                .where(*_holds(lease))
                .values(
                    lease_expires_at=func.clock_timestamp() + LEASE_DURATION,
                    heartbeat_at=func.clock_timestamp(),
                )
                .returning(ReportModel.id)
            ).scalar_one_or_none()
        if updated is None:
            raise LeaseLostError("報告的 lease 已過期或不屬於這個 worker")

    def complete(
        self,
        lease: ReportLease,
        rendered: Rendered,
        *,
        data_as_of: datetime,
        generated_at: datetime,
    ) -> None:
        with self._sessions.begin() as session:
            held = session.execute(
                select(ReportModel.id).where(*_holds(lease)).with_for_update()
            ).scalar_one_or_none()
            if held is None:
                raise LeaseLostError("報告的 lease 已過期或不屬於這個 worker：不寫入內容")
            session.execute(
                insert(ReportContentModel).values(
                    report_id=lease.report_id, content=rendered.content
                )
            )
            session.execute(
                update(ReportModel)
                .where(ReportModel.id == lease.report_id)
                .values(
                    status=ReportStatus.SUCCEEDED.value,
                    lease_owner=None,
                    lease_expires_at=None,
                    heartbeat_at=None,
                    data_as_of=data_as_of,
                    generated_at=generated_at,
                    size_bytes=len(rendered.content),
                    sha256=hashlib.sha256(rendered.content).hexdigest(),
                    truncated=rendered.truncated,
                    omitted_findings=rendered.omitted_findings,
                    finished_at=func.clock_timestamp(),
                )
            )
