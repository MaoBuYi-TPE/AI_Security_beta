"""容器的紀錄：runner 內的對帳找待處理的容器並結算（docs/DECISIONS.md §17.2、§17.4）。

- 待處理：記下了容器、還沒確認刪除，而且不是「runner 階段且 lease 還有效」（owner 還在處理）。
- 結算（確認容器已不存在之後）：先鎖 scan、再鎖 run（和認領、prepare、取消相同的順序），重新確認
  仍待處理，記下 container_removed_at；仍在 runner 階段（lease 已過期）→ interrupted
  （LEASE_EXPIRED），用量留空。其他狀態只記下時間。
- 在呼叫端的 transaction 中執行（ScanQueue 每個操作一個短 transaction）。
"""

from collections.abc import Collection
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import ColumnElement, and_, func, or_, select, update
from sqlalchemy.orm import Session

from secscan.scans.domain.lifecycle import RUNNER_STAGE_RUN_STATUSES, RunErrorCode, RunStatus
from secscan.scans.models import ScannerRunModel
from secscan.scans.progress import ScanProgress, now


@dataclass(frozen=True, slots=True)
class PendingContainer:
    run_id: UUID
    scan_id: UUID
    name: str


def leased() -> ColumnElement[bool]:
    """lease 還有效（owner 仍可能在處理這個 run）。"""
    return and_(
        ScannerRunModel.lease_owner.is_not(None),
        ScannerRunModel.lease_expires_at > func.clock_timestamp(),
    )


def awaiting_removal() -> ColumnElement[bool]:
    """記下了容器、還沒確認刪除，而且 owner 不再處理（docs/DECISIONS.md §17.2）。"""
    runner_stage = ScannerRunModel.status.in_(sorted(RUNNER_STAGE_RUN_STATUSES))
    return and_(
        ScannerRunModel.container_name.is_not(None),
        ScannerRunModel.container_removed_at.is_(None),
        ~and_(runner_stage, leased()),
    )


class ContainerRecords:
    def __init__(self, session: Session) -> None:
        self._session = session
        self._progress = ScanProgress(session)

    def pending(self, limit: int) -> tuple[PendingContainer, ...]:
        """依建立的順序，最多 limit 個（部分索引 ix_scanner_runs_pending_containers）。"""
        rows = self._session.execute(
            select(ScannerRunModel.id, ScannerRunModel.scan_id, ScannerRunModel.container_name)
            .where(awaiting_removal())
            .order_by(ScannerRunModel.created_at, ScannerRunModel.id)
            .limit(limit)
        )
        return tuple(
            PendingContainer(run_id=row.id, scan_id=row.scan_id, name=row.container_name)
            for row in rows
        )

    def settle(self, run_id: UUID) -> bool:
        """容器已確認不存在：記下時間，runner 階段的 run 標成 interrupted。

        條件已經改變（另一個對帳者先結算、run 不存在）時不動，回 False。
        """
        scan_id = self._session.scalar(
            select(ScannerRunModel.scan_id).where(ScannerRunModel.id == run_id)
        )
        if scan_id is None:
            return False
        scan = self._progress.lock_scan(scan_id)
        run = self._progress.run(run_id, conditions=(awaiting_removal(),))
        if scan is None or run is None:
            return False
        self._session.execute(
            update(ScannerRunModel)
            .where(ScannerRunModel.id == run_id)
            .values(container_removed_at=now())
            .execution_options(synchronize_session=False)
        )
        if run.status in RUNNER_STAGE_RUN_STATUSES:
            self._progress.move(
                scan, run, RunStatus.INTERRUPTED, error_code=RunErrorCode.LEASE_EXPIRED
            )
            self._progress.settle(scan)
        return True

    def unsettled(self, run_ids: Collection[UUID]) -> frozenset[UUID]:
        """啟動時的清理要跳過的 run：容器還沒確認刪除，或 lease 還有效（§17.4）。"""
        if not run_ids:
            return frozenset()
        in_use = or_(
            and_(
                ScannerRunModel.container_name.is_not(None),
                ScannerRunModel.container_removed_at.is_(None),
            ),
            leased(),
        )
        found = self._session.scalars(
            select(ScannerRunModel.id).where(ScannerRunModel.id.in_(run_ids), in_use)
        )
        return frozenset(found)
