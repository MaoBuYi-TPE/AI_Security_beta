"""原始證據的紀錄與逾期的轉換（docs/DECISIONS.md §30.3、§30.5）。

runner 的 keeper 與 admin 指令使用：

- 逾期：第一次進入 collected 起算（看 run.status 事件；不用最後一次，否則每次重試都重新
  計時），超過期限仍在 collected，或在 normalizing 而 lease 已過期 → failed
  （PARSE_DEADLINE_EXCEEDED）。先鎖 scan 再鎖 run（和佇列相同的順序），鎖住之後重新確認條件，
  同一個 transaction 重算 scan 的狀態。
  之後 worker 以舊 lease 寫入都會被 lease 的檢查擋下；已經存好的部分結果保留。
- 待加密：已終止，而且沒有容器或容器已確認刪除（之後沒有任何程序會再寫這個目錄），還沒有紀錄。
- 待清除：sealed 而且加密時間早於保留期限。
- keeper 處理檔案時與 rotate-evidence-keys 以 advisory lock 互斥（session 層級：transaction 結束之後
  仍持有，連線閒置時不會被 idle_in_transaction 的逾時中止）。
- 時間（now）由呼叫端傳入，測試可以注入；DB 寫入的時間仍用 statement_timestamp()。
"""

from collections.abc import Collection, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import ColumnElement, Engine, and_, exists, func, insert, or_, select, update
from sqlalchemy.orm import Session, sessionmaker

from secscan.scans.domain.evidence import EvidenceStatus, SealedEvidence
from secscan.scans.domain.lifecycle import TERMINAL_RUN_STATUSES, RunErrorCode, RunStatus
from secscan.scans.domain.model import EventType
from secscan.scans.evidence_models import RunEvidenceModel
from secscan.scans.models import ScanEventModel, ScannerRunModel
from secscan.scans.progress import ScanProgress, now

# pg_advisory_lock 的鍵（任意固定的 64 位元整數；"secscan evidence" 的前 8 bytes）。
EVIDENCE_LOCK_KEY = 0x73656373_63616E65


@dataclass(frozen=True, slots=True)
class EvidenceRun:
    run_id: UUID
    scan_id: UUID


@dataclass(frozen=True, slots=True)
class EvidenceSummary:
    """retention-status 的數量（不含任何路徑或內容）。"""

    in_progress: int
    overdue: int
    pending: int
    none: int
    sealed: int
    due: int
    purged: int


class EvidenceStore:
    def __init__(self, sessions: sessionmaker[Session], *, engine: Engine) -> None:
        self._sessions = sessions
        self._engine = engine

    # --- 逾期 ------------------------------------------------------------------------------

    def overdue(self, *, now: datetime, max_minutes: int, limit: int) -> tuple[EvidenceRun, ...]:
        with self._sessions() as session:
            rows = session.execute(
                select(ScannerRunModel.id, ScannerRunModel.scan_id)
                .where(_overdue(now, max_minutes))
                .order_by(ScannerRunModel.created_at, ScannerRunModel.id)
                .limit(limit)
            )
            return tuple(EvidenceRun(row.id, row.scan_id) for row in rows)

    def expire(self, run: EvidenceRun, *, now: datetime, max_minutes: int) -> bool:
        """鎖住之後條件仍成立才轉成 failed；條件已改變（worker 先完成、已退回…）時回 False。"""
        with self._sessions.begin() as session:
            progress = ScanProgress(session)
            scan = progress.lock_scan(run.scan_id)
            if scan is None:
                return False
            state = progress.run(run.run_id, conditions=(_overdue(now, max_minutes),))
            if state is None:
                return False
            progress.move(
                scan, state, RunStatus.FAILED, error_code=RunErrorCode.PARSE_DEADLINE_EXCEEDED
            )
            progress.settle(scan)
            return True

    # --- 加密 ------------------------------------------------------------------------------

    def sealable(self, *, limit: int) -> tuple[EvidenceRun, ...]:
        with self._sessions() as session:
            rows = session.execute(
                select(ScannerRunModel.id, ScannerRunModel.scan_id)
                .where(_settled(), ~_recorded())
                .order_by(ScannerRunModel.finished_at, ScannerRunModel.id)
                .limit(limit)
            )
            return tuple(EvidenceRun(row.id, row.scan_id) for row in rows)

    def record(self, run: EvidenceRun, sealed: SealedEvidence | None) -> bool:
        """記下加密完成（sealed）或從來沒有目錄（None）；已經有紀錄時不動，回 False。"""
        values: dict[str, object] = {
            "scanner_run_id": run.run_id,
            "scan_id": run.scan_id,
            "status": (EvidenceStatus.NONE if sealed is None else EvidenceStatus.SEALED).value,
            "file_count": 0 if sealed is None else sealed.files,
            "plaintext_bytes": 0 if sealed is None else sealed.plaintext_bytes,
            "sealed_at": None if sealed is None else now(),
        }
        with self._sessions.begin() as session:
            if session.get(RunEvidenceModel, run.run_id) is not None:
                return False
            session.execute(insert(RunEvidenceModel).values(**values))
            return True

    # --- 清除 ------------------------------------------------------------------------------

    def purgeable(
        self, *, now: datetime, retention_days: int, limit: int
    ) -> tuple[EvidenceRun, ...]:
        with self._sessions() as session:
            rows = session.execute(
                select(RunEvidenceModel.scanner_run_id, RunEvidenceModel.scan_id)
                .where(_due(now, retention_days))
                .order_by(RunEvidenceModel.sealed_at, RunEvidenceModel.scanner_run_id)
                .limit(limit)
            )
            return tuple(EvidenceRun(row.scanner_run_id, row.scan_id) for row in rows)

    def record_purged(self, run: EvidenceRun) -> bool:
        with self._sessions.begin() as session:
            purged = session.scalar(
                update(RunEvidenceModel)
                .where(
                    RunEvidenceModel.scanner_run_id == run.run_id,
                    RunEvidenceModel.status == EvidenceStatus.SEALED.value,
                )
                .values(status=EvidenceStatus.PURGED.value, purged_at=now())
                .returning(RunEvidenceModel.scanner_run_id)
                .execution_options(synchronize_session=False)
            )
            return purged is not None

    # --- 其他 ------------------------------------------------------------------------------

    def known(self, run_ids: Collection[UUID]) -> frozenset[UUID]:
        """有 scanner_runs 紀錄的 run（其餘的目錄是孤兒，例如舊的 probe）。"""
        if not run_ids:
            return frozenset()
        with self._sessions() as session:
            found = session.scalars(
                select(ScannerRunModel.id).where(ScannerRunModel.id.in_(list(run_ids)))
            )
            return frozenset(found)

    def sealed_runs(self) -> tuple[EvidenceRun, ...]:
        """所有 sealed 的 run（換版用）。"""
        with self._sessions() as session:
            rows = session.execute(
                select(RunEvidenceModel.scanner_run_id, RunEvidenceModel.scan_id)
                .where(RunEvidenceModel.status == EvidenceStatus.SEALED.value)
                .order_by(RunEvidenceModel.scanner_run_id)
            )
            return tuple(EvidenceRun(row.scanner_run_id, row.scan_id) for row in rows)

    def summary(self, *, now: datetime, retention_days: int, max_minutes: int) -> EvidenceSummary:
        with self._sessions() as session:

            def count(*conditions: ColumnElement[bool]) -> int:
                return int(session.scalar(select(func.count()).where(*conditions)) or 0)

            def recorded(status: EvidenceStatus) -> int:
                return int(
                    session.scalar(
                        select(func.count())
                        .select_from(RunEvidenceModel)
                        .where(RunEvidenceModel.status == status.value)
                    )
                    or 0
                )

            terminal = ScannerRunModel.status.in_(sorted(s.value for s in TERMINAL_RUN_STATUSES))
            return EvidenceSummary(
                in_progress=count(~terminal),
                overdue=count(_overdue(now, max_minutes)),
                pending=count(terminal, ~_recorded()),
                none=recorded(EvidenceStatus.NONE),
                sealed=recorded(EvidenceStatus.SEALED),
                due=int(
                    session.scalar(
                        select(func.count())
                        .select_from(RunEvidenceModel)
                        .where(_due(now, retention_days))
                    )
                    or 0
                ),
                purged=recorded(EvidenceStatus.PURGED),
            )

    @contextmanager
    def exclusive(self) -> Iterator[bool]:
        """嘗試取得處理檔案的 advisory lock（不等待）；yield 是否取得。離開時釋放。"""
        with self._engine.connect() as connection:
            acquired = bool(connection.scalar(select(func.pg_try_advisory_lock(EVIDENCE_LOCK_KEY))))
            connection.commit()
            try:
                yield acquired
            finally:
                if acquired:
                    connection.scalar(select(func.pg_advisory_unlock(EVIDENCE_LOCK_KEY)))
                    connection.commit()


def _first_collected() -> ColumnElement[datetime]:
    return (
        select(func.min(ScanEventModel.created_at))
        .where(
            ScanEventModel.scan_id == ScannerRunModel.scan_id,
            ScanEventModel.scanner_run_id == ScannerRunModel.id,
            ScanEventModel.event_type == EventType.RUN_STATUS.value,
            ScanEventModel.payload["status"].astext == RunStatus.COLLECTED.value,
        )
        .scalar_subquery()
    )


def _overdue(now: datetime, max_minutes: int) -> ColumnElement[bool]:
    waiting = or_(
        ScannerRunModel.status == RunStatus.COLLECTED.value,
        and_(
            ScannerRunModel.status == RunStatus.NORMALIZING.value,
            ScannerRunModel.lease_expires_at <= func.clock_timestamp(),
        ),
    )
    return and_(waiting, _first_collected() <= now - timedelta(minutes=max_minutes))


def _settled() -> ColumnElement[bool]:
    """已終止，而且沒有容器或容器已確認刪除。"""
    return and_(
        ScannerRunModel.status.in_(sorted(status.value for status in TERMINAL_RUN_STATUSES)),
        or_(
            ScannerRunModel.container_name.is_(None),
            ScannerRunModel.container_removed_at.is_not(None),
        ),
    )


def _recorded() -> ColumnElement[bool]:
    return exists().where(RunEvidenceModel.scanner_run_id == ScannerRunModel.id)


def _due(now: datetime, retention_days: int) -> ColumnElement[bool]:
    return and_(
        RunEvidenceModel.status == EvidenceStatus.SEALED.value,
        RunEvidenceModel.sealed_at <= now - timedelta(days=retention_days),
    )
