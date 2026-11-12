"""隔離目錄的搬移、對帳與解除在 DB 中的轉換（docs/DECISIONS.md §30.13；v0024 的 trigger）。

runner 的 keeper（runner/isolation.py）與 admin 指令使用：

- unresolved：還沒解除的隔離紀錄（最早的在前；搬移指令使用）。unresolved_page：keeper 的對帳分頁，
  隔離中的紀錄先處理（程式碼與安全審查 M1）。overdue：隔離中超過門檻的紀錄（緊急升級）。
- settled：run 已終止、容器已確認刪除，也就是沒有有效的解析 lease（條件和待加密相同）；孤兒目錄
  一律成立。
- record_source（轉換 0）：v0024 之前留下、還沒隔離完成的紀錄記下來源 inode（runs-layout 的搬移
  指令）。
- record_move_failure（轉換 1）：搬不到 held/；次數加 1、記下代碼（時間由 trigger 寫入）。
- mark_isolated（轉換 2）：目錄已搬到 held/，同一個 transaction 寫 audit `evidence.isolated`。
- begin_release（轉換 3）：retry-evidence 已在 held/ 加密並驗證，同一個 transaction 寫 audit
  `evidence.release`。
- note：其他 audit（`evidence.isolation_overdue`、`evidence.reisolated`）。
- summary：retention-status 的「隔離未完成」段落與各階段的數量。

每個轉換都在 WHERE 中寫出前提，條件不成立（另一個程序先改了）時回 False，不靠 trigger 的例外。
時間欄位的值由 trigger 以 clock_timestamp() 取代（不採用用戶端的時間）。
"""

from collections.abc import Collection, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import ColumnElement, exists, func, select, tuple_, update
from sqlalchemy.orm import Session, sessionmaker

from secscan.core.json_types import JsonValue
from secscan.scans.domain.evidence import HoldMoveCode
from secscan.scans.evidence_holds import HeldDirectory, held_directory, hold_audit
from secscan.scans.evidence_models import EvidenceHoldModel
from secscan.scans.evidence_records import run_settled
from secscan.scans.models import ScannerRunModel
from secscan.scans.progress import now

_HOLD = EvidenceHoldModel


@dataclass(frozen=True, slots=True)
class IsolationSummary:
    """還沒解除的隔離各階段的數量；隔離中（明文仍在 active/）的最早幾筆與超過門檻的數量。"""

    isolating: int
    urgent: int
    isolated: int
    releasing: int
    oldest: tuple[HeldDirectory, ...]


class HoldIsolationStore:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def unresolved(self, *, limit: int) -> tuple[HeldDirectory, ...]:
        with self._sessions() as session:
            models = session.scalars(
                select(_HOLD)
                .where(_HOLD.resolved_at.is_(None))
                .order_by(_HOLD.held_at, _HOLD.directory)
                .limit(limit)
            )
            return tuple(held_directory(model) for model in models)

    def unresolved_page(
        self, *, isolating: bool, after: HeldDirectory | None, limit: int
    ) -> tuple[HeldDirectory, ...]:
        """還沒解除的紀錄的一頁（keyset：held_at、directory 之後）；isolating 選隔離中或其他階段。
        keeper 先處理完隔離中的紀錄（明文仍在 active/），已隔離與解除中的紀錄不會擋住它們。"""
        stage = _HOLD.isolated_at.is_(None) if isolating else _HOLD.isolated_at.is_not(None)
        query = select(_HOLD).where(_HOLD.resolved_at.is_(None), stage)
        if after is not None:
            query = query.where(
                tuple_(_HOLD.held_at, _HOLD.directory) > (after.hold.held_at, after.directory)
            )
        with self._sessions() as session:
            models = session.scalars(query.order_by(_HOLD.held_at, _HOLD.directory).limit(limit))
            return tuple(held_directory(model) for model in models)

    def overdue(
        self, *, now: datetime, urgent_after: timedelta, limit: int
    ) -> tuple[HeldDirectory, ...]:
        """隔離中超過門檻的紀錄（最早的在前）：緊急升級直接查 DB，不依賴對帳的批次。"""
        with self._sessions() as session:
            models = session.scalars(
                select(_HOLD)
                .where(
                    _HOLD.resolved_at.is_(None),
                    _HOLD.isolated_at.is_(None),
                    _HOLD.held_at <= now - urgent_after,
                )
                .order_by(_HOLD.held_at, _HOLD.directory)
                .limit(limit)
            )
            return tuple(held_directory(model) for model in models)

    def unresolved_among(self, directories: Collection[UUID]) -> frozenset[UUID]:
        """directories 中有還沒解除的隔離紀錄的目錄。"""
        if not directories:
            return frozenset()
        with self._sessions() as session:
            found = session.scalars(
                select(_HOLD.directory).where(
                    _HOLD.directory.in_(list(directories)), _HOLD.resolved_at.is_(None)
                )
            )
            return frozenset(found)

    def settled(self, held: HeldDirectory) -> bool:
        if held.scanner_run_id is None:
            return True
        with self._sessions() as session:
            return bool(
                session.scalar(
                    select(exists().where(ScannerRunModel.id == held.scanner_run_id, run_settled()))
                )
            )

    def record_source(self, directory: UUID, source_ino: int) -> bool:
        with self._sessions.begin() as session:
            return _changed(
                session,
                directory,
                (_HOLD.source_ino.is_(None), _HOLD.isolated_at.is_(None)),
                {"source_ino": source_ino},
            )

    def record_move_failure(self, directory: UUID, code: HoldMoveCode) -> bool:
        with self._sessions.begin() as session:
            return _changed(
                session,
                directory,
                (_HOLD.isolated_at.is_(None),),
                {
                    "move_failures": _HOLD.move_failures + 1,
                    "last_move_error": code.value,
                    "last_move_failed_at": now(),
                },
            )

    def mark_isolated(self, held: HeldDirectory) -> bool:
        with self._sessions.begin() as session:
            changed = _changed(
                session,
                held.directory,
                (_HOLD.isolated_at.is_(None), _HOLD.source_ino.is_not(None)),
                {"isolated_at": now()},
            )
            if changed:
                hold_audit(
                    session,
                    "evidence.isolated",
                    held.directory,
                    held.scanner_run_id,
                    {"kind": held.kind, "move_failures": held.moves.count},
                )
            return changed

    def begin_release(self, held: HeldDirectory, changes: Mapping[str, JsonValue]) -> bool:
        with self._sessions.begin() as session:
            changed = _changed(
                session,
                held.directory,
                (_HOLD.isolated_at.is_not(None), _HOLD.releasing_at.is_(None)),
                {"releasing_at": now()},
            )
            if changed:
                hold_audit(
                    session,
                    "evidence.release",
                    held.directory,
                    held.scanner_run_id,
                    {"kind": held.kind, **changes},
                )
            return changed

    def note(self, held: HeldDirectory, action: str, changes: Mapping[str, JsonValue]) -> None:
        with self._sessions.begin() as session:
            hold_audit(
                session,
                action,
                held.directory,
                held.scanner_run_id,
                {"kind": held.kind, **changes},
            )

    def summary(self, *, now: datetime, urgent_after: timedelta, listed: int) -> IsolationSummary:
        unresolved = _HOLD.resolved_at.is_(None)
        isolating = _HOLD.isolated_at.is_(None)
        releasing = _HOLD.releasing_at.is_not(None)
        with self._sessions() as session:
            # 還沒解除的條件寫在 WHERE：用得到部分索引 ix_evidence_holds_active（資料庫審查 L1）。
            counts = session.execute(
                select(
                    func.count().filter(isolating),
                    func.count().filter(isolating, _HOLD.held_at <= now - urgent_after),
                    func.count().filter(~isolating, ~releasing),
                    func.count().filter(releasing),
                )
                .select_from(_HOLD)
                .where(unresolved)
            ).one()
            oldest = session.scalars(
                select(_HOLD)
                .where(unresolved, isolating)
                .order_by(_HOLD.held_at, _HOLD.directory)
                .limit(listed)
            )
            return IsolationSummary(
                isolating=int(counts[0]),
                urgent=int(counts[1]),
                isolated=int(counts[2]),
                releasing=int(counts[3]),
                oldest=tuple(held_directory(model) for model in oldest),
            )


def _changed(
    session: Session,
    directory: UUID,
    conditions: tuple[ColumnElement[bool], ...],
    values: Mapping[str, object],
) -> bool:
    """還沒解除、而且符合前提的這一列才更新；回傳是否更新了。"""
    changed = session.scalar(
        update(_HOLD)
        .where(_HOLD.directory == directory, _HOLD.resolved_at.is_(None), *conditions)
        .values(**values)
        .returning(_HOLD.directory)
        .execution_options(synchronize_session=False)
    )
    return changed is not None
