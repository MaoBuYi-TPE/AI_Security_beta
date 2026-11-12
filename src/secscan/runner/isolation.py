"""隔離目錄的機密性隔離：搬到 held/ 與對帳（docs/DECISIONS.md §30.13）。

keeper 每一輪在加密與清除之前（含啟動之後的第一輪）、持有 evidence advisory lock 時呼叫 reconcile。
不變條件：
- I1：已隔離 ⇒ 目錄不在 active/。
- I2：解除中 ⇒ 目錄如果在 active/，只含加密檔；明文只可能在 held/。
- I3：隔離中是唯一允許明文留在 active/ 的未解除狀態，一律看得見並計時。

每個還沒解除的隔離紀錄，依 DB 的階段與目錄的位置（active/、held/）處理：
- 隔離中：只在 active/ → 確認沒有有效的解析 lease，搬到 held/，再寫 isolated_at；只在 held/（搬移
  之後、寫 DB 之前中斷）→ 確認身分（真的目錄、同一個裝置、inode 等於 source_ino）、fsync 兩個區域，
  才補寫 isolated_at；兩邊都有是衝突，都沒有是遺失：記下搬移失敗。
- 已隔離：只在 held/ 是正常；只在 active/（違反 I1）→ 搬回 held/、ERROR、audit
  `evidence.reisolated`。
- 解除中：只在 held/，或在 active/ 而且只有加密檔（結構檢查）→ 解除待完成（WARNING，retry-evidence
  再執行一次就完成）；在 active/ 而含明文或結構不符（違反 I2）→ 搬回 held/。
- 已隔離或解除中，兩邊都有或都沒有：ERROR。
- held/ 中沒有對應紀錄的目錄：ERROR `EVIDENCE_HELD_UNKNOWN`；held/ 的條目超過上限：全域
  fail closed。
對帳絕不自動解除、不記成 none、sealed 或 purged，也不刪除任何目錄。

失敗只讓這個目錄退避（`isolate:<名稱>`，和 keeper 的退避分開），keeper 維持健康、其他 run 照常；
隔離中的失敗寫進 DB（retention-status 看得見）。隔離中的紀錄先處理、分頁到全部完成（已隔離與解除
中的紀錄不會擋住它們）。隔離中超過 ISOLATION_URGENT_AFTER 就升級為緊急狀態：每一輪直接查 DB，
CRITICAL log 與 audit `evidence.isolation_overdue`（每個程序對每個目錄一次）。主動告警是 T35。
log 只含目錄名稱與代碼，不含路徑或內容。
"""

import logging
import time
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError

from secscan.core.json_types import JsonValue
from secscan.runner.backoff import Backoff
from secscan.runner.evidence import DirectoryState
from secscan.runner.hold_moves import HoldMoves, MoveError
from secscan.runner.layout import Area
from secscan.runner.sealed_files import EvidenceError
from secscan.scans.domain.evidence import ISOLATION_URGENT_AFTER, HoldMoveCode, HoldStage
from secscan.scans.evidence_holds import HeldDirectory

logger = logging.getLogger(__name__)

_BATCH = 500
UNKNOWN_HELD = "EVIDENCE_HELD_UNKNOWN"


class IsolationStore(Protocol):
    """DB 的部分（scans.evidence_hold_isolation.HoldIsolationStore）。"""

    def unresolved_page(
        self, *, isolating: bool, after: HeldDirectory | None, limit: int
    ) -> tuple[HeldDirectory, ...]: ...

    def overdue(
        self, *, now: datetime, urgent_after: timedelta, limit: int
    ) -> tuple[HeldDirectory, ...]: ...

    def unresolved_among(self, directories: Collection[UUID]) -> frozenset[UUID]: ...

    def settled(self, held: HeldDirectory) -> bool: ...

    def record_move_failure(self, directory: UUID, code: HoldMoveCode) -> bool: ...

    def mark_isolated(self, held: HeldDirectory) -> bool: ...

    def note(self, held: HeldDirectory, action: str, changes: Mapping[str, JsonValue]) -> None: ...


class Inspector(Protocol):
    """active/ 的結構檢查（runner.evidence.EvidenceVault.inspect）。"""

    def inspect(self, name: str) -> DirectoryState | None: ...


@dataclass(slots=True)
class IsolationReport:
    isolated: int = 0
    reisolated: int = 0
    failures: int = 0
    urgent: int = 0


class HoldIsolation:
    def __init__(
        self,
        store: IsolationStore,
        moves: HoldMoves,
        active: Inspector,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        monotonic: Callable[[], float] = time.monotonic,
        interval_seconds: float = 10.0,
        urgent_after: timedelta = ISOLATION_URGENT_AFTER,
    ) -> None:
        self._store = store
        self._moves = moves
        self._active = active
        self._clock = clock
        self._monotonic = monotonic
        self._urgent_after = urgent_after
        self._backoff = Backoff(interval_seconds, monotonic)
        self._overdue_noted: set[UUID] = set()
        self._pending_noted: set[UUID] = set()
        self._unknown_noted: set[str] = set()
        self._unaudited: dict[UUID, HeldDirectory] = {}
        self._others_noted = 0

    def reconcile(self, deadline: float) -> IsolationReport:
        """隔離中的紀錄先處理（明文仍在 active/），再處理其他階段；分頁到全部完成或時間用完。
        緊急升級直接查 DB，不受批次與時間的影響（程式碼與安全審查 M1）。"""
        report = IsolationReport()
        seen: set[str] = set()
        self._flush_audits()
        for isolating in (True, False):
            if not self._pages(isolating, deadline, seen, report):
                break
        self._escalate(report)
        self._unknown(seen)
        return report

    def _pages(
        self, isolating: bool, deadline: float, seen: set[str], report: IsolationReport
    ) -> bool:
        """一個階段的所有頁；時間用完時回 False。"""
        after: HeldDirectory | None = None
        while True:
            page = self._store.unresolved_page(isolating=isolating, after=after, limit=_BATCH)
            for held in page:
                if self._monotonic() > deadline:
                    return False
                seen.add(held.name)
                self._one(held, report)
            if len(page) < _BATCH:
                return True
            after = page[-1]

    # --- 每個隔離紀錄 ----------------------------------------------------------------------

    def _one(self, held: HeldDirectory, report: IsolationReport) -> None:
        key = f"isolate:{held.name}"
        if key in self._backoff.waiting():
            return
        try:
            self._dispatch(held, report)
            self._backoff.clear(key)
        except MoveError as exc:
            self._failed(held, key, exc, report)
        except SQLAlchemyError as exc:
            report.failures += 1
            self._backoff.failed(key, exc)
            logger.error("隔離的目錄 %s：DB 錯誤（%s），稍後重試", held.name, type(exc).__name__)

    def _dispatch(self, held: HeldDirectory, report: IsolationReport) -> bool:
        """處理一個隔離紀錄；隔離中的目錄這一次完成隔離時回 True。"""
        stage = held.hold.stage
        if stage is HoldStage.ISOLATING:
            return self._isolating(held, report)
        presence = self._moves.presence(held.name)
        if presence.active and presence.held:
            raise MoveError(HoldMoveCode.CONFLICT, "active/ 與 held/ 都有這個目錄")
        if not presence.active and not presence.held:
            raise MoveError(HoldMoveCode.DIRECTORY_MISSING, "active/ 與 held/ 都沒有這個目錄")
        if stage is HoldStage.ISOLATED:
            if presence.active:
                self._reisolate(held, report, "已隔離的目錄出現在 active/（違反 I1）")
            return False
        if presence.held:
            self._pending(held, "retry-evidence 還沒搬回 active/")
        elif self._only_sealed(held.name):
            self._pending(held, "已搬回 active/、還沒記下解除：再執行一次 retry-evidence")
        else:
            self._reisolate(held, report, "解除中的目錄在 active/ 含明文或結構不符（違反 I2）")
        return False

    def _isolating(self, held: HeldDirectory, report: IsolationReport) -> bool:
        source_ino = held.source_ino
        if source_ino is None:
            if held.directory not in self._pending_noted:
                self._pending_noted.add(held.directory)
                logger.error(
                    "隔離中的目錄 %s 沒有來源 inode（v0024 之前留下）：不搬移、不補寫，"
                    "請執行 make runs-layout-migrate",
                    held.name,
                )
            return False
        presence = self._moves.presence(held.name)
        if presence.active and presence.held:
            raise MoveError(HoldMoveCode.CONFLICT, "active/ 與 held/ 都有這個目錄")
        if not presence.active and not presence.held:
            raise MoveError(HoldMoveCode.DIRECTORY_MISSING, "active/ 與 held/ 都沒有這個目錄")
        if presence.active:
            if not self._store.settled(held):
                logger.warning("目錄 %s 還有有效的解析 lease：這一輪不搬移", held.name)
                return False
            self._moves.move(held.name, Area.ACTIVE, Area.HELD, source_ino)
        else:
            # 搬移之後、寫 DB 之前中斷：先確認身分並讓目錄項目落盤，才補寫。
            self._moves.identify(held.name, Area.HELD, source_ino)
            self._moves.settle()
        if not self._store.mark_isolated(held):
            return False
        report.isolated += 1
        logger.info("目錄 %s 已隔離（搬到 held/，worker 讀不到）", held.name)
        return True

    def _reisolate(self, held: HeldDirectory, report: IsolationReport, why: str) -> None:
        if held.source_ino is None:
            raise MoveError(HoldMoveCode.CONFLICT, "沒有來源 inode，無法確認身分")
        self._moves.move(held.name, Area.ACTIVE, Area.HELD, held.source_ino)
        report.reisolated += 1
        logger.error("目錄 %s：%s；已搬回 held/", held.name, why)
        self._unaudited[held.directory] = held
        self._flush_audits()

    def _flush_audits(self) -> None:
        """重新隔離的 audit：寫入失敗時留到下一輪再寫（目錄已在 held/，不會再觸發；審查 L2）。"""
        for directory, held in list(self._unaudited.items()):
            try:
                self._store.note(held, "evidence.reisolated", {"stage": held.hold.stage.value})
            except SQLAlchemyError as exc:
                logger.error(
                    "目錄 %s 的重新隔離無法寫入 audit（%s）：下一輪再寫",
                    held.name,
                    type(exc).__name__,
                )
                return
            del self._unaudited[directory]

    def _only_sealed(self, name: str) -> bool:
        try:
            state = self._active.inspect(name)
        except EvidenceError:
            return False
        return state is not None and not state.plaintext

    def _pending(self, held: HeldDirectory, why: str) -> None:
        if held.directory in self._pending_noted:
            return
        self._pending_noted.add(held.directory)
        logger.warning("目錄 %s 解除待完成（%s）", held.name, why)

    def _failed(
        self, held: HeldDirectory, key: str, exc: MoveError, report: IsolationReport
    ) -> None:
        report.failures += 1
        attempt = self._backoff.failed(key, exc)
        delay = attempt.retry_at - self._monotonic()
        stage = held.hold.stage
        logger.error(
            "隔離的目錄 %s 無法處理（%s，%s）：其他 run 照常，%.0f 秒後重試",
            held.name,
            exc.code.value,
            stage.value,
            delay,
        )
        if stage is not HoldStage.ISOLATING:
            return
        try:
            self._store.record_move_failure(held.directory, exc.code)
        except SQLAlchemyError as error:
            logger.error("目錄 %s 的搬移失敗無法記下（%s）", held.name, type(error).__name__)

    def _escalate(self, report: IsolationReport) -> None:
        """隔離中超過門檻：CRITICAL log 與 audit（每個程序對每個目錄一次）；主動告警是 T35。"""
        now = self._clock()
        for held in self._store.overdue(now=now, urgent_after=self._urgent_after, limit=_BATCH):
            report.urgent += 1
            if held.directory in self._overdue_noted:
                continue
            minutes = int((now - held.hold.held_at).total_seconds() // 60)
            logger.critical(
                "目錄 %s 隔離中已 %s 分鐘：明文仍在 active/、worker 可能讀得到，需要緊急處理"
                "（retention-status）",
                held.name,
                minutes,
            )
            last = held.moves.last_code
            try:
                self._store.note(
                    held,
                    "evidence.isolation_overdue",
                    {
                        "minutes": minutes,
                        "move_failures": held.moves.count,
                        "last_move_error": None if last is None else last.value,
                    },
                )
            except SQLAlchemyError as exc:
                logger.error(
                    "目錄 %s 的緊急事件無法寫入 audit（%s）", held.name, type(exc).__name__
                )
                continue
            self._overdue_noted.add(held.directory)

    # --- held/ 中沒有紀錄的目錄 ------------------------------------------------------------

    def _unknown(self, seen: set[str]) -> None:
        listing = self._moves.held_entries()
        if listing.others != self._others_noted:
            self._others_noted = listing.others
            if listing.others:
                logger.error("held/ 中有 %s 個不是隔離目錄的條目", listing.others)
        names = [
            name
            for name in listing.directories
            if name not in seen and name not in self._unknown_noted
        ]
        for start in range(0, len(names), _BATCH):
            batch = names[start : start + _BATCH]
            known = self._store.unresolved_among([UUID(name) for name in batch])
            for name in batch:
                if UUID(name) not in known:
                    self._unknown_noted.add(name)
                    logger.error(
                        "held/ 中的目錄 %s 沒有還沒解除的隔離紀錄（%s）", name, UNKNOWN_HELD
                    )
