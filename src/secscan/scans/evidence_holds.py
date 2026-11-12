"""需要人工處理的原始證據（docs/DECISIONS.md §30.12）：evidence_holds 的寫入、查詢、解除與數量。

- hold：keeper 對同一個目錄連續 HOLD_AFTER_FAILURES 次超過上限時寫入；同一個 transaction 寫 audit
  `evidence.hold`（actor 是 null；run 的目錄帶 project）。DB 的 trigger 再確認 run 已終止、容器已
  確認刪除、還沒有 run_evidence；孤兒目錄沒有 scanner_runs 紀錄。
- held：隔離中的目錄（keeper 跳過隔離的孤兒；隔離的 run 由 evidence_records 在 SQL 中排除）。
- active、audit、resolve：`secscan-admin retry-evidence` 讀還沒解除的隔離、寫 audit；加密成功之後
  在同一個 transaction 中寫入 sealed 的 run_evidence（run 的目錄）、resolved_at 與 audit
  `evidence.resolve`。trigger 要求 run 已有 sealed 的紀錄，所以不可能沒有加密就解除。
- summary：retention-status 的數量與最早的幾筆（目錄名稱、種類、代碼、次數與時間，不含路徑）。
隔離的搬移（held/）、對帳與解除的轉換在 evidence_hold_isolation.py（§30.13）。
"""

from collections.abc import Collection, Mapping
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import func, insert, select, update
from sqlalchemy.orm import Session, sessionmaker

from secscan.audit.service import AuditTrail
from secscan.core.json_types import JsonValue
from secscan.scans.domain.evidence import (
    EvidenceHold,
    EvidenceHoldCode,
    EvidenceStatus,
    HoldMoveCode,
    SealedEvidence,
)
from secscan.scans.evidence_models import EvidenceHoldModel, RunEvidenceModel, evidence_hold
from secscan.scans.models import ScanModel, ScannerRunModel
from secscan.scans.progress import now

HOLD_OBJECT_TYPE = "evidence_hold"
RUN_KIND = "run"
ORPHAN_KIND = "orphan"


class HoldNotActiveError(Exception):
    """這個目錄沒有還沒解除的隔離（不存在，或已經解除）。"""


@dataclass(frozen=True, slots=True)
class MoveFailures:
    """搬不到 held/ 的次數、最近一次的代碼與時間（§30.13）。"""

    count: int = 0
    last_code: HoldMoveCode | None = None
    last_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class HeldDirectory:
    """一個隔離中的目錄：run 的目錄有 scanner_run_id 與 scan_id（就是目錄名稱），孤兒目錄沒有。
    source_ino 是隔離之前記下的來源目錄 inode（v0024 之前留下的紀錄沒有）。"""

    directory: UUID
    scanner_run_id: UUID | None
    scan_id: UUID | None
    hold: EvidenceHold
    source_ino: int | None = None
    moves: MoveFailures = MoveFailures()

    @property
    def kind(self) -> str:
        return ORPHAN_KIND if self.scanner_run_id is None else RUN_KIND

    @property
    def name(self) -> str:
        """runs volume 中的目錄名稱。"""
        return str(self.directory)


@dataclass(frozen=True, slots=True)
class HoldSummary:
    """還沒解除的隔離（run 與孤兒目錄的數量、各錯誤代碼的數量）、已解除的數量與最早的幾筆。"""

    runs: int
    orphans: int
    by_code: Mapping[EvidenceHoldCode, int]
    resolved: int
    oldest: tuple[HeldDirectory, ...]


class EvidenceHolds:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def hold(
        self,
        directory: UUID,
        scan_id: UUID | None,
        code: EvidenceHoldCode,
        attempts: int,
        source_ino: int,
    ) -> None:
        """scan_id 是 None 代表孤兒目錄；否則 directory 就是 run_id。source_ino 是 active/ 中這個
        目錄的 inode（隔離的搬移與對帳以它確認身分；§30.13）。"""
        run_id = None if scan_id is None else directory
        with self._sessions.begin() as session:
            session.execute(
                insert(EvidenceHoldModel).values(
                    directory=directory,
                    scanner_run_id=run_id,
                    scan_id=scan_id,
                    error_code=code.value,
                    attempts=attempts,
                    source_ino=source_ino,
                )
            )
            hold_audit(
                session,
                "evidence.hold",
                directory,
                run_id,
                {
                    "kind": ORPHAN_KIND if run_id is None else RUN_KIND,
                    "error_code": code.value,
                    "attempts": attempts,
                },
            )

    def held(self, directories: Collection[UUID]) -> frozenset[UUID]:
        if not directories:
            return frozenset()
        with self._sessions() as session:
            found = session.scalars(
                select(EvidenceHoldModel.directory).where(
                    EvidenceHoldModel.directory.in_(list(directories)),
                    EvidenceHoldModel.resolved_at.is_(None),
                )
            )
            return frozenset(found)

    def active(self, directory: UUID) -> HeldDirectory | None:
        with self._sessions() as session:
            model = session.scalar(
                select(EvidenceHoldModel).where(
                    EvidenceHoldModel.directory == directory,
                    EvidenceHoldModel.resolved_at.is_(None),
                )
            )
            return None if model is None else _held(model)

    def resolve(
        self, held: HeldDirectory, sealed: SealedEvidence, changes: Mapping[str, JsonValue]
    ) -> None:
        """加密已驗證之後解除；隔離已經不在（另一次執行先解除了）時拋出 HoldNotActiveError、
        整個 transaction 回滾。先鎖住還沒解除的隔離：另一次執行同時解除時，這裡等它 commit、重新
        確認之後拿不到，不會撞上 run_evidence 的主鍵而誤報成 DB 錯誤（資料庫審查 L1）。"""
        with self._sessions.begin() as session:
            locked = session.scalar(
                select(EvidenceHoldModel.directory)
                .where(
                    EvidenceHoldModel.directory == held.directory,
                    EvidenceHoldModel.resolved_at.is_(None),
                )
                .with_for_update()
            )
            if locked is None:
                raise HoldNotActiveError("這個目錄已經不在隔離中")
            if held.scanner_run_id is not None:
                session.execute(
                    insert(RunEvidenceModel).values(
                        scanner_run_id=held.scanner_run_id,
                        scan_id=held.scan_id,
                        status=EvidenceStatus.SEALED.value,
                        file_count=sealed.files,
                        plaintext_bytes=sealed.plaintext_bytes,
                        sealed_at=now(),
                    )
                )
            # resolved_at 的值由 trigger 以 clock_timestamp() 取代（不採用用戶端的時間）。
            session.execute(
                update(EvidenceHoldModel)
                .where(EvidenceHoldModel.directory == held.directory)
                .values(resolved_at=now())
                .execution_options(synchronize_session=False)
            )
            hold_audit(
                session,
                "evidence.resolve",
                held.directory,
                held.scanner_run_id,
                {
                    "kind": held.kind,
                    "files": sealed.files,
                    "plaintext_bytes": sealed.plaintext_bytes,
                    **changes,
                },
            )

    def audit(self, held: HeldDirectory, action: str, changes: Mapping[str, JsonValue]) -> None:
        """retry-evidence 的 audit（evidence.retry、evidence.retry_failed）；run 帶 project。"""
        with self._sessions.begin() as session:
            hold_audit(
                session, action, held.directory, held.scanner_run_id, {"kind": held.kind, **changes}
            )

    def summary(self, *, listed: int) -> HoldSummary:
        active = EvidenceHoldModel.resolved_at.is_(None)
        is_run = EvidenceHoldModel.scanner_run_id.is_not(None)
        with self._sessions() as session:
            runs, orphans, resolved = session.execute(
                select(
                    func.count().filter(active, is_run),
                    func.count().filter(active, ~is_run),
                    func.count().filter(~active),
                ).select_from(EvidenceHoldModel)
            ).one()
            by_code = session.execute(
                select(EvidenceHoldModel.error_code, func.count())
                .where(active)
                .group_by(EvidenceHoldModel.error_code)
            )
            oldest = session.scalars(
                select(EvidenceHoldModel)
                .where(active)
                .order_by(EvidenceHoldModel.held_at, EvidenceHoldModel.directory)
                .limit(listed)
            )
            return HoldSummary(
                runs=int(runs),
                orphans=int(orphans),
                by_code={EvidenceHoldCode(code): int(count) for code, count in by_code},
                resolved=int(resolved),
                oldest=tuple(_held(model) for model in oldest),
            )


def _held(model: EvidenceHoldModel) -> HeldDirectory:
    return held_directory(model)


def held_directory(model: EvidenceHoldModel) -> HeldDirectory:
    error = model.last_move_error
    return HeldDirectory(
        model.directory,
        model.scanner_run_id,
        model.scan_id,
        evidence_hold(model),
        source_ino=model.source_ino,
        moves=MoveFailures(
            count=model.move_failures,
            last_code=None if error is None else HoldMoveCode(error),
            last_at=model.last_move_failed_at,
        ),
    )


def hold_audit(
    session: Session,
    action: str,
    directory: UUID,
    run_id: UUID | None,
    changes: Mapping[str, JsonValue],
) -> None:
    project_id = None
    if run_id is not None:
        project_id = session.scalar(
            select(ScanModel.project_id)
            .join(ScannerRunModel, ScannerRunModel.scan_id == ScanModel.id)
            .where(ScannerRunModel.id == run_id)
        )
    AuditTrail(session).record(
        action=action,
        object_type=HOLD_OBJECT_TYPE,
        object_id=directory,
        actor_key_id=None,
        project_id=project_id,
        request_id=None,
        changes=changes,
    )
