"""需要人工處理的原始證據：人工重試加密與解除隔離（docs/DECISIONS.md §30.12、§30.13）。

在 runner 容器內執行（只有它掛載整個 runs volume、持有 EVIDENCE_ENCRYPTION_KEYS）：

    secscan-admin retry-evidence --directory <目錄名稱> --reason <理由> \\
        [--max-depth <32 到 64>] [--max-entries <20000 到 50000>] \\
        [--max-path-chars <8388608 到 16777216>]

- 只處理已隔離（目錄在 held/）或解除中的紀錄；隔離中（還沒搬到 held/）exit 1
  `EVIDENCE_HOLD_NOT_ISOLATED`，位置和紀錄不符也 exit 1（交給 keeper 對帳），都不做任何改變。
- 和 keeper 以 advisory lock 互斥（等鎖的方式同 rotate-evidence-keys）；執行期間 runner 不認領新的
  run。先寫 audit `evidence.retry`（上限、理由與階段）；寫不進去就不開始。
- 步驟（§30.13）：
  4. 在 held/ 中以指定的上限加密（keeper 的同一條路徑：先驗證才刪除明文；可以重複執行）；
  5. 確認只有加密檔，並逐一解密驗證；
  6. 寫入 releasing_at 與 audit `evidence.release`（已經是解除中就略過）；
  7. 搬回 active/（和隔離相同的搬移步驟：inode 比對、fsync、事後驗證）；
  8. 在 active/ 再驗證一次；不通過就搬回 held/、exit 1；
  9. 同一個 transaction 寫入 sealed 的 run_evidence（run 的目錄）、resolved_at 與 audit
     `evidence.resolve`，之後照常保留到期再清除。
  解除中而目錄已在 active/（第 7 步之後中斷）時從第 8 步開始。
- 失敗時寫 audit `evidence.retry_failed`、exit 1；再執行一次會從正確的步驟繼續。明文只會在 held/
  （worker 讀不到）；active/ 中只會有已驗證的加密檔。
- 上限：整棵樹列在記憶體中，而這個程序和 runner 共用容器的記憶體上限，所以有絕對的上限：深度 64、
  條目 50,000、路徑總長度 16M 字元（最壞約 64 MB）。更大的樹不在系統內處理。
- 刻意不提供：不加密就解除隔離，或刪除目錄的指令。
說明都寫到 stderr，不含路徑或內容。
"""

import argparse
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from secscan.cli.evidence import runner_vault, with_evidence_lock
from secscan.cli.services import EXIT_FAILURE, EXIT_OK, Report, with_database
from secscan.core.config import Settings
from secscan.core.identifiers import canonical_uuid
from secscan.core.json_types import JsonValue
from secscan.core.text import require_text
from secscan.runner.evidence import EvidenceError, EvidenceLimitError, EvidenceVault
from secscan.runner.fs import TreeLimits
from secscan.runner.hold_moves import HoldMoves, MoveError
from secscan.runner.layout import Area
from secscan.scans.domain.evidence import EvidenceHoldCode, HoldStage, SealedEvidence
from secscan.scans.evidence_hold_isolation import HoldIsolationStore
from secscan.scans.evidence_holds import EvidenceHolds, HeldDirectory, HoldNotActiveError
from secscan.scans.evidence_records import EvidenceStore

RETRY_COMMAND = "retry-evidence"
APPLICATION_NAME = "secscan-evidence-cli"
DEFAULT_LIMITS = TreeLimits()
MAX_DEPTH = 64
MAX_ENTRIES = 50_000
MAX_PATH_CHARS = 16 * 1024 * 1024
REASON_MAX_LENGTH = 200
MISSING_DIRECTORY = "EVIDENCE_DIRECTORY_MISSING"
SEALED_NOT_RECORDED = "EVIDENCE_SEALED_NOT_RECORDED"
NOT_ISOLATED = "EVIDENCE_HOLD_NOT_ISOLATED"

type Subparsers = argparse._SubParsersAction[Any]


@dataclass(frozen=True, slots=True)
class _Request:
    directory: UUID
    reason: str
    limits: TreeLimits


@dataclass(frozen=True, slots=True)
class _Outcome:
    exit_code: int
    message: str


def register(commands: Subparsers) -> None:
    parser = commands.add_parser(
        RETRY_COMMAND,
        help="人工重試加密一個需要人工處理的目錄（寫 audit；在 runner 容器內執行）",
        description=(
            "以指定的上限重新加密 retention-status 列出的隔離目錄；加密驗證通過才解除隔離。"
            "失敗時隔離不變、明文保留原狀。沒有不加密就解除或刪除目錄的方式。"
        ),
    )
    parser.add_argument("--directory", required=True, help="retention-status 列出的目錄名稱")
    parser.add_argument(
        "--reason",
        required=True,
        help=f"處置的理由（單行、最多 {REASON_MAX_LENGTH} 字，寫進 audit）",
    )
    parser.add_argument(
        "--max-depth",
        type=_bounded(DEFAULT_LIMITS.max_depth, MAX_DEPTH),
        default=DEFAULT_LIMITS.max_depth,
        help=f"目錄深度的上限（{DEFAULT_LIMITS.max_depth} 到 {MAX_DEPTH}）",
    )
    parser.add_argument(
        "--max-entries",
        type=_bounded(DEFAULT_LIMITS.max_entries, MAX_ENTRIES),
        default=DEFAULT_LIMITS.max_entries,
        help=f"條目數的上限（{DEFAULT_LIMITS.max_entries} 到 {MAX_ENTRIES}）",
    )
    parser.add_argument(
        "--max-path-chars",
        type=_bounded(DEFAULT_LIMITS.max_path_chars, MAX_PATH_CHARS),
        default=DEFAULT_LIMITS.max_path_chars,
        help=f"路徑總字元數的上限（{DEFAULT_LIMITS.max_path_chars} 到 {MAX_PATH_CHARS}）",
    )


def run(args: argparse.Namespace, settings: Settings, report: Report) -> int | None:
    """這個模組的指令；其他指令回傳 None。"""
    if args.command != RETRY_COMMAND:
        return None
    directory = canonical_uuid(args.directory)
    if directory is None:
        report("--directory 必須是標準格式的 UUID（retention-status 列出的目錄名稱）。")
        return EXIT_FAILURE
    try:
        require_text(args.reason, field="--reason", max_length=REASON_MAX_LENGTH)
    except ValueError as exc:
        report(f"{exc}。")
        return EXIT_FAILURE
    if not _utf8(args.reason):
        report("--reason 不可包含無法以 UTF-8 表示的位元組（例如終端的編碼不是 UTF-8）。")
        return EXIT_FAILURE
    limits = TreeLimits(
        max_depth=args.max_depth,
        max_entries=args.max_entries,
        max_path_chars=args.max_path_chars,
    )
    vault = runner_vault(settings, report, limits=limits)
    if vault is None:
        return EXIT_FAILURE
    request = _Request(directory, args.reason, limits)
    return with_database(
        settings,
        report,
        lambda engine: _retry(engine, vault, request, report),
        application_name=APPLICATION_NAME,
    )


def _retry(engine: Engine, vault: EvidenceVault, request: _Request, report: Report) -> int:
    sessions = sessionmaker(engine, expire_on_commit=False)
    store = EvidenceStore(sessions, engine=engine)
    moves = HoldMoves(vault.volume)
    release = _Release(EvidenceHolds(sessions), HoldIsolationStore(sessions), vault, moves, request)
    outcome = with_evidence_lock(store, release.run)
    if outcome is None:
        report("keeper 正在處理原始證據，等不到鎖：請稍後再執行（沒有改變任何檔案）。")
        return EXIT_FAILURE
    report(outcome.message)
    return outcome.exit_code


class _Release:
    """在 held/ 加密並驗證 → 開始解除 → 搬回 active/ → 在 active/ 再驗證 → 解除（§30.13）。
    依 DB 的階段與目錄的位置決定從哪一步開始，中斷之後再執行一次就從正確的步驟繼續。"""

    def __init__(
        self,
        holds: EvidenceHolds,
        isolation: HoldIsolationStore,
        vault: EvidenceVault,
        moves: HoldMoves,
        request: _Request,
    ) -> None:
        self._holds = holds
        self._isolation = isolation
        self._held_vault = vault.in_area(Area.HELD)
        self._active_vault = vault.in_area(Area.ACTIVE)
        self._moves = moves
        self._request = request
        self._limits: dict[str, JsonValue] = {
            "max_depth": request.limits.max_depth,
            "max_entries": request.limits.max_entries,
            "max_path_chars": request.limits.max_path_chars,
        }

    def run(self) -> _Outcome:
        directory = self._request.directory
        held = self._holds.active(directory)
        if held is None:
            return _Outcome(
                EXIT_FAILURE,
                f"目錄 {directory} 沒有需要人工處理的隔離（不存在或已解除）：沒有做任何改變。",
            )
        if held.hold.stage is HoldStage.ISOLATING:
            return _Outcome(
                EXIT_FAILURE,
                f"目錄 {directory} 的隔離還沒完成（{NOT_ISOLATED}；明文可能仍在 active/）："
                "先以 retention-status 查看搬移失敗，等 keeper 搬到 held/ 之後再執行。"
                "沒有做任何改變。",
            )
        try:
            presence = self._moves.presence(held.name)
        except EvidenceError as exc:
            return _Outcome(EXIT_FAILURE, f"無法確認目錄的位置（{exc}）：沒有做任何改變。")
        in_held = presence.held and not presence.active
        resumed = held.hold.stage is HoldStage.RELEASING and presence.active and not presence.held
        if held.source_ino is None or not (in_held or resumed):
            return _Outcome(
                EXIT_FAILURE,
                f"目錄 {directory} 的位置和隔離紀錄不符：交給 keeper 對帳（看 runner 的 log）。"
                "沒有做任何改變。",
            )
        try:
            self._holds.audit(
                held,
                "evidence.retry",
                {
                    "error_code": held.hold.code.value,
                    "reason": self._request.reason,
                    "stage": held.hold.stage.value,
                    **self._limits,
                },
            )
        except SQLAlchemyError as exc:
            return _Outcome(EXIT_FAILURE, f"無法寫入 audit（{type(exc).__name__}）：沒有開始加密。")
        if in_held:
            failure = self._from_held(held, held.source_ino)
            if failure is not None:
                return failure
        return self._finish(held, held.source_ino)

    def _from_held(self, held: HeldDirectory, source_ino: int) -> _Outcome | None:
        """步驟 4 到 7：在 held/ 加密並驗證、記下開始解除、搬回 active/。"""
        name = held.name
        try:
            sealed = self._held_vault.seal(name)
            if sealed is None:
                return _failed(self._holds, held, MISSING_DIRECTORY, "held/ 中沒有這個目錄")
            if verified(self._held_vault, name) != sealed:
                return _failed(self._holds, held, None, "加密檔的數量或大小和加密的結果不符")
        except EvidenceError as exc:
            return _failed(self._holds, held, _code(exc), str(exc))
        if held.hold.stage is HoldStage.ISOLATED:
            try:
                started = self._isolation.begin_release(held, self._limits)
            except SQLAlchemyError as exc:
                return _failed(self._holds, held, None, f"無法記下開始解除（{type(exc).__name__}）")
            if not started:
                return _Outcome(EXIT_FAILURE, "隔離紀錄已被另一次執行改變：請再執行一次。")
        try:
            self._moves.move(name, Area.HELD, Area.ACTIVE, source_ino)
        except EvidenceError as exc:
            return _failed(self._holds, held, _code(exc), f"無法搬回 active/（{exc}）")
        return None

    def _finish(self, held: HeldDirectory, source_ino: int) -> _Outcome:
        """步驟 8 到 9：在 active/ 再驗證，才寫入 run_evidence 與 resolved_at。"""
        name = held.name
        try:
            sealed = verified(self._active_vault, name)
        except EvidenceError as exc:
            note = self._back_to_held(name, source_ino)
            return _failed(self._holds, held, None, f"搬回 active/ 之後驗證不通過（{exc}）{note}")
        try:
            self._holds.resolve(held, sealed, self._limits)
        except HoldNotActiveError:
            note = _unrecorded(self._holds, held, sealed, "這個隔離已由另一次執行解除")
            return _Outcome(
                EXIT_FAILURE, f"已加密，但這個隔離已由另一次執行解除：沒有再寫入。{note}"
            )
        except SQLAlchemyError as exc:
            note = _unrecorded(self._holds, held, sealed, f"DB 寫入失敗（{type(exc).__name__}）")
            return _Outcome(
                EXIT_FAILURE,
                f"已加密、驗證並搬回 active/，但 DB 寫入失敗（{type(exc).__name__}）："
                f"隔離維持解除中（active/ 中只有加密檔）。請再執行一次。{note}",
            )
        return _Outcome(
            EXIT_OK,
            f"已加密 {sealed.files} 個檔案並解除隔離（目錄 {name}）；"
            "之後照常保留到期再清除。這次處置已記入 audit。",
        )

    def _back_to_held(self, name: str, source_ino: int) -> str:
        try:
            self._moves.move(name, Area.ACTIVE, Area.HELD, source_ino)
        except EvidenceError as exc:
            return f"；無法搬回 held/（{exc}），keeper 的對帳會處理"
        return "；已搬回 held/，再執行一次會重新加密"


def verified(vault: EvidenceVault, name: str) -> SealedEvidence:
    """目錄只有加密檔（嚴格的結構檢查），而且每個加密檔都解得開、內容相符；回傳數量與明文大小。"""
    vault.require_sealed_only(name)
    infos = vault.listing(name)
    return SealedEvidence(files=len(infos), plaintext_bytes=sum(info.size for info in infos))


def _failed(holds: EvidenceHolds, held: HeldDirectory, code: str | None, error: str) -> _Outcome:
    note = ""
    try:
        holds.audit(held, "evidence.retry_failed", {"error_code": code, "error": error})
    except SQLAlchemyError as exc:
        note = f"（audit 也無法寫入：{type(exc).__name__}）"
    advice = (
        "可以指定較高的 --max-depth、--max-entries、--max-path-chars 再試；"
        if code in _LIMIT_CODES
        else ""
    )
    return _Outcome(
        EXIT_FAILURE,
        f"仍無法完成（{error}）{note}：隔離沒有解除，明文只會留在 held/（worker 讀不到）。{advice}"
        "再執行一次會從中斷的步驟繼續；更大的樹不在系統內處理，系統不會刪除它。",
    )


def _unrecorded(
    holds: EvidenceHolds, held: HeldDirectory, sealed: SealedEvidence, error: str
) -> str:
    """明文已換成密文、DB 卻沒有記下：另外寫一筆結果的 audit，稽核看得出明文已被處理（安全審查
    L1）。寫不進去時回傳說明。"""
    changes: dict[str, JsonValue] = {
        "error_code": SEALED_NOT_RECORDED,
        "error": error,
        "files": sealed.files,
        "plaintext_bytes": sealed.plaintext_bytes,
    }
    try:
        holds.audit(held, "evidence.retry_failed", changes)
    except SQLAlchemyError as exc:
        return f"（結果的 audit 也無法寫入：{type(exc).__name__}）"
    return ""


def _utf8(text: str) -> bool:
    """argv 以 surrogateescape 解碼：不合法的 UTF-8 會變成孤立的 surrogate，寫進 audit 時才失敗。"""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


_LIMIT_CODES = frozenset(code.value for code in EvidenceHoldCode)


def _code(exc: EvidenceError) -> str | None:
    if isinstance(exc, EvidenceLimitError | MoveError):
        return exc.code.value
    return None


def _bounded(minimum: int, maximum: int) -> Callable[[str], int]:
    def parse(text: str) -> int:
        try:
            value = int(text)
        except ValueError:
            raise argparse.ArgumentTypeError("必須是整數") from None
        if not minimum <= value <= maximum:
            raise argparse.ArgumentTypeError(f"必須在 {minimum} 到 {maximum} 之間")
        return value

    return parse
