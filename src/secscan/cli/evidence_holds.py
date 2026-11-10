"""需要人工處理的原始證據：人工重試加密（docs/DECISIONS.md §30.12）。

在 runner 容器內執行（只有它掛載 runs volume、持有 EVIDENCE_ENCRYPTION_KEYS）：

    secscan-admin retry-evidence --directory <目錄名稱> --reason <理由> \\
        [--max-depth <32 到 64>] [--max-entries <20000 到 50000>]

- 只處理還沒解除的隔離（retention-status 列出的目錄名稱）；沒有就 exit 1、不做任何改變。
- 和 keeper 以 advisory lock 互斥（等鎖的方式同 rotate-evidence-keys）；執行期間 runner 不認領新的
  run。
- 先寫 audit `evidence.retry`（上限與理由）；寫不進去就不開始。
- 以指定的上限加密，走 keeper 的同一條路徑（先驗證才刪除明文）。成功時在同一個 transaction 寫入
  sealed 的 run_evidence（run 的目錄）、resolved_at 與 audit `evidence.resolve`，之後照常保留到期
  再清除。
- 失敗時（仍然超過上限、其他錯誤、目錄不存在）寫 audit `evidence.retry_failed`，隔離不變、明文保留
  原狀，exit 1。目錄不存在不會記成「沒有目錄」。
- 加密完成、DB 寫入失敗：提示再執行一次（加密可以重複執行）；記下之前維持隔離。
- 上限：整棵樹列在記憶體中，而這個程序和 runner 共用容器的記憶體上限，所以最多深度 64、條目 50,000；
  更大的樹不在系統內處理。
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
from secscan.scans.domain.evidence import EvidenceHoldCode
from secscan.scans.evidence_holds import EvidenceHolds, HeldDirectory, HoldNotActiveError
from secscan.scans.evidence_records import EvidenceStore

RETRY_COMMAND = "retry-evidence"
APPLICATION_NAME = "secscan-evidence-cli"
DEFAULT_LIMITS = TreeLimits()
MAX_DEPTH = 64
MAX_ENTRIES = 50_000
REASON_MAX_LENGTH = 200
MISSING_DIRECTORY = "EVIDENCE_DIRECTORY_MISSING"

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
    limits = TreeLimits(max_depth=args.max_depth, max_entries=args.max_entries)
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
    holds = EvidenceHolds(sessions)
    outcome = with_evidence_lock(store, lambda: _retry_locked(holds, vault, request))
    if outcome is None:
        report("keeper 正在處理原始證據，等不到鎖：請稍後再執行（沒有改變任何檔案）。")
        return EXIT_FAILURE
    report(outcome.message)
    return outcome.exit_code


def _retry_locked(holds: EvidenceHolds, vault: EvidenceVault, request: _Request) -> _Outcome:
    held = holds.active(request.directory)
    if held is None:
        return _Outcome(
            EXIT_FAILURE,
            f"目錄 {request.directory} 沒有需要人工處理的隔離（不存在或已解除）：沒有做任何改變。",
        )
    limits: dict[str, JsonValue] = {
        "max_depth": request.limits.max_depth,
        "max_entries": request.limits.max_entries,
    }
    try:
        holds.audit(
            held,
            "evidence.retry",
            {"error_code": held.hold.code.value, "reason": request.reason, **limits},
        )
    except SQLAlchemyError as exc:
        return _Outcome(EXIT_FAILURE, f"無法寫入 audit（{type(exc).__name__}）：沒有開始加密。")
    try:
        sealed = vault.seal(str(request.directory))
    except EvidenceError as exc:
        return _failed(holds, held, _code(exc), str(exc))
    if sealed is None:
        return _failed(holds, held, MISSING_DIRECTORY, "runs volume 中沒有這個目錄")
    try:
        holds.resolve(held, sealed, limits)
    except HoldNotActiveError:
        return _Outcome(EXIT_FAILURE, "已加密，但這個隔離已由另一次執行解除：沒有再寫入。")
    except SQLAlchemyError as exc:
        return _Outcome(
            EXIT_FAILURE,
            f"已加密並驗證，但 DB 寫入失敗（{type(exc).__name__}）：隔離維持不變。"
            "請再執行一次（加密可以重複執行）。",
        )
    return _Outcome(
        EXIT_OK,
        f"已加密 {sealed.files} 個檔案並解除隔離（目錄 {request.directory}）；"
        "之後照常保留到期再清除。這次處置已記入 audit。",
    )


def _failed(holds: EvidenceHolds, held: HeldDirectory, code: str | None, error: str) -> _Outcome:
    note = ""
    try:
        holds.audit(held, "evidence.retry_failed", {"error_code": code, "error": error})
    except SQLAlchemyError as exc:
        note = f"（audit 也無法寫入：{type(exc).__name__}）"
    advice = "可以指定較高的 --max-depth、--max-entries 再試；" if code in _LIMIT_CODES else ""
    return _Outcome(
        EXIT_FAILURE,
        f"仍無法加密（{error}）{note}：隔離不變，明文保留原狀。{advice}"
        "更大的樹不在系統內處理，系統不會刪除它。",
    )


_LIMIT_CODES = frozenset(code.value for code in EvidenceHoldCode)


def _code(exc: EvidenceError) -> str | None:
    return exc.code.value if isinstance(exc, EvidenceLimitError) else None


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
