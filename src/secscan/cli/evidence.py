"""原始證據的管理指令（docs/DECISIONS.md §30.3、§30.5、§30.6）。

在 runner 容器內執行（只有它掛載 runs volume、持有 EVIDENCE_ENCRYPTION_KEYS）：

    secscan-admin rotate-evidence-keys
    secscan-admin export-evidence --run <run_id> [--path <run 目錄中的相對路徑>]

在主機或任何能連 DB 的地方執行（只讀，不需要任何金鑰）：

    uv run secscan-admin retention-status

- rotate-evidence-keys：以第一個金鑰重新加密每個加密檔（驗證之後才取代；可以中斷後重跑）。和 keeper
  以 advisory lock 互斥：換版期間 keeper 不加密、不清除，runner 不認領新的 run。audit 只記數量。
- export-evidence（break-glass）：沒有 --path 時列出加密檔的原本路徑、大小與 sha256；有 --path 時
  先完整驗證，再寫入 audit（寫不進去就不匯出），最後才把明文寫到 stdout。不寫任何檔案。
- retention-status：pending、逾期、已加密、待清除與已清除的數量；不含路徑或內容。
說明都寫到 stderr。
"""

import argparse
import hashlib
import json
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy import Engine, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from secscan.audit.service import AuditTrail
from secscan.cli.services import EXIT_FAILURE, EXIT_OK, NOT_READY, Report
from secscan.core.config import Settings
from secscan.core.db import DatabaseStatus, create_db_engine, probe_database
from secscan.migrations import head_revision
from secscan.runner.config import RunnerSettings
from secscan.runner.evidence import EvidenceError, EvidenceVault
from secscan.scans.evidence_records import EvidenceStore
from secscan.scans.models import ScanModel, ScannerRunModel
from secscan.security.key_rings import EVIDENCE_SETTING, evidence_cipher
from secscan.security.secret_cipher import InvalidEncryptionKeysError

ROTATE_COMMAND = "rotate-evidence-keys"
EXPORT_COMMAND = "export-evidence"
STATUS_COMMAND = "retention-status"
COMMANDS = (ROTATE_COMMAND, EXPORT_COMMAND, STATUS_COMMAND)
APPLICATION_NAME = "secscan-evidence-cli"
# 取得 advisory lock 的嘗試（keeper 每一輪最多持有 30 秒，之間會釋放）。
LOCK_ATTEMPTS = 90
LOCK_WAIT_SECONDS = 1.0
MAX_LISTED = 10

type Subparsers = argparse._SubParsersAction[Any]


def register(commands: Subparsers) -> None:
    commands.add_parser(
        ROTATE_COMMAND,
        help="以 EVIDENCE_ENCRYPTION_KEYS 的第一個金鑰重新加密原始證據（在 runner 容器內執行）",
        description=(
            "以 EVIDENCE_ENCRYPTION_KEYS 的第一個金鑰重新加密 runs volume 中每個加密檔，驗證之後才"
            "取代；可以中斷後重跑。換版期間 runner 不認領新的 run。"
        ),
    )
    export = commands.add_parser(
        EXPORT_COMMAND,
        help="列出或匯出一個 run 的原始證據（break-glass；寫 audit；在 runner 容器內執行）",
        description=(
            "沒有 --path 時列出加密檔的原本路徑、大小與 sha256；有 --path 時完整驗證、"
            "寫入 audit 之後才把明文寫到 stdout。不寫任何檔案。"
        ),
    )
    export.add_argument("--run", required=True, type=UUID, help="run 的 id")
    export.add_argument(
        "--path", default=None, help="run 目錄中的相對路徑（例如 out/zap-report.json）"
    )
    commands.add_parser(
        STATUS_COMMAND,
        help="列出原始證據、報告與摘錄的保留狀態（只有數量）",
        description="列出 pending、逾期、已加密、待清除與已清除的數量；不含路徑或內容。",
    )


def run(args: argparse.Namespace, settings: Settings, report: Report) -> int | None:
    """這個模組的指令；其他指令回傳 None。"""
    if args.command == STATUS_COMMAND:
        return _with_database(settings, report, lambda engine: _status(engine, settings, report))
    if args.command not in (ROTATE_COMMAND, EXPORT_COMMAND):
        return None
    try:
        runner_settings = RunnerSettings()
        cipher = evidence_cipher(_setting(settings))
    except ValidationError:
        report("設定不正確（RUNNER_* 環境變數）。")
        return EXIT_FAILURE
    except InvalidEncryptionKeysError as exc:
        report(f"{exc}。")
        return EXIT_FAILURE
    vault = EvidenceVault(runner_settings.runs_dir, cipher)
    if args.command == ROTATE_COMMAND:
        return _with_database(settings, report, lambda engine: _rotate(engine, vault, report))
    return _with_database(
        settings, report, lambda engine: _export(engine, vault, args.run, args.path, report)
    )


# --- rotate-evidence-keys ----------------------------------------------------------------------


def _rotate(engine: Engine, vault: EvidenceVault, report: Report) -> int:
    store = EvidenceStore(sessionmaker(engine, expire_on_commit=False), engine=engine)
    outcome = _rotate_locked(store, vault)
    if outcome is None:
        report("keeper 正在處理原始證據，等不到鎖：請稍後再執行（沒有改變任何檔案）。")
        return EXIT_FAILURE
    files, directories, failed = outcome
    _audit(engine, "evidence_keys.rotate", None, None, {"files": files, "failures": len(failed)})
    if failed:
        listed = "、".join(failed[:MAX_LISTED])
        report(
            f"有 {len(failed)} 個目錄無法換版（{listed}）：原本的加密檔保留原狀。"
            f"請把加密它們的金鑰加回 {EVIDENCE_SETTING} 再執行。其他 {files} 個檔案已換版。"
        )
        return EXIT_FAILURE
    report(
        f"已以 {EVIDENCE_SETTING} 的第一個金鑰重新加密 {files} 個檔案（{directories} 個目錄）。"
        "現在可以移除舊金鑰；移除後重啟 runner，並再執行一次這個指令確認全部解得開。"
    )
    return EXIT_OK


def _rotate_locked(store: EvidenceStore, vault: EvidenceVault) -> tuple[int, int, list[str]] | None:
    """持有 advisory lock 時換版；keeper 只在每一輪處理檔案時持有鎖，所以重試到拿到為止。"""
    for attempt in range(LOCK_ATTEMPTS):
        if attempt:
            time.sleep(LOCK_WAIT_SECONDS)
        with store.exclusive() as acquired:
            if acquired:
                return _rotate_all(vault)
    return None


def _rotate_all(vault: EvidenceVault) -> tuple[int, int, list[str]]:
    files = directories = 0
    failed: list[str] = []
    for name in vault.entries():
        try:
            rotated = vault.rotate(name)
        except EvidenceError:
            failed.append(name)
            continue
        files += rotated
        directories += 1 if rotated else 0
    return files, directories, failed


# --- export-evidence ---------------------------------------------------------------------------


def _export(
    engine: Engine, vault: EvidenceVault, run_id: UUID, path: str | None, report: Report
) -> int:
    name = str(run_id)
    try:
        if path is None:
            for info in vault.listing(name):
                line = {"path": info.path, "sha256": info.sha256, "size_bytes": info.size}
                sys.stdout.write(json.dumps(line, ensure_ascii=False) + "\n")
            return EXIT_OK
        verified = vault.export(name, path, _Discard())
    except EvidenceError as exc:
        report(f"{exc}。")
        return EXIT_FAILURE
    project_id = _project_of(engine, run_id)
    changes = {"run_id": name, "path_sha256": _sha256(path), "size_bytes": verified.size}
    _audit(engine, "evidence.export", run_id, project_id, changes)
    try:
        exported = vault.export(name, path, sys.stdout.buffer)
    except EvidenceError as exc:
        report(f"{exc}：輸出不完整，請丟棄。")
        return EXIT_FAILURE
    sys.stdout.buffer.flush()
    if exported.sha256 != verified.sha256:
        report("兩次解密的內容不同：輸出不可信，請丟棄。")
        return EXIT_FAILURE
    report(f"已匯出 {exported.size} bytes（sha256 {exported.sha256}）；這次存取已記入 audit。")
    return EXIT_OK


class _Discard:
    def write(self, data: bytes, /) -> int:
        return len(data)


def _project_of(engine: Engine, run_id: UUID) -> UUID | None:
    with Session(engine) as session:
        project: UUID | None = session.scalar(
            select(ScanModel.project_id)
            .join(ScannerRunModel, ScannerRunModel.scan_id == ScanModel.id)
            .where(ScannerRunModel.id == run_id)
        )
        return project


# --- retention-status --------------------------------------------------------------------------


def _status(engine: Engine, settings: Settings, report: Report) -> int:
    store = EvidenceStore(sessionmaker(engine, expire_on_commit=False), engine=engine)
    summary = store.summary(
        now=datetime.now(UTC),
        retention_days=settings.evidence_retention_days,
        max_minutes=settings.evidence_plaintext_max_minutes,
    )
    report(
        "原始證據："
        f"執行中或等待解析 {summary.in_progress}（其中逾期 {summary.overdue}）、"
        f"已終止但未加密 {summary.pending}、沒有目錄 {summary.none}、"
        f"已加密 {summary.sealed}（其中已到期待清除 {summary.due}）、已清除 {summary.purged}。"
        f"保留 {settings.evidence_retention_days} 天、等待解析上限 "
        f"{settings.evidence_plaintext_max_minutes} 分鐘。"
    )
    return EXIT_OK


# --- 共用 --------------------------------------------------------------------------------------


def _with_database(settings: Settings, report: Report, action: Callable[[Engine], int]) -> int:
    engine = create_db_engine(settings, application_name=APPLICATION_NAME, pooled=False)
    try:
        status = probe_database(engine, head_revision())
        if status is not DatabaseStatus.READY:
            report(NOT_READY[status])
            return EXIT_FAILURE
        return action(engine)
    except SQLAlchemyError as exc:
        report(f"資料庫發生錯誤（{type(exc).__name__}），已停止。")
        return EXIT_FAILURE
    finally:
        engine.dispose()


def _audit(
    engine: Engine,
    action: str,
    object_id: UUID | None,
    project_id: UUID | None,
    changes: dict[str, Any],
) -> None:
    with Session(engine, expire_on_commit=False) as session, session.begin():
        AuditTrail(session).record(
            action=action,
            object_type="run_evidence",
            object_id=object_id,
            actor_key_id=None,
            project_id=project_id,
            request_id=None,
            changes=changes,
        )


def _setting(settings: Settings) -> str | None:
    keys = settings.evidence_encryption_keys
    return keys.get_secret_value() if keys is not None else None


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()
