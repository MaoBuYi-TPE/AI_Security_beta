"""放在獨立模組的 admin 指令：目標 secret 的換版、加密金鑰、原始證據、需要人工處理的原始證據、保留
期限、runs volume 的 layout（docs/DECISIONS.md §12.3、§30）與既有資料庫的擁有權移轉（§31.5）。
secscan.cli 只負責註冊與分派到這裡。
不需要 DB 與金鑰設定的指令（init-runs-layout、sync-secret-files、generate-secret-files）由
secscan.cli 在載入 Settings 之前分派（without_settings）。

每個指令之前先確認持有的幾組金鑰沒有共用（主機上的 .env 三組都有；§30.11）。
"""

import argparse

from secscan.cli import (
    db_roles,
    evidence,
    evidence_holds,
    keys,
    runs_layout,
    secret_files,
    secret_keys,
)
from secscan.cli.services import Report
from secscan.core.config import Settings


def register(commands: keys.Subparsers) -> None:
    secret_keys.register(commands)
    keys.register(commands)
    evidence.register(commands)
    evidence_holds.register(commands)
    runs_layout.register(commands)
    db_roles.register(commands)
    secret_files.register(commands)


def without_settings(args: argparse.Namespace, report: Report) -> int | None:
    """不需要 DB 與金鑰設定的指令；其他指令回傳 None。

    - init-runs-layout：compose 的 runs-init，沒有任何環境變數與金鑰（docs/DECISIONS.md §30.13）；
    - sync-secret-files、generate-secret-files：只讀 .env 的七個秘密，或完全不讀（§32）。
    """
    if args.command == runs_layout.INIT_COMMAND:
        return runs_layout.init_command(args, report)
    return secret_files.run(args, report)


def run(args: argparse.Namespace, settings: Settings, report: Report) -> int | None:
    """這些模組的指令（回傳 exit code）；其他指令回傳 None。"""
    handled = keys.refuse_shared_rings(settings, report)
    if handled is None:
        handled = secret_keys.run(args, settings, report)
    if handled is None:
        handled = keys.run(args, settings, report)
    if handled is None:
        handled = evidence.run(args, settings, report)
    if handled is None:
        handled = evidence_holds.run(args, settings, report)
    if handled is None:
        handled = runs_layout.run(args, settings, report)
    if handled is None:
        handled = db_roles.run(args, settings, report)
    return handled
