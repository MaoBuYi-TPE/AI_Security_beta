"""放在獨立模組的 admin 指令：目標 secret 的換版、加密金鑰、原始證據與保留期限
（docs/DECISIONS.md §12.3、§30）。secscan.cli 只負責註冊與分派到這裡。

每個指令之前先確認持有的幾組金鑰沒有共用（主機上的 .env 三組都有；§30.11）。
"""

import argparse

from secscan.cli import evidence, keys, secret_keys
from secscan.cli.services import Report
from secscan.core.config import Settings


def register(commands: keys.Subparsers) -> None:
    secret_keys.register(commands)
    keys.register(commands)
    evidence.register(commands)


def run(args: argparse.Namespace, settings: Settings, report: Report) -> int | None:
    """這些模組的指令（回傳 exit code）；其他指令回傳 None。"""
    handled = keys.refuse_shared_rings(settings, report)
    if handled is None:
        handled = secret_keys.run(args, settings, report)
    if handled is None:
        handled = keys.run(args, settings, report)
    if handled is None:
        handled = evidence.run(args, settings, report)
    return handled
