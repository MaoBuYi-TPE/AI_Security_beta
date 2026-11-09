"""加密金鑰的管理指令（docs/DECISIONS.md §30.2、§30.6）。

    uv run secscan-admin check-encryption-keys

- 在主機上檢查 .env（或環境變數）的三組金鑰：都存在、合乎規則，而且彼此沒有相同的金鑰。
  只顯示每一組的數量，不顯示金鑰；不連資料庫。
"""

import argparse
from typing import Any

from pydantic import SecretStr

from secscan.cli.services import EXIT_FAILURE, EXIT_OK, Report
from secscan.core.config import Settings
from secscan.security.key_rings import ALL_SETTINGS
from secscan.security.secret_cipher import InvalidEncryptionKeysError, check_distinct_key_rings

CHECK_COMMAND = "check-encryption-keys"
COMMANDS = (CHECK_COMMAND,)

type Subparsers = argparse._SubParsersAction[Any]


def register(commands: Subparsers) -> None:
    commands.add_parser(
        CHECK_COMMAND,
        help="檢查三組加密金鑰都存在、合乎規則而且互不相同（只顯示數量）",
        description=(
            "檢查 SECRET_、EVIDENCE_、CONTENT_ENCRYPTION_KEYS：都存在、合乎規則，而且彼此沒有相同的"
            "金鑰。只顯示每一組的數量，不顯示金鑰，不連資料庫。"
        ),
    )


def run(args: argparse.Namespace, settings: Settings, report: Report) -> int | None:
    """這個模組的指令；其他指令回傳 None。"""
    if args.command == CHECK_COMMAND:
        return check_encryption_keys(settings, report)
    return None


def check_encryption_keys(settings: Settings, report: Report) -> int:
    values = _key_settings(settings)
    missing = [name for name, value in values.items() if value is None]
    if missing:
        report(f"缺少 {'、'.join(missing)}：請執行 make env（只補上缺少的金鑰，不改既有的值）。")
        return EXIT_FAILURE
    present = {name: value for name, value in values.items() if value is not None}
    try:
        check_distinct_key_rings(present)
    except InvalidEncryptionKeysError as exc:
        report(f"{exc}。")
        return EXIT_FAILURE
    counts = "、".join(f"{name} {len(value.split(','))} 個" for name, value in present.items())
    report(f"三組加密金鑰都合乎規則，彼此沒有相同的金鑰（{counts}）。")
    return EXIT_OK


def _key_settings(settings: Settings) -> dict[str, str | None]:
    fields: dict[str, SecretStr | None] = {
        ALL_SETTINGS[0]: settings.secret_encryption_keys,
        ALL_SETTINGS[1]: settings.evidence_encryption_keys,
        ALL_SETTINGS[2]: settings.content_encryption_keys,
    }
    return {
        name: value.get_secret_value() if value is not None else None
        for name, value in fields.items()
    }
