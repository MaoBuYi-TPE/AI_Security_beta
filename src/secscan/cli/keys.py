"""加密金鑰的管理指令（docs/DECISIONS.md §30.2、§30.6）。

    uv run secscan-admin check-encryption-keys
    uv run secscan-admin rotate-content-keys

- check-encryption-keys：在主機上檢查 .env（或環境變數）的三組金鑰：都存在、合乎規則，而且彼此
  沒有相同的金鑰。只顯示每一組的數量，不顯示金鑰；不連資料庫。
- rotate-content-keys：以 CONTENT_ENCRYPTION_KEYS 的第一個金鑰重新加密報告內容與人工複測摘錄
  （報告一份一個 transaction、摘錄分批；可以重複執行）。解不開的保留原狀並列出 id，exit 1；
  audit 只記數量。
  步驟：新金鑰放第一個 → 重啟 api、worker → 執行 → 移除舊金鑰、重啟 → 再執行一次確認。
"""

import argparse
from typing import Any

from pydantic import SecretStr
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.cli.services import EXIT_FAILURE, EXIT_OK, Report, audit_local, with_database
from secscan.core.config import Settings
from secscan.security.blob_cipher import BlobCipher
from secscan.security.key_rings import (
    ALL_SETTINGS,
    CONTENT_SETTING,
    content_cipher,
    shared_rings,
)
from secscan.security.secret_cipher import InvalidEncryptionKeysError, check_distinct_key_rings
from secscan.worker.content_keys import ContentRotation

CHECK_COMMAND = "check-encryption-keys"
ROTATE_COMMAND = "rotate-content-keys"
COMMANDS = (CHECK_COMMAND, ROTATE_COMMAND)
APPLICATION_NAME = "secscan-keys-cli"
MAX_LISTED = 10

type Subparsers = argparse._SubParsersAction[Any]


def register(commands: Subparsers) -> None:
    commands.add_parser(
        ROTATE_COMMAND,
        help=f"以 {CONTENT_SETTING} 的第一個金鑰重新加密報告內容與人工複測摘錄",
        description=(
            f"以 {CONTENT_SETTING} 的第一個金鑰重新加密報告內容與人工複測摘錄；解不開的保留原狀"
            "並列出 id。可以重複執行。"
        ),
    )
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
    if args.command == ROTATE_COMMAND:
        return rotate_content_keys(settings, report)
    return None


def refuse_shared_rings(settings: Settings, report: Report) -> int | None:
    """每個 admin 指令之前：主機上的三組金鑰共用時停止（EXIT_FAILURE）；沒有問題回 None。"""
    problem = shared_rings(_key_settings(settings))
    if problem is None:
        return None
    report(f"{problem}。沒有執行任何指令。")
    return EXIT_FAILURE


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


def rotate_content_keys(settings: Settings, report: Report) -> int:
    keys = settings.content_encryption_keys
    try:
        cipher = content_cipher(keys.get_secret_value() if keys is not None else None)
    except InvalidEncryptionKeysError as exc:
        report(f"{exc}。")
        return EXIT_FAILURE
    return with_database(
        settings,
        report,
        lambda engine: _rotate(engine, cipher, report),
        application_name=APPLICATION_NAME,
    )


def _rotate(engine: Engine, cipher: BlobCipher, report: Report) -> int:
    result = ContentRotation(sessionmaker(engine, expire_on_commit=False), cipher).run()
    audit_local(
        engine,
        "content_keys.rotate",
        {"reports": result.reports, "excerpts": result.excerpts, "failures": result.failures},
        object_type="content",
    )
    if result.failures:
        listed = [str(report_id) for report_id in result.unreadable_reports]
        listed += [
            f"{finding}#{sequence}:{kind}" for finding, sequence, kind in result.unreadable_excerpts
        ]
        report(
            f"有 {result.failures} 份內容無法以目前的金鑰解開（{'、'.join(listed[:MAX_LISTED])}）："
            f"保留原狀。請把加密它們的金鑰加回 {CONTENT_SETTING} 再執行；"
            f"其他 {result.reports} 份報告、{result.excerpts} 段摘錄已換版。"
        )
        return EXIT_FAILURE
    report(
        f"已以 {CONTENT_SETTING} 的第一個金鑰重新加密 {result.reports} 份報告、"
        f"{result.excerpts} 段人工複測摘錄。現在可以移除舊金鑰；移除後重啟 api 與 worker，"
        "並再執行一次這個指令確認全部解得開。"
    )
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
