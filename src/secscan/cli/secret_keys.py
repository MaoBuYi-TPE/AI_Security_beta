"""目標 secret 的金鑰換版（T08；docs/DECISIONS.md §12.3）。

    uv run secscan-admin rotate-secret-keys

以 SECRET_ENCRYPTION_KEYS 的第一個金鑰重新加密所有還在的 secret；有任何一份解不開就全部回滾、
exit 1，只列出 profile id。T23a 起從 secscan.cli 搬到這裡（行為不變，§30.11）。
"""

import argparse
from collections.abc import Sequence
from typing import Any

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from secscan.auth_profiles.service import AuthProfileService, SecretRotationError
from secscan.cli.services import EXIT_FAILURE, EXIT_OK, NOT_READY, Report
from secscan.core.config import Settings
from secscan.core.db import DatabaseStatus, create_db_engine, probe_database
from secscan.migrations import head_revision
from secscan.security.secret_cipher import InvalidEncryptionKeysError, SecretCipher

ROTATE_COMMAND = "rotate-secret-keys"
APPLICATION_NAME = "secscan-cli"
MAX_LISTED_PROFILES = 10

type Subparsers = argparse._SubParsersAction[Any]


def register(commands: Subparsers) -> None:
    commands.add_parser(
        ROTATE_COMMAND,
        help="以 SECRET_ENCRYPTION_KEYS 的第一個金鑰重新加密所有的 secret",
        description=(
            "以 SECRET_ENCRYPTION_KEYS 的第一個金鑰重新加密所有還在的 secret。"
            "有任何一份解不開就全部回滾。"
        ),
    )


def run(args: argparse.Namespace, settings: Settings, report: Report) -> int | None:
    """這個模組的指令；其他指令回傳 None。"""
    if args.command != ROTATE_COMMAND:
        return None
    return rotate_secret_keys(settings, report)


def rotate_secret_keys(settings: Settings, report: Report) -> int:
    keys = settings.secret_encryption_keys
    try:
        cipher = SecretCipher.from_setting(keys.get_secret_value() if keys is not None else None)
    except InvalidEncryptionKeysError as exc:
        report(f"{exc}。")
        return EXIT_FAILURE
    engine = create_db_engine(settings, application_name=APPLICATION_NAME, pooled=False)
    try:
        status = probe_database(engine, head_revision())
        if status is not DatabaseStatus.READY:
            report(NOT_READY[status])
            return EXIT_FAILURE
        with Session(engine, expire_on_commit=False) as session, session.begin():
            count = AuthProfileService(session, cipher=cipher).reencrypt_secrets()
    except SecretRotationError as exc:
        report(_unreadable_message(exc.profile_ids))
        return EXIT_FAILURE
    except SQLAlchemyError as exc:
        report(f"重新加密時資料庫發生錯誤（{type(exc).__name__}），已回滾，沒有改變任何 secret。")
        return EXIT_FAILURE
    finally:
        engine.dispose()
    report(
        f"已以 SECRET_ENCRYPTION_KEYS 的第一個金鑰重新加密 {count} 份 secret。"
        "現在可以移除其他金鑰；移除後請重啟 API，並再執行一次這個指令確認全部解得開。"
    )
    return EXIT_OK


def _unreadable_message(profile_ids: Sequence[object]) -> str:
    listed = "、".join(str(profile_id) for profile_id in profile_ids[:MAX_LISTED_PROFILES])
    if len(profile_ids) > MAX_LISTED_PROFILES:
        listed += f" 等 {len(profile_ids)} 個"
    return (
        f"有 {len(profile_ids)} 份 secret 無法以目前的金鑰解開（profile：{listed}），"
        "已回滾，沒有改變任何 secret。請把加密它們的金鑰加回 SECRET_ENCRYPTION_KEYS 再執行；"
        "密文被搬到其他 profile 時也會解不開。"
    )
