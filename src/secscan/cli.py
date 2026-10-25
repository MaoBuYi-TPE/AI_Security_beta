"""本機管理指令 secscan-admin。

建立 platform_admin key（docs/DECISIONS.md §9.1）：

    uv run secscan-admin create-admin-key --name "本機管理員" [--expires-in-days 90] [--output PATH]

- DB 連線設定與 API 相同（DB_* 環境變數或 .env）。能執行這個指令的人本來就有 DB 帳密。
- 完整的 key 只在 commit 成功之後寫出一次：預設寫到 stdout；`--output` 則寫進新建、權限 600
  的檔案（已存在就拒絕，不覆寫）。說明、key id 與 prefix 寫到 stderr。DB 只存 hash。
- 沒有建立 key（設定錯誤、DB 不可用、commit 失敗）時，不寫出任何東西，也不留下空檔。

加密金鑰換版（docs/DECISIONS.md §12.3）：

    uv run secscan-admin rotate-secret-keys

- 以 SECRET_ENCRYPTION_KEYS 的第一個金鑰，重新加密所有還在的 secret（一個 transaction）。
- 有任何一份解不開就全部回滾、exit 1，只列出 profile id；說明都寫到 stderr，不輸出 secret。
"""

import argparse
import os
import sys
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TextIO

from pydantic import ValidationError
from pydantic_core import ErrorDetails
from sqlalchemy import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

# 和 API 入口一樣載入完整的 ORM model 登記（跨功能 FK 需要；見 secscan.main）。
import secscan.migrations.metadata  # noqa: F401
from secscan.api_keys.domain import (
    API_KEY_NAME_MAX_LENGTH,
    DEFAULT_KEY_LIFETIME,
    MAX_KEY_LIFETIME,
    IssuedApiKey,
)
from secscan.api_keys.service import ApiKeyService
from secscan.auth_profiles.service import AuthProfileService, SecretRotationError
from secscan.core.config import Settings
from secscan.core.db import DatabaseStatus, create_db_engine, probe_database
from secscan.core.text import require_text
from secscan.migrations import head_revision
from secscan.security.secret_cipher import InvalidEncryptionKeysError, SecretCipher

PROGRAM = "secscan-admin"
CLI_APPLICATION_NAME = "secscan-cli"
EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2  # argparse 的參數錯誤
OUTPUT_FILE_MODE = 0o600
ROTATE_COMMAND = "rotate-secret-keys"
# 解不開時最多列出幾個 profile id（其餘以數量表示）。
MAX_LISTED_PROFILES = 10

_NOT_READY = {
    DatabaseStatus.UNAVAILABLE: "無法連線資料庫：請先執行 make db-up，並確認 .env 的 DB_* 設定。",
    DatabaseStatus.SCHEMA_OUTDATED: "資料庫 schema 不是目前版本：請先執行 make migrate。",
}


class KeyOutput:
    """完整 key 的去處：stdout，或以 O_EXCL 新建、權限 600 的檔案。

    檔案在建立 key 之前就先開好（開不了就不建立 key）；沒有寫出 key 時，discard() 會刪除它。
    """

    def __init__(self, path: Path | None) -> None:
        self._path = path
        self._opened: tuple[Path, TextIO] | None = None
        self._delivered = False

    @property
    def description(self) -> str:
        return str(self._path) if self._path is not None else "stdout 那一行"

    def prepare(self) -> None:
        if self._path is not None:
            descriptor = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, OUTPUT_FILE_MODE)
            self._opened = (self._path, os.fdopen(descriptor, "w", encoding="utf-8"))

    def deliver(self, value: str) -> None:
        stream = self._opened[1] if self._opened is not None else sys.stdout
        stream.write(f"{value}\n")
        stream.flush()
        if self._opened is not None:
            os.fsync(stream.fileno())
            stream.close()
        self._delivered = True

    def discard(self) -> None:
        """沒有寫出 key（或只寫了一半）時，關閉並刪除事先建立的檔案。"""
        if self._opened is None or self._delivered:
            return
        path, stream = self._opened
        stream.close()
        path.unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        settings = Settings()
    except ValidationError as exc:
        # 只列出欄位與原因，不列出輸入值（可能是密碼）。
        problems = "；".join(_describe(error) for error in exc.errors())
        _report(f"設定不正確（DB_* 環境變數或 .env）：{problems}")
        return EXIT_FAILURE
    if args.command == ROTATE_COMMAND:
        return _rotate_secret_keys(settings)
    output = KeyOutput(args.output)
    try:
        output.prepare()
    except OSError as exc:
        _report(
            f"無法建立輸出檔 {args.output}（{_reason(exc)}；已存在的檔案不會被覆寫）。"
            "沒有建立任何 key。"
        )
        return EXIT_FAILURE
    try:
        return _create_admin_key(
            settings, output, name=args.name, lifetime_days=args.expires_in_days
        )
    finally:
        output.discard()


def _create_admin_key(
    settings: Settings, output: KeyOutput, *, name: str, lifetime_days: int
) -> int:
    engine = create_db_engine(settings, application_name=CLI_APPLICATION_NAME, pooled=False)
    try:
        status = probe_database(engine, head_revision())
        if status is not DatabaseStatus.READY:
            _report(_NOT_READY[status])
            return EXIT_FAILURE
        issued, expires_at = _issue(engine, name=name, lifetime_days=lifetime_days)
    except SQLAlchemyError as exc:
        # 只報例外類別：驅動的訊息可能含連線資訊或資料值。
        _report(f"建立 key 時資料庫發生錯誤（{type(exc).__name__}），已回滾，沒有建立任何 key。")
        return EXIT_FAILURE
    finally:
        engine.dispose()
    # transaction 已 commit：這時 key 才真的存在，才寫出來。
    try:
        output.deliver(issued.value)
    except OSError as exc:
        _report(
            f"key 已建立（id {issued.key.id}），但寫出失敗（{_reason(exc)}）。沒有人拿得到它的值，"
            "所以無法使用；可以撤銷它，再重新執行一次。"
        )
        return EXIT_FAILURE
    _report_issued(issued, expires_at, output.description)
    return EXIT_OK


def _rotate_secret_keys(settings: Settings) -> int:
    keys = settings.secret_encryption_keys
    try:
        cipher = SecretCipher.from_setting(keys.get_secret_value() if keys is not None else None)
    except InvalidEncryptionKeysError as exc:
        _report(f"{exc}。")
        return EXIT_FAILURE
    engine = create_db_engine(settings, application_name=CLI_APPLICATION_NAME, pooled=False)
    try:
        status = probe_database(engine, head_revision())
        if status is not DatabaseStatus.READY:
            _report(_NOT_READY[status])
            return EXIT_FAILURE
        with Session(engine, expire_on_commit=False) as session, session.begin():
            count = AuthProfileService(session, cipher=cipher).reencrypt_secrets()
    except SecretRotationError as exc:
        _report(_unreadable_message(exc.profile_ids))
        return EXIT_FAILURE
    except SQLAlchemyError as exc:
        _report(f"重新加密時資料庫發生錯誤（{type(exc).__name__}），已回滾，沒有改變任何 secret。")
        return EXIT_FAILURE
    finally:
        engine.dispose()
    _report(
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


def _issue(engine: Engine, *, name: str, lifetime_days: int) -> tuple[IssuedApiKey, datetime]:
    now = datetime.now(UTC)
    expires_at = now + timedelta(days=lifetime_days)
    with Session(engine, expire_on_commit=False) as session, session.begin():
        issued = ApiKeyService(session).issue_admin_key(name=name, expires_at=expires_at, now=now)
    return issued, expires_at


def _report_issued(issued: IssuedApiKey, expires_at: datetime, destination: str) -> None:
    key = issued.key
    _report(
        f"已建立 platform_admin key：id {key.id}，prefix {key.prefix}，"
        f"到期 {expires_at:%Y-%m-%d %H:%M} UTC。"
    )
    _report(
        f"完整的 key 只寫出這一次（{destination}），請妥善保存；"
        "遺失時重新建立一把，並撤銷舊的 key（DELETE /api/v1/keys/{key_id}）。"
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=PROGRAM, description="secscan 本機管理指令")
    commands = parser.add_subparsers(dest="command", required=True, metavar="command")
    create = commands.add_parser(
        "create-admin-key",
        help="建立 platform_admin key（完整的 key 只寫出一次）",
        description="建立 platform_admin key。完整的 key 只寫出一次，DB 只存 hash。",
    )
    create.add_argument("--name", required=True, type=_key_name, help="key 的用途或持有人")
    create.add_argument(
        "--expires-in-days",
        type=_lifetime_days,
        default=DEFAULT_KEY_LIFETIME.days,
        help=f"有效天數，1 到 {MAX_KEY_LIFETIME.days}，預設 {DEFAULT_KEY_LIFETIME.days}",
    )
    create.add_argument(
        "--output",
        type=Path,
        default=None,
        help="把 key 寫進這個新檔案（權限 600；已存在就拒絕），不寫到 stdout",
    )
    commands.add_parser(
        ROTATE_COMMAND,
        help="以 SECRET_ENCRYPTION_KEYS 的第一個金鑰重新加密所有的 secret",
        description=(
            "以 SECRET_ENCRYPTION_KEYS 的第一個金鑰重新加密所有還在的 secret。"
            "有任何一份解不開就全部回滾。"
        ),
    )
    return parser


def _key_name(value: str) -> str:
    try:
        require_text(value, field="name", max_length=API_KEY_NAME_MAX_LENGTH)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None
    return value


def _lifetime_days(value: str) -> int:
    try:
        days = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("必須是整數天數") from None
    if not 1 <= days <= MAX_KEY_LIFETIME.days:
        raise argparse.ArgumentTypeError(f"必須介於 1 與 {MAX_KEY_LIFETIME.days} 天之間")
    return days


def _describe(error: ErrorDetails) -> str:
    location = ".".join(str(part) for part in error["loc"]) or "設定"
    return f"{location}：{error['msg']}"


def _reason(exc: OSError) -> str:
    return exc.strerror or type(exc).__name__


def _report(message: str) -> None:
    sys.stderr.write(f"{message}\n")
