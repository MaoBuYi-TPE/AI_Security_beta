"""compose secrets 的秘密檔（T23b-b2；docs/DECISIONS.md §32）。

sync-secret-files 與 generate-secret-files：

    uv run secscan-admin sync-secret-files [--check] [--dir secrets]    （make secrets）
    uv run secscan-admin generate-secret-files <新建的空目錄>             （Live 的 recipe）

- SECRET_FILES 是唯一的對照表：.env 的名稱、secrets/ 的檔名、容器內的路徑。compose.yaml 的頂層
  secrets 與每個 `*_FILE` 都和它一致（tests/unit/test_compose_secrets.py）。
- 兩個指令都在載入 Settings 之前分派，不需要 DB；終端只顯示名稱與動作，一律不顯示值。
- sync-secret-files：.env 仍是唯一由人編輯的來源（.env 不改）。值以只有七個欄位的設定類別讀取
  （同樣的 .env 解析與優先順序），檢查之後寫進 secrets/：目錄 0700、檔案 0600、沒有結尾換行；
  內容相同就不動，不同時以暫存檔原子替換（O_EXCL → fchmod → 寫入 → fsync → rename → fsync 目錄）。
  所有操作都經由目錄的 fd（O_DIRECTORY | O_NOFOLLOW）。symlink 與權限過寬、別人擁有的目錄一律拒絕；
  不認得的檔案不刪除，只列出名稱。`--check` 不寫入，缺少或不一致就 exit 1。
- DB 角色的密碼在第一次初始化之後不會跟著 secrets/ 改變：更新 db 的三個密碼檔時印出固定的警告。
- generate-secret-files：Live 的拋棄式秘密（docs/DECISIONS.md §32；計畫 §3.1）。產生七個隨機值
  （格式和 make env 相同），只寫進新建的空目錄，不讀 .env。
"""

import argparse
import os
import secrets
import stat
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from secscan.cli.keys import Subparsers
from secscan.cli.services import Report
from secscan.core.config import ENV_FILE
from secscan.core.secret_files import MAX_SECRET_LENGTH
from secscan.core.settings_errors import SettingsError, build_settings
from secscan.security.secret_cipher import InvalidEncryptionKeysError, new_key, parse_keys

SYNC_COMMAND = "sync-secret-files"
GENERATE_COMMAND = "generate-secret-files"
DEFAULT_SECRETS_DIR = Path("secrets")
CONTAINER_SECRETS_DIR = "/run/secrets"
DIRECTORY_MODE = 0o700
FILE_MODE = 0o600
# 工具自己的暫存檔：開始時清除上次留下的。
TEMP_PREFIX = ".secscan-sync-"
# make env 的格式：密碼是 24 bytes 的 hex（48 個字元）；金鑰是 Fernet 金鑰（44 個字元）。
PASSWORD_BYTES = 24
_FIRST_PRINTABLE = 0x21
_LAST_PRINTABLE = 0x7E
_QUOTES = frozenset(b"\"'`")
EXIT_OK = 0
EXIT_FAILURE = 1


class Kind(StrEnum):
    """秘密的格式：密碼（hex）或 Fernet 金鑰。"""

    PASSWORD = "password"  # noqa: S105 - 格式的名稱，不是密碼
    KEYS = "keys"


@dataclass(frozen=True, slots=True)
class SecretFile:
    env_name: str
    file_name: str
    kind: Kind

    @property
    def container_path(self) -> str:
        return f"{CONTAINER_SECRETS_DIR}/{self.file_name}"


SECRET_FILES = (
    SecretFile("DB_ADMIN_PASSWORD", "db_admin_password", Kind.PASSWORD),
    SecretFile("TEST_DB_PASSWORD", "test_db_password", Kind.PASSWORD),
    SecretFile("DB_OWNER_PASSWORD", "db_owner_password", Kind.PASSWORD),
    SecretFile("DB_PASSWORD", "db_password", Kind.PASSWORD),
    SecretFile("SECRET_ENCRYPTION_KEYS", "secret_encryption_keys", Kind.KEYS),
    SecretFile("EVIDENCE_ENCRYPTION_KEYS", "evidence_encryption_keys", Kind.KEYS),
    SecretFile("CONTENT_ENCRYPTION_KEYS", "content_encryption_keys", Kind.KEYS),
)
# 開發 db 的三個角色：密碼只在第一次初始化時寫進 DB，之後換檔案不會改 DB 中的密碼。
DB_ROLE_FILES = frozenset({"db_admin_password", "db_owner_password", "db_password"})
DB_ROLE_WARNING = (
    "警告：db 的角色密碼只在第一次初始化時建立，更新 secrets/ 不會改變 DB 中的密碼"
    "（不一致時服務會無法登入；見 README 的換版說明）。"
)


class SecretFilesError(Exception):
    """秘密檔的目錄或檔案不符合規則；訊息只有名稱與原因。"""


class Action(StrEnum):
    ADDED = "新增"
    UPDATED = "更新"
    UNCHANGED = "不變"
    MISSING = "缺少"
    DIFFERENT = "不一致"


class SecretSources(BaseSettings):
    """sync-secret-files 讀的七個值：和其他設定類別相同的 .env 解析與優先順序（環境變數優先）。"""

    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
        hide_input_in_errors=True,
    )

    db_admin_password: SecretStr | None = None
    test_db_password: SecretStr | None = None
    db_owner_password: SecretStr | None = None
    db_password: SecretStr | None = None
    secret_encryption_keys: SecretStr | None = None
    evidence_encryption_keys: SecretStr | None = None
    content_encryption_keys: SecretStr | None = None

    def values(self) -> dict[str, SecretStr | None]:
        return {item.file_name: getattr(self, item.file_name) for item in SECRET_FILES}


def register(commands: Subparsers) -> None:
    sync = commands.add_parser(
        SYNC_COMMAND,
        help="由 .env 產生 compose secrets 的秘密檔（make secrets；不顯示任何值）",
        description=(
            ".env 的七個秘密寫進 secrets/（目錄 0700、檔案 0600、沒有結尾換行）；內容相同就不動。"
            "--check 只檢查，缺少或不一致就 exit 1。"
        ),
    )
    sync.add_argument("--check", action="store_true", help="只檢查，不寫入")
    sync.add_argument("--dir", type=Path, default=DEFAULT_SECRETS_DIR, help="秘密檔的目錄")
    generate = commands.add_parser(
        GENERATE_COMMAND,
        help="在新建的空目錄產生拋棄式的秘密檔（Live 的 recipe；不讀 .env、不顯示任何值）",
        description="產生七個隨機的秘密（格式和 make env 相同），寫進新建、空的 0700 目錄。",
    )
    generate.add_argument("directory", type=Path, help="新建、空的 0700 目錄（mktemp -d）")


def run(args: argparse.Namespace, report: Report) -> int | None:
    """這兩個指令（回傳 exit code）；其他指令回傳 None。不載入 Settings。"""
    if args.command == SYNC_COMMAND:
        return _sync_command(args.dir, check=args.check, report=report)
    if args.command == GENERATE_COMMAND:
        return _generate_command(args.directory, report=report)
    return None


# --------------------------------------------------------------------------- sync


def _sync_command(directory: Path, *, check: bool, report: Report) -> int:
    try:
        sources = build_settings(SecretSources)
    except SettingsError as exc:
        report(f"{exc}（.env 或環境變數）。沒有寫入任何檔案。")
        return EXIT_FAILURE
    values, problems = _checked_values(sources.values())
    if problems:
        report(f"這些秘密的值不正確：{'、'.join(problems)}。沒有寫入任何檔案。")
        return EXIT_FAILURE
    try:
        if check:
            return _check(directory, values, report)
        return _sync(directory, values, report)
    except SecretFilesError as exc:
        report(f"{exc}。")
        return EXIT_FAILURE


def _checked_values(raw: Mapping[str, SecretStr | None]) -> tuple[dict[str, bytes], list[str]]:
    values: dict[str, bytes] = {}
    problems: list[str] = []
    for item in SECRET_FILES:
        secret = raw[item.file_name]
        value = secret.get_secret_value() if secret is not None else ""
        if _valid(item, value):
            values[item.file_name] = value.encode("ascii")
        else:
            problems.append(item.env_name)
    return values, problems


def _valid(item: SecretFile, value: str) -> bool:
    encoded = value.encode("utf-8")
    if not 1 <= len(encoded) <= MAX_SECRET_LENGTH:
        return False
    if any(not _FIRST_PRINTABLE <= byte <= _LAST_PRINTABLE or byte in _QUOTES for byte in encoded):
        return False
    if item.kind is Kind.KEYS:
        try:
            parse_keys(value, item.env_name)
        except InvalidEncryptionKeysError:
            return False
    return True


def _sync(directory: Path, values: Mapping[str, bytes], report: Report) -> int:
    with _directory(directory, create=True) as descriptor:
        _remove_stale_temporaries(descriptor)
        actions = {
            item.file_name: _write_if_changed(descriptor, item, values) for item in SECRET_FILES
        }
        for name, action in actions.items():
            report(f"{name}：{action}")
        _report_unknown(descriptor, report)
    if any(actions[name] is Action.UPDATED for name in DB_ROLE_FILES):
        report(DB_ROLE_WARNING)
    return EXIT_OK


def _check(directory: Path, values: Mapping[str, bytes], report: Report) -> int:
    if not os.path.lexists(directory):
        report(f"{directory} 不存在：請執行 make secrets。")
        return EXIT_FAILURE
    with _directory(directory, create=False) as descriptor:
        results = {item.file_name: _compare(descriptor, item, values) for item in SECRET_FILES}
    bad = [
        f"{name}（{action}）" for name, action in results.items() if action is not Action.UNCHANGED
    ]
    if bad:
        report(f"secrets/ 和 .env 不一致：{'、'.join(bad)}。請執行 make secrets。")
        return EXIT_FAILURE
    report("secrets/ 和 .env 一致。")
    return EXIT_OK


def _write_if_changed(descriptor: int, item: SecretFile, values: Mapping[str, bytes]) -> Action:
    current = _existing(descriptor, item.file_name)
    value = values[item.file_name]
    if current is not None and current == (value, FILE_MODE):
        return Action.UNCHANGED
    _replace(descriptor, item.file_name, value)
    return Action.ADDED if current is None else Action.UPDATED


def _compare(descriptor: int, item: SecretFile, values: Mapping[str, bytes]) -> Action:
    current = _existing(descriptor, item.file_name)
    if current is None:
        return Action.MISSING
    if current != (values[item.file_name], FILE_MODE):
        return Action.DIFFERENT
    return Action.UNCHANGED


def _existing(descriptor: int, name: str) -> tuple[bytes, int] | None:
    """目前的內容與權限；不存在回傳 None。symlink 或不是一般檔案時拒絕。"""
    try:
        info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode):
        raise SecretFilesError(f"{name} 不是一般檔案（或是 symlink）：拒絕處理")
    reason: str | None = None
    content = b""
    try:
        content = _read(descriptor, name)
    except OSError as exc:
        reason = exc.strerror or type(exc).__name__
    if reason is not None:
        raise SecretFilesError(f"無法讀取 {name}（{reason}）")
    return content, stat.S_IMODE(info.st_mode)


def _read(descriptor: int, name: str) -> bytes:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    file_descriptor = os.open(name, flags, dir_fd=descriptor)
    with os.fdopen(file_descriptor, "rb") as stream:
        return stream.read(MAX_SECRET_LENGTH + 2)


def _replace(descriptor: int, name: str, value: bytes) -> None:
    temporary = f"{TEMP_PREFIX}{name}.{secrets.token_hex(8)}"
    try:
        _write_new(descriptor, temporary, value)
        os.rename(temporary, name, src_dir_fd=descriptor, dst_dir_fd=descriptor)
        os.fsync(descriptor)
    except OSError as exc:
        _discard(descriptor, temporary)
        reason = exc.strerror or type(exc).__name__
        raise SecretFilesError(f"無法寫入 {name}（{reason}）：原本的檔案沒有改變") from None


def _write_new(descriptor: int, name: str, value: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    file_descriptor = os.open(name, flags, FILE_MODE, dir_fd=descriptor)
    try:
        os.fchmod(file_descriptor, FILE_MODE)
        view = memoryview(value)
        while view:
            written = os.write(file_descriptor, view)
            view = view[written:]
        os.fsync(file_descriptor)
    finally:
        os.close(file_descriptor)


def _discard(descriptor: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=descriptor)
    except FileNotFoundError:
        return


def _remove_stale_temporaries(descriptor: int) -> None:
    for name in os.listdir(descriptor):
        if not name.startswith(TEMP_PREFIX):
            continue
        info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISREG(info.st_mode):
            os.unlink(name, dir_fd=descriptor)


def _report_unknown(descriptor: int, report: Report) -> None:
    known = {item.file_name for item in SECRET_FILES}
    unknown = sorted(name for name in os.listdir(descriptor) if name not in known)
    if unknown:
        report(f"secrets/ 中有不認得的檔案（沒有刪除）：{'、'.join(unknown)}")


@contextmanager
def _directory(directory: Path, *, create: bool) -> Iterator[int]:
    """目錄的 fd：必須是目前使用者擁有、0700、不是 symlink 的目錄。

    不存在時（create）以 0700 建立。
    """
    if create and not os.path.lexists(directory):
        try:
            directory.mkdir(mode=DIRECTORY_MODE)
        except OSError as exc:
            raise SecretFilesError(f"無法建立 {directory}（{exc.strerror}）") from None
    try:
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise SecretFilesError(f"{directory} 必須是目錄，不可以是 symlink") from None
    try:
        _require_private(descriptor, directory)
        yield descriptor
    finally:
        os.close(descriptor)


def _require_private(descriptor: int, directory: Path) -> None:
    info = os.fstat(descriptor)
    if info.st_uid != os.getuid():
        raise SecretFilesError(f"{directory} 不是目前的使用者擁有的：拒絕處理")
    if stat.S_IMODE(info.st_mode) != DIRECTORY_MODE:
        raise SecretFilesError(f"{directory} 的權限必須是 0700：拒絕處理")


# --------------------------------------------------------------------------- generate


def generate_values() -> dict[str, bytes]:
    """七個獨立產生的隨機值（格式和 make env 相同）。"""
    values: dict[str, bytes] = {}
    for item in SECRET_FILES:
        if item.kind is Kind.PASSWORD:
            values[item.file_name] = secrets.token_hex(PASSWORD_BYTES).encode("ascii")
        else:
            values[item.file_name] = new_key().encode("ascii")
    return values


def _generate_command(directory: Path, *, report: Report) -> int:
    try:
        with _directory(directory, create=False) as descriptor:
            if os.listdir(descriptor):
                raise SecretFilesError(f"{directory} 不是空的目錄：拒絕寫入")
            for name, value in generate_values().items():
                _write_new(descriptor, name, value)
            os.fsync(descriptor)
    except SecretFilesError as exc:
        report(f"{exc}。")
        return EXIT_FAILURE
    except OSError as exc:
        report(f"無法產生拋棄式的秘密檔（{exc.strerror or type(exc).__name__}）。")
        return EXIT_FAILURE
    report(f"已產生 {len(SECRET_FILES)} 個拋棄式的秘密檔。")
    return EXIT_OK
