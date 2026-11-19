"""compose secrets 的秘密檔（T23b-b2；docs/DECISIONS.md §32）。

sync-secret-files 與 generate-secret-files：

    uv run secscan-admin sync-secret-files [--check] [--dir secrets]    （make secrets）
    uv run secscan-admin generate-secret-files <新建的空目錄>             （Live 的 recipe）

- SECRET_FILES 是唯一的對照表：.env 的名稱、secrets/ 的檔名、容器內的路徑。compose.yaml 的頂層
  secrets 與每個 `*_FILE` 都和它一致（tests/unit/test_compose_secrets.py）。
- 兩個指令都在載入 Settings 之前分派，不需要 DB；終端只顯示名稱與動作，一律不顯示值。
- sync-secret-files：.env 仍是唯一由人編輯的來源（.env 不改）。值以只有七個欄位的設定類別讀取，
  **只讀 .env**：shell 中殘留的同名環境變數（不分大小寫）會讓容器與主機工具的值分歧，所以存在時
  拒絕執行（安全審查 L1）。檢查之後寫進 secrets/：目錄 0700、檔案 0600、沒有結尾換行；四個 DB 密碼
  至少 32 個字元（initdb 只檢查 owner 與應用程式角色的密碼；admin 與 test 的只在這裡檢查）。字元集
  比 initdb 嚴格（另外拒絕引號與反引號）：這裡接受的值 initdb 一定接受（契約測試只核對長度）。
  內容相同就不動，不同時以暫存檔原子替換（O_EXCL → fchmod → 寫入 → fsync → rename → fsync 目錄）；
  內容相同、只有權限不對時同樣替換，回報「修正權限」。
  每個檔案各自原子替換，七個檔案之間不是交易：一個檔案失敗就停止（G1d），每個檔案回報完成的動作、
  失敗（rename 之前失敗：原本的檔案沒有改變）、狀態不明（rename 之後目錄的 fsync 失敗，或 rename
  回報 EIO：可能已是新的內容，或無法確認已寫入磁碟），或沒有處理（維持原狀）。
  所有操作都經由目錄的 fd（O_DIRECTORY | O_NOFOLLOW）。symlink 與權限過寬、別人擁有的目錄一律拒絕；
  不認得的檔案不刪除，只列出名稱。`--check` 不寫入，缺少或不一致就 exit 1。
- DB 角色的密碼在第一次初始化之後不會跟著 secrets/ 改變：db 的三個密碼檔更新或狀態不明時（含中途
  失敗）印出固定的警告。
- generate-secret-files：Live 的拋棄式秘密（docs/DECISIONS.md §32；計畫 §3.1）。產生七個隨機值
  （格式和 make env 相同），只寫進新建的空目錄，不讀 .env。
"""

import argparse
import errno
import os
import secrets
import stat
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

from secscan.cli.keys import Subparsers
from secscan.cli.services import Report
from secscan.core.config import ENV_FILE
from secscan.core.secret_files import MAX_SECRET_LENGTH, MIN_DB_PASSWORD_LENGTH
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


class ReplaceError(SecretFilesError):
    """替換一個檔案失敗。uncertain：檔案可能已是新的內容（rename 之後目錄的 fsync 失敗，或 rename
    回報 EIO）；否則原本的檔案沒有改變。"""

    def __init__(self, message: str, *, uncertain: bool) -> None:
        super().__init__(message)
        self.uncertain = uncertain


class Action(StrEnum):
    ADDED = "新增"
    UPDATED = "更新"
    PERMISSIONS = "修正權限"
    UNCHANGED = "不變"
    MISSING = "缺少"
    DIFFERENT = "不一致"
    # 中途失敗時（G1d）：失敗的檔案、之後沒有處理的檔案。
    FAILED = "失敗（原本的檔案沒有改變）"
    UNCERTAIN = "狀態不明（可能已換成新的內容）"
    SKIPPED = "沒有處理（維持原狀）"


# 內容可能和之前不同的動作（中途失敗時的摘要）；db 的密碼檔是這兩種時印出角色密碼的警告。
CHANGED = frozenset({Action.ADDED, Action.UPDATED, Action.PERMISSIONS})
DB_ROLE_CHANGES = frozenset({Action.UPDATED, Action.UNCERTAIN})


class SecretSources(BaseSettings):
    """sync-secret-files 讀的七個值：只讀 .env（和其他設定類別相同的 .env 解析）。

    環境變數不是來源（安全審查 L1）：同名的環境變數存在時，指令在讀取之前就拒絕執行。
    """

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

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (init_settings, dotenv_settings)

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


def shadowing_variables(environ: Mapping[str, str]) -> list[str]:
    """環境中和七個秘密同名的變數（不分大小寫，和 pydantic-settings 的比對相同）；只回傳名稱。"""
    present = {name.upper() for name in environ}
    return [item.env_name for item in SECRET_FILES if item.env_name in present]


def _sync_command(directory: Path, *, check: bool, report: Report) -> int:
    shadowing = shadowing_variables(os.environ)
    if shadowing:
        report(
            f"環境變數中有和 .env 同名的秘密設定：{'、'.join(shadowing)}。sync-secret-files "
            "只以 .env 為來源；請在 unset 這些變數之後再執行。沒有寫入任何檔案。"
        )
        return EXIT_FAILURE
    try:
        sources = build_settings(SecretSources)
    except SettingsError as exc:
        report(f"{exc}（.env）。沒有寫入任何檔案。")
        return EXIT_FAILURE
    values, problems = _checked_values(sources.values())
    if problems:
        report(
            f"這些秘密的值不正確：{'、'.join(problems)}（可列印的 ASCII、不含空白與引號；DB 密碼 "
            f"{MIN_DB_PASSWORD_LENGTH} 到 {MAX_SECRET_LENGTH} 個字元；金鑰是 Fernet 格式）。"
            "沒有寫入任何檔案。"
        )
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
    shortest = MIN_DB_PASSWORD_LENGTH if item.kind is Kind.PASSWORD else 1
    if not shortest <= len(encoded) <= MAX_SECRET_LENGTH:
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
        actions, failure = _write_all(descriptor, values)
        for name, action in actions.items():
            report(f"{name}：{action}")
        if any(actions[name] in DB_ROLE_CHANGES for name in DB_ROLE_FILES):
            report(DB_ROLE_WARNING)
        if failure is not None:
            report(_partial(failure, actions))
            return EXIT_FAILURE
        _report_unknown(descriptor, report)
    return EXIT_OK


def _write_all(
    descriptor: int, values: Mapping[str, bytes]
) -> tuple[dict[str, Action], SecretFilesError | None]:
    """依序處理七個檔案；一個失敗就停止，之後的檔案不處理（G1d）。回傳每個檔案的動作與失敗。"""
    actions: dict[str, Action] = {}
    failure: SecretFilesError | None = None
    for item in SECRET_FILES:
        if failure is not None:
            actions[item.file_name] = Action.SKIPPED
            continue
        try:
            actions[item.file_name] = _write_if_changed(descriptor, item, values)
        except SecretFilesError as exc:
            uncertain = isinstance(exc, ReplaceError) and exc.uncertain
            actions[item.file_name] = Action.UNCERTAIN if uncertain else Action.FAILED
            failure = exc
    return actions, failure


def _partial(failure: SecretFilesError, actions: Mapping[str, Action]) -> str:
    """中途失敗的摘要：不宣稱沒有寫入任何檔案，除非確實沒有任何檔案改變。"""
    changed = sum(1 for action in actions.values() if action in CHANGED)
    uncertain = sum(1 for action in actions.values() if action is Action.UNCERTAIN)
    if not changed and not uncertain:
        return f"{failure}。沒有更新任何檔案；修正原因之後再執行 make secrets。"
    return (
        f"{failure}。secrets/ 只更新了一部分（已更新 {changed} 個、狀態不明 {uncertain} 個；"
        "各檔案的狀態見上面）：修正原因之後再執行 make secrets（內容相同的檔案不會再寫入）。"
    )


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
    if current is None:
        return Action.ADDED
    # 內容相同、只有權限不對：DB 中的密碼不受影響，不印出角色密碼的警告（程式碼審查 LOW-3）。
    return Action.PERMISSIONS if current[0] == value else Action.UPDATED


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
    except OSError as exc:
        raise SecretFilesError(f"無法確認 {name}（{_reason(exc)}）") from None
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
    """以暫存檔原子替換一個檔案；失敗時拋出 ReplaceError。

    G1d：rename 之後（或 rename 回報 EIO）失敗時，不宣稱原本的檔案沒有改變。
    """
    temporary = f"{TEMP_PREFIX}{name}.{secrets.token_hex(8)}"
    try:
        _write_new(descriptor, temporary, value)
    except OSError as exc:
        raise _not_replaced(descriptor, temporary, name, exc) from None
    try:
        os.rename(temporary, name, src_dir_fd=descriptor, dst_dir_fd=descriptor)
    except OSError as exc:
        # POSIX 的 rename（DESCRIPTION）：EIO 以外的失敗不影響 new；EIO 時無法確認 rename 是否已經
        # 發生。網路檔案系統等不符合規格的實作不在保證之內（secrets/ 在本機的檔案系統）。
        if exc.errno != errno.EIO:
            raise _not_replaced(descriptor, temporary, name, exc) from None
        left = _leftover(descriptor, temporary)
        raise ReplaceError(
            f"無法確認 {name} 是否已換成新的內容（rename 回報 {_reason(exc)}）{left}",
            uncertain=True,
        ) from None
    try:
        os.fsync(descriptor)
    except OSError as exc:
        raise ReplaceError(
            f"{name} 已換成新的內容，但目錄的 fsync 失敗（{_reason(exc)}）：無法確認已寫入磁碟，"
            "當機或斷電時可能回到原本的內容",
            uncertain=True,
        ) from None


def _not_replaced(descriptor: int, temporary: str, name: str, exc: OSError) -> ReplaceError:
    """rename 之前失敗：原本的檔案沒有改變。暫存檔刪不掉時一併回報，不蓋掉原本的錯誤。"""
    left = _leftover(descriptor, temporary)
    return ReplaceError(
        f"無法寫入 {name}（{_reason(exc)}）：原本的檔案沒有改變{left}", uncertain=False
    )


def _leftover(descriptor: int, temporary: str) -> str:
    """刪除暫存檔；刪不掉時回傳要附在訊息後面的說明（說明不含值；留下的暫存檔含秘密的值、0600，
    下一次執行時清除）。"""
    return "" if _discard(descriptor, temporary) else "；暫存檔可能留著（下一次執行時清除）"


def _reason(exc: OSError) -> str:
    return exc.strerror or type(exc).__name__


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


def _discard(descriptor: int, name: str) -> bool:
    """刪除自己的暫存檔；刪不掉時回傳 False（不拋出，以免蓋掉原本的錯誤；下一次執行時清除）。"""
    try:
        os.unlink(name, dir_fd=descriptor)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return True


def _remove_stale_temporaries(descriptor: int) -> None:
    try:
        for name in os.listdir(descriptor):
            if not name.startswith(TEMP_PREFIX):
                continue
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISREG(info.st_mode):
                os.unlink(name, dir_fd=descriptor)
    except OSError as exc:
        raise SecretFilesError(
            f"無法清除上次留下的暫存檔（{_reason(exc)}）：沒有寫入任何檔案"
        ) from None


def _report_unknown(descriptor: int, report: Report) -> None:
    known = {item.file_name for item in SECRET_FILES}
    try:
        names = os.listdir(descriptor)
    except OSError as exc:
        raise SecretFilesError(
            f"無法列出 secrets/ 中的其他檔案（{_reason(exc)}）；七個秘密檔都已處理（見上面）"
        ) from None
    unknown = sorted(name for name in names if name not in known)
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
