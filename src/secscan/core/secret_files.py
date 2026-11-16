"""`*_FILE` 秘密檔的讀取（T23b-b2；docs/DECISIONS.md §32）。

compose secrets 把每個秘密掛載成 `/run/secrets/<名稱>` 的唯讀檔案，設定以 `X_FILE` 指向它。
這裡只負責「安全地讀一個秘密檔」，和欄位無關：

- 開檔：`O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK`。最後一段是 symlink 就拒絕；FIFO 不會卡在
  開檔（O_NONBLOCK），之後由 fstat 拒絕。只接受一般檔案。
- 大小：不信任 `st_size`，最多讀 4096 + 1 bytes，超過就拒絕。
- 內容：只接受可列印的 ASCII（0x21 到 0x7E，不含空白），長度 1 到 4095（上限和 initdb 的 awk
  相同；DB 密碼的下限 32 由 sync-secret-files 與 initdb 檢查，這裡不檢查），最多容許一個結尾的
  換行。CR、第二行、控制字元與非 ASCII 一律拒絕。
- 所有錯誤都轉成固定訊息的 SecretFileError（ValueError 的子類別：在 validator 中會變成
  ValidationError）。訊息只有設定的名稱與原因，不含檔案內容；例外不帶原本的 OSError（`__context__`
  是 None），也不會產生帶著 bytes 的 UnicodeDecodeError。

不使用 pydantic-settings 的 secrets_dir：它會 strip、目錄不存在只警告、is_file() 跟隨 symlink，
而且和環境變數同時有值時靜默採用其中一個（docs/DECISIONS.md §32）。
"""

import errno
import os
import stat
from collections.abc import Iterable, Mapping

MAX_SECRET_LENGTH = 4095
# DB 角色的密碼至少 32 個字元：initdb（deploy/postgres/initdb/10-roles.sql 的 awk）在第一次初始化時
# 檢查 owner 與應用程式角色的密碼，sync-secret-files 對四個 DB 密碼套用同樣的規則（G1 審查 L6、
# LOW-3、資料庫 LOW-1）。讀取（read_secret_file）不檢查下限：金鑰等其他秘密也經過這裡。
MIN_DB_PASSWORD_LENGTH = 32
# 值加上一個結尾的換行；多讀 1 byte 才分辨得出「剛好」與「超過」。
MAX_SECRET_FILE_BYTES = MAX_SECRET_LENGTH + 1
_READ_LIMIT = MAX_SECRET_FILE_BYTES + 1
_CHUNK = 1024
_OPEN_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_FIRST_PRINTABLE = 0x21
_LAST_PRINTABLE = 0x7E
FILE_SUFFIX = "_file"

IS_SYMLINK = "不可以是 symlink"
CANNOT_OPEN = "無法開啟"
NOT_REGULAR = "必須是一般檔案"
CANNOT_READ = "無法讀取"
EMPTY = "是空的"
TOO_LONG = f"超過 {MAX_SECRET_LENGTH} 個字元"
NOT_ONE_LINE = "只能有一行可列印的 ASCII（不含空白、CR 與控制字元）"
NOT_A_PATH = "必須是檔案路徑"


class SecretFileError(ValueError):
    """秘密檔不符合規則；訊息固定，只有設定的名稱與原因。"""

    def __init__(self, label: str, reason: str) -> None:
        super().__init__(f"{label} 指向的秘密檔{reason}")


def read_secret_file(path: str | os.PathLike[str], *, label: str) -> str:
    """讀取一個秘密檔，回傳去掉結尾換行之後的值。

    label 是錯誤訊息中的設定名稱（例如 DB_PASSWORD_FILE）。
    """
    data = _read_regular_file(os.fspath(path), label)
    return _decode(data, label)


def resolve_secret_files(data: object, fields: Iterable[str], *, env_prefix: str = "") -> object:
    """設定類別的 before validator 用：`<欄位>_file` 有值時讀檔，放進 `<欄位>`。

    - 輸入不是 Mapping 時照原樣回傳；回傳新的 dict，不修改輸入。
    - None 視為沒有設定；`X` 與 `X_FILE` 同時有值（含空字串）時拒絕，訊息只有兩個設定的名稱。
    - 讀完之後把 `X_FILE` 設成 None：model_dump() 的結果再驗證一次時不會被誤判為同時設定。
    """
    if not isinstance(data, Mapping):
        return data
    resolved = dict(data)
    for field in fields:
        file_field = f"{field}{FILE_SUFFIX}"
        path = resolved.get(file_field)
        if path is None:
            continue
        value_env = f"{env_prefix}{field}".upper()
        file_env = f"{env_prefix}{file_field}".upper()
        if resolved.get(field) is not None:
            raise ValueError(f"{value_env} 與 {file_env} 只能設定其中一個")
        if not isinstance(path, str | os.PathLike):
            raise SecretFileError(file_env, NOT_A_PATH)
        resolved[field] = read_secret_file(path, label=file_env)
        resolved[file_field] = None
    return resolved


def _read_regular_file(path: str, label: str) -> bytes:
    reason: str | None = None
    try:
        descriptor = os.open(path, _OPEN_FLAGS)
    except OSError as exc:
        reason = IS_SYMLINK if exc.errno == errno.ELOOP else CANNOT_OPEN
    if reason is not None:
        raise SecretFileError(label, reason)
    try:
        return _read_descriptor(descriptor, label)
    finally:
        os.close(descriptor)


def _read_descriptor(descriptor: int, label: str) -> bytes:
    reason: str | None = None
    data = b""
    try:
        if stat.S_ISREG(os.fstat(descriptor).st_mode):
            data = _read_at_most(descriptor, _READ_LIMIT)
        else:
            reason = NOT_REGULAR
    except OSError:
        reason = CANNOT_READ
    if reason is not None:
        raise SecretFileError(label, reason)
    return data


def _read_at_most(descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total < limit:
        chunk = os.read(descriptor, min(_CHUNK, limit - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _decode(data: bytes, label: str) -> str:
    if len(data) > MAX_SECRET_FILE_BYTES:
        raise SecretFileError(label, TOO_LONG)
    value = data.removesuffix(b"\n")
    if not value:
        raise SecretFileError(label, EMPTY)
    if len(value) > MAX_SECRET_LENGTH:
        raise SecretFileError(label, TOO_LONG)
    if not all(_FIRST_PRINTABLE <= byte <= _LAST_PRINTABLE for byte in value):
        raise SecretFileError(label, NOT_ONE_LINE)
    return value.decode("ascii")
