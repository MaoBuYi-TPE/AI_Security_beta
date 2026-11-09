"""benchmarks/results 的加密（T23a；docs/DECISIONS.md §30.7）。

benchmarks 中唯一使用 cryptography 的模組。


- 金鑰檔：BENCH_KEY_FILE，預設 ~/.config/secscan/bench-keys；一行一把 Fernet 金鑰（1 到 4 把，
  第一把用來加密，其餘只用來解密）。必須是一般檔案（以 O_NOFOLLOW 開檔、對 fd 檢查，不是
  symlink）、只有擁有者能讀寫（0600 或 0400）、屬於目前的使用者；上層目錄屬於目前的使用者而且
  別人不能寫入；不在 repo 與結果目錄之中。金鑰一律不輸出。
- 每個結果檔加密成一個 Fernet token：明文是 `BENCH_MAGIC + context + "\\n" + 內容`，context 是
  `<結果目錄的名稱>/<檔名>`，改名或搬到別的結果目錄都解不開。
- benchmarks 是黑箱、不 import secscan（BENCH-11）：這裡自己包裝 Fernet（和平台的
  security/blob_cipher 單一 token 相同的作法）。
- 金鑰遺失之後結果無法復原：請另外備份金鑰檔。
"""

import base64
import errno
import os
import re
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Self

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

KEY_FILE_VARIABLE = "BENCH_KEY_FILE"
DEFAULT_KEY_FILE = Path("~/.config/secscan/bench-keys")
REPO_ROOT = Path(__file__).resolve().parents[1]
MAX_KEYS = 4
MAX_PLAINTEXT_BYTES = 64 * 1024 * 1024
BENCH_MAGIC = b"secscan.bench/1\n"
_KEY = re.compile(r"[A-Za-z0-9_-]{43}=")
_CONTEXT = re.compile(r"[A-Za-z0-9_.-]{1,128}/[A-Za-z0-9_.-]{1,128}")
_PRIVATE_DIR = 0o700
_PRIVATE_FILE = 0o600
_MAX_KEY_FILE_BYTES = 4096
_MISSING = f"找不到 bench 的金鑰檔：請先執行 make bench-key，或以 {KEY_FILE_VARIABLE} 指定"


class SealingError(ValueError):
    """金鑰檔或密文的問題；訊息不含金鑰或內容。"""


def key_file_path(environ: Mapping[str, str] = os.environ) -> Path:
    """BENCH_KEY_FILE，或預設的 ~/.config/secscan/bench-keys。"""
    configured = environ.get(KEY_FILE_VARIABLE, "")
    return Path(configured or DEFAULT_KEY_FILE).expanduser()


class BenchKeys:
    """bench 結果的金鑰；repr 只顯示數量。"""

    def __init__(self, keys: Sequence[str]) -> None:
        """keys 是金鑰的文字（已經過 _parse 的檢查，或測試直接產生的金鑰）。"""
        if not keys:
            raise SealingError("bench 的金鑰檔至少要有一把金鑰")
        self._fernet = MultiFernet([Fernet(key) for key in keys])
        self._count = len(keys)
        self._texts = frozenset(keys)

    @classmethod
    def load(cls, path: Path, *, forbidden: Sequence[Path] = (REPO_ROOT,)) -> Self:
        """讀金鑰檔（先檢查位置與上層目錄，再以 O_NOFOLLOW 開檔、對 fd 檢查類型、擁有者與權限）；
        不合規則時拋出 SealingError。"""
        _check_location(path, forbidden)
        _check_parent(path.parent)
        return cls(_parse(_read_key_file(path)))

    def __repr__(self) -> str:
        return f"BenchKeys(keys={self._count})"

    def contains_key(self, text: str) -> bool:
        """text 中是否出現任何一把金鑰（寫入前的秘密檢查用）。"""
        return any(key in text for key in self._texts)

    def seal(self, content: bytes, *, context: str) -> bytes:
        _check_context(context)
        if len(content) > MAX_PLAINTEXT_BYTES:
            raise SealingError(f"結果檔不可超過 {MAX_PLAINTEXT_BYTES:,} bytes")
        return self._fernet.encrypt(BENCH_MAGIC + context.encode("ascii") + b"\n" + content)

    def unseal(self, token: bytes, *, context: str) -> bytes:
        _check_context(context)
        try:
            plaintext = self._fernet.decrypt(token)
        except InvalidToken:
            raise SealingError("結果檔解不開：金鑰不對，或內容被改過") from None
        if not plaintext.startswith(BENCH_MAGIC):
            raise SealingError("結果檔不是預期的格式")
        found, separator, content = plaintext[len(BENCH_MAGIC) :].partition(b"\n")
        if not separator or found != context.encode("ascii"):
            raise SealingError("結果檔不屬於這個位置（改名或搬到別的結果目錄）")
        return content


def create_key_file(path: Path, *, forbidden: Sequence[Path] = (REPO_ROOT,)) -> None:
    """以 O_EXCL 建立新的金鑰檔（0600，上層目錄 0700）；已經存在就失敗，不覆寫。"""
    _check_location(path, forbidden)
    path.parent.mkdir(mode=_PRIVATE_DIR, parents=True, exist_ok=True)
    _check_parent(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, _PRIVATE_FILE)
    except FileExistsError:
        raise SealingError("bench 的金鑰檔已經存在；不覆寫（換版請手動編輯）") from None
    try:
        os.fchmod(descriptor, _PRIVATE_FILE)
        os.write(descriptor, Fernet.generate_key() + b"\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _parse(text: str) -> list[str]:
    entries = [line.strip() for line in text.splitlines() if line.strip()]
    if not 1 <= len(entries) <= MAX_KEYS:
        raise SealingError(f"bench 的金鑰檔必須有 1 到 {MAX_KEYS} 把金鑰（一行一把）")
    seen: set[bytes] = set()
    for position, entry in enumerate(entries, start=1):
        if _KEY.fullmatch(entry) is None:
            raise SealingError(f"bench 的金鑰檔的第 {position} 把金鑰不是有效的 Fernet 金鑰")
        raw = base64.urlsafe_b64decode(entry)
        if raw in seen:
            raise SealingError(f"bench 的金鑰檔的第 {position} 把金鑰與前面的重複")
        seen.add(raw)
    return entries


def _read_key_file(path: Path) -> str:
    """以 O_NOFOLLOW 開檔，對開好的 fd 檢查（檢查之後才換成 symlink 也讀不到別的檔案）。"""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        raise SealingError(_MISSING) from None
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise SealingError("bench 的金鑰檔必須是一般檔案（不可是 symlink）") from None
        raise SealingError(f"bench 的金鑰檔讀不到（{type(error).__name__}）") from None
    try:
        _check_opened(os.fstat(descriptor))
        content = os.read(descriptor, _MAX_KEY_FILE_BYTES)
    except OSError as error:
        raise SealingError(f"bench 的金鑰檔讀不到（{type(error).__name__}）") from None
    finally:
        os.close(descriptor)
    try:
        return content.decode("ascii")
    except UnicodeDecodeError:
        raise SealingError("bench 的金鑰檔讀不到（UnicodeDecodeError）") from None


def _check_opened(info: os.stat_result) -> None:
    if not stat.S_ISREG(info.st_mode):
        raise SealingError("bench 的金鑰檔必須是一般檔案（不可是 symlink）")
    if info.st_mode & 0o077:
        raise SealingError("bench 的金鑰檔只能由擁有者讀寫（權限 0600）")
    if info.st_uid != os.getuid():
        raise SealingError("bench 的金鑰檔必須屬於目前的使用者")


def _check_parent(directory: Path) -> None:
    """上層目錄屬於目前的使用者，而且 group 與 other 不能寫入（否則金鑰檔可以被換掉）。"""
    try:
        info = directory.lstat()
    except FileNotFoundError:
        raise SealingError(_MISSING) from None
    except OSError as error:
        raise SealingError(f"bench 金鑰檔的上層目錄讀不到（{type(error).__name__}）") from None
    if not stat.S_ISDIR(info.st_mode):
        raise SealingError("bench 金鑰檔的上層目錄必須是目錄（不可是 symlink）")
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise SealingError("bench 金鑰檔的上層目錄必須屬於目前的使用者，而且別人不能寫入")


def _check_location(path: Path, forbidden: Sequence[Path]) -> None:
    resolved = path.expanduser().resolve()
    for root in forbidden:
        if resolved.is_relative_to(root.resolve()):
            raise SealingError("bench 的金鑰檔不可放在 repo 或結果目錄之中")


def _check_context(context: str) -> None:
    if _CONTEXT.fullmatch(context) is None:
        raise SealingError("結果檔的 context 必須是 <結果目錄>/<檔名>")
