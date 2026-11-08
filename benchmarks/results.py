"""結果目錄（BENCH-03；SECURITY_AND_TESTING.md §8）：獨占建立、不覆寫、限制權限、寫入前檢查秘密。

- 目錄 0700、檔案 0600，以 O_EXCL 建立：同名的結果不會被覆寫，重跑一定換新的 BENCH_NAME。
- **沒有加密**（加密保存是 T23a 的範圍）：文件與 manifest 如實揭露。
- 寫入前檢查秘密：平台 API key 的格式、Bearer 與 JWT 的樣式，以及這次 session 建立的秘密原值
  （呼叫端傳入）。發現時拒絕寫入，訊息只說明種類，不印出值。
- SHA256SUMS 記下每個檔案的 sha256；評估之前先核對。
"""

import hashlib
import json
import os
import re
from collections.abc import Collection
from pathlib import Path
from typing import Any

DIRECTORY_MODE = 0o700
FILE_MODE = 0o600
CHECKSUMS = "SHA256SUMS"
MIN_KNOWN_SECRET_LENGTH = 8
_FILE_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_PATTERNS = {
    "platform_api_key": re.compile(r"secscan_[0-9a-f]{16}_[0-9a-f]{64}"),
    "bearer_token": re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{16,}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
}


class ResultsError(ValueError):
    """結果目錄的操作不符合規則（已存在、名稱不合、檔案被改過）。"""


class SecretLeakError(ResultsError):
    """要寫入的內容含有秘密；訊息只列出種類。"""


def reserve(root: Path, name: str) -> Path:
    """建立 root/name（0700）；已經存在就失敗，不重用、不覆寫。"""
    if _FILE_NAME.fullmatch(name) is None or name.startswith("."):
        raise ResultsError("結果目錄的名稱不合規則")
    root.mkdir(mode=DIRECTORY_MODE, parents=True, exist_ok=True)
    directory = root / name
    try:
        directory.mkdir(mode=DIRECTORY_MODE)
    except FileExistsError:
        raise ResultsError("結果目錄已經存在；請換一個新的名稱") from None
    directory.chmod(DIRECTORY_MODE)
    return directory


def find_secrets(text: str, known: Collection[str] = ()) -> list[str]:
    """出現的秘密種類（不含值）。known 中太短的值不比對，避免誤判一般字串。"""
    kinds = [kind for kind, pattern in _PATTERNS.items() if pattern.search(text)]
    if any(len(value) >= MIN_KNOWN_SECRET_LENGTH and value in text for value in known):
        kinds.append("session_secret")
    return kinds


def canonical_json(document: object) -> bytes:
    return (
        json.dumps(document, sort_keys=True, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")


def write_json(directory: Path, name: str, document: object, *, known: Collection[str] = ()) -> str:
    """以 canonical JSON 獨占寫入 directory/name（0600），回傳 sha256。"""
    return write_bytes(directory, name, canonical_json(document), known=known)


def write_bytes(directory: Path, name: str, content: bytes, *, known: Collection[str] = ()) -> str:
    if _FILE_NAME.fullmatch(name) is None or name.startswith(".") or name == CHECKSUMS:
        raise ResultsError("檔名不合規則")
    leaks = find_secrets(content.decode("utf-8", errors="replace"), known)
    if leaks:
        raise SecretLeakError(f"內容含有秘密（{'、'.join(sorted(set(leaks)))}），拒絕寫入")
    _create(directory / name, content)
    return hashlib.sha256(content).hexdigest()


def seal(directory: Path) -> dict[str, str]:
    """寫入 SHA256SUMS（目錄中所有檔案，依名稱排序）；之後不再寫入。"""
    digests = _digests(directory)
    lines = "".join(f"{digest}  {name}\n" for name, digest in sorted(digests.items()))
    _create(directory / CHECKSUMS, lines.encode("ascii"))
    return digests


def verify(directory: Path) -> dict[str, str]:
    """核對 SHA256SUMS；檔案多出、缺少或內容不同都失敗。"""
    path = directory / CHECKSUMS
    if not path.is_file():
        raise ResultsError("缺少 SHA256SUMS（session 沒有正常結束）")
    expected: dict[str, str] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        digest, _, name = line.partition("  ")
        expected[name] = digest
    if _digests(directory) != expected:
        raise ResultsError("結果目錄的檔案和 SHA256SUMS 不符")
    return expected


def read_json(directory: Path, name: str) -> Any:
    if _FILE_NAME.fullmatch(name) is None:
        raise ResultsError("檔名不合規則")
    return json.loads((directory / name).read_text(encoding="utf-8"))


def _digests(directory: Path) -> dict[str, str]:
    digests: dict[str, str] = {}
    for path in sorted(directory.iterdir()):
        if path.name == CHECKSUMS:
            continue
        if not path.is_file() or path.is_symlink():
            raise ResultsError("結果目錄只能有一般檔案")
        digests[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return digests


def _create(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, FILE_MODE)
    except FileExistsError:
        raise ResultsError("檔案已經存在；結果不覆寫") from None
    # 以檔案描述子設定權限（不再經過路徑）：umask 不會讓權限和 0600 不同。
    os.fchmod(descriptor, FILE_MODE)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(content)
