"""結果目錄（BENCH-03、BSEAL-01；SECURITY_AND_TESTING.md §8；docs/DECISIONS.md §30.7）。

- 目錄 0700、檔案 0600，以 O_EXCL 建立：同名的結果不會被覆寫，重跑一定換新的 BENCH_NAME。
- 每個檔案都以 bench 的金鑰加密（benchmarks/sealing.py），寫成 `<檔名>.sealed`；明文不寫到磁碟，
  也沒有明文的暫存檔。context 是 `<結果目錄的名稱>/<檔名>`。
- 寫入前檢查秘密（明文）：平台 API key 的格式、Bearer 與 JWT 的樣式、Fernet 金鑰的形狀、bench 的
  金鑰，以及這次 session 建立的秘密原值（呼叫端傳入）。發現時拒絕寫入，訊息只說明種類，不印出值。
- SHA256SUMS 是明文的清單，記下每個加密檔的 sha256：沒有金鑰也能核對完整性。manifest 另外記下
  每個檔案明文與密文的 sha256（雙重 sha256）；評估時先核對 SHA256SUMS，再解密、核對明文。
- 結果目錄只能有加密檔與 SHA256SUMS：明文的檔案（例如 T23a 之前的結果）一律拒絕，改以
  make bench-seal 轉換（benchmarks/legacy.py）。
"""

import hashlib
import json
import os
import re
from collections.abc import Collection
from pathlib import Path
from typing import Any

from benchmarks.models import FileDigests
from benchmarks.sealing import BenchKeys

DIRECTORY_MODE = 0o700
FILE_MODE = 0o600
CHECKSUMS = "SHA256SUMS"
SEALED_SUFFIX = ".sealed"
MIN_KNOWN_SECRET_LENGTH = 8
_FILE_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_PATTERNS = {
    "platform_api_key": re.compile(r"secscan_[0-9a-f]{16}_[0-9a-f]{64}"),
    "bearer_token": re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{16,}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    # 單獨出現的 url-safe base64 32 bytes（平台與 bench 的 Fernet 金鑰都是這個形狀）。
    "fernet_key": re.compile(r"(?<![A-Za-z0-9_=-])[A-Za-z0-9_-]{43}=(?![A-Za-z0-9_=-])"),
}


class ResultsError(ValueError):
    """結果目錄的操作不符合規則（已存在、名稱不合、檔案被改過、有明文的檔案）。"""


class SecretLeakError(ResultsError):
    """要寫入的內容含有秘密；訊息只列出種類。"""


def reserve(root: Path, name: str) -> Path:
    """建立 root/name（0700）；已經存在就失敗，不重用、不覆寫。"""
    _check_name(name, "結果目錄的名稱不合規則")
    root.mkdir(mode=DIRECTORY_MODE, parents=True, exist_ok=True)
    directory = root / name
    try:
        directory.mkdir(mode=DIRECTORY_MODE)
    except FileExistsError:
        raise ResultsError("結果目錄已經存在；請換一個新的名稱") from None
    directory.chmod(DIRECTORY_MODE)
    return directory


def find_secrets(
    text: str, known: Collection[str] = (), keys: BenchKeys | None = None
) -> list[str]:
    """出現的秘密種類（不含值）。known 中太短的值不比對，避免誤判一般字串。"""
    kinds = [kind for kind, pattern in _PATTERNS.items() if pattern.search(text)]
    if any(len(value) >= MIN_KNOWN_SECRET_LENGTH and value in text for value in known):
        kinds.append("session_secret")
    if keys is not None and keys.contains_key(text):
        kinds.append("bench_key")
    return kinds


def canonical_json(document: object) -> bytes:
    return (
        json.dumps(document, sort_keys=True, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")


def write_json(
    directory: Path,
    name: str,
    document: object,
    *,
    keys: BenchKeys,
    known: Collection[str] = (),
    batch: str | None = None,
) -> FileDigests:
    """以 canonical JSON 加密、獨占寫入 directory/<name>.sealed（0600）。"""
    return write_bytes(
        directory, name, canonical_json(document), keys=keys, known=known, batch=batch
    )


def write_bytes(
    directory: Path,
    name: str,
    content: bytes,
    *,
    keys: BenchKeys,
    known: Collection[str] = (),
    batch: str | None = None,
) -> FileDigests:
    """檢查秘密 → 加密 → 獨占寫入（fsync）；回傳明文與密文的 sha256。

    batch 是結果目錄最後的名稱（context 的一部分）；make bench-seal 寫進暫存的 partial 目錄時傳入。
    """
    _check_name(name, "檔名不合規則")
    if name == CHECKSUMS:
        raise ResultsError("檔名不合規則")
    leaks = find_secrets(content.decode("utf-8", errors="replace"), known, keys)
    if leaks:
        raise SecretLeakError(f"內容含有秘密（{'、'.join(sorted(set(leaks)))}），拒絕寫入")
    token = keys.seal(content, context=_context(directory, name, batch))
    _create(directory / f"{name}{SEALED_SUFFIX}", token)
    return FileDigests(
        sha256=hashlib.sha256(content).hexdigest(),
        sealed_sha256=hashlib.sha256(token).hexdigest(),
    )


def write_checksums(directory: Path) -> dict[str, str]:
    """寫入 SHA256SUMS（每個加密檔，依名稱排序）；之後不再寫入。"""
    digests = _digests(directory)
    lines = "".join(f"{digest}  {name}\n" for name, digest in sorted(digests.items()))
    _create(directory / CHECKSUMS, lines.encode("ascii"))
    return digests


def verify(directory: Path) -> dict[str, str]:
    """核對 SHA256SUMS（不需要金鑰）；檔案多出、缺少、內容不同或有明文的檔案都失敗。"""
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


def read_bytes(directory: Path, name: str, *, keys: BenchKeys, batch: str | None = None) -> bytes:
    """解密 directory/<name>.sealed（context 綁定結果目錄與檔名）。"""
    _check_name(name, "檔名不合規則")
    token = (directory / f"{name}{SEALED_SUFFIX}").read_bytes()
    return keys.unseal(token, context=_context(directory, name, batch))


def read_json(directory: Path, name: str, *, keys: BenchKeys) -> Any:
    return json.loads(read_bytes(directory, name, keys=keys))


def sealed_name(name: str) -> str:
    return f"{name}{SEALED_SUFFIX}"


def _context(directory: Path, name: str, batch: str | None) -> str:
    return f"{batch if batch is not None else directory.name}/{name}"


def _check_name(name: str, message: str) -> None:
    if _FILE_NAME.fullmatch(name) is None or name.startswith("."):
        raise ResultsError(message)


def _digests(directory: Path) -> dict[str, str]:
    digests: dict[str, str] = {}
    for path in sorted(directory.iterdir()):
        if path.name == CHECKSUMS:
            continue
        if not path.is_file() or path.is_symlink():
            raise ResultsError("結果目錄只能有一般檔案")
        if not path.name.endswith(SEALED_SUFFIX):
            raise ResultsError(
                "結果目錄中有明文的檔案：拒絕（T23a 之前的結果請以 make bench-seal 轉換）"
            )
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
        handle.flush()
        os.fsync(handle.fileno())
