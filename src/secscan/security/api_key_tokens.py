"""平台 API key 的產生、格式檢查與雜湊（docs/DECISIONS.md §9.1）。只用標準函式庫。

格式：secscan_<prefix>_<secret>
- prefix：16 個小寫 hex（64-bit），公開的識別碼，存在 DB，驗證時用來查詢。
- secret：64 個小寫 hex（256-bit），只在建立時出現一次。

DB 只存 prefix 與完整 key 的 SHA-256。key 是高熵亂數，離線猜測不可行，所以不用慢雜湊。
"""

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field

KEY_LABEL = "secscan"
PREFIX_BYTES = 8
SECRET_BYTES = 32
KEY_LENGTH = len(KEY_LABEL) + 1 + PREFIX_BYTES * 2 + 1 + SECRET_BYTES * 2
# 只接受小寫 ASCII hex：[0-9a-f] 不會像 \d 一樣比對到全形或其他語系的數字。
_KEY_PATTERN = re.compile(
    rf"{KEY_LABEL}_(?P<prefix>[0-9a-f]{{{PREFIX_BYTES * 2}}})_[0-9a-f]{{{SECRET_BYTES * 2}}}"
)


@dataclass(frozen=True, slots=True)
class GeneratedKey:
    """剛產生的 key；完整值不出現在 repr。"""

    prefix: str
    value: str = field(repr=False)


def generate_key() -> GeneratedKey:
    """prefix 與 secret 分兩次向 OS 的 CSPRNG 取亂數：公開的 prefix 不是 secret 的一部分。"""
    prefix = secrets.token_hex(PREFIX_BYTES)
    secret = secrets.token_hex(SECRET_BYTES)
    return GeneratedKey(prefix=prefix, value=f"{KEY_LABEL}_{prefix}_{secret}")


def parse_prefix(value: str) -> str | None:
    """格式完全正確時回傳 prefix，否則回傳 None。先比長度，超長的輸入不進 regex。"""
    if len(value) != KEY_LENGTH:
        return None
    match = _KEY_PATTERN.fullmatch(value)
    return match.group("prefix") if match is not None else None


def hash_key(value: str) -> bytes:
    """完整 key 的 SHA-256（32 bytes），存在 api_keys.key_hash。"""
    return hashlib.sha256(value.encode()).digest()


def key_matches(value: str, expected_hash: bytes) -> bool:
    """以常數時間比對，不讓回應時間透露 hash 從第幾個 byte 開始不同。"""
    return hmac.compare_digest(hash_key(value), expected_hash)
