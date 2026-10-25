"""目標 secret 的加密（docs/DECISIONS.md §12.1）：MultiFernet，第一個金鑰加密，每個金鑰都能解密。

- 加密的是 `{"context": …, "v": 1, "value": …}` 的 JSON：Fernet 沒有 associated data，以 context
  把密文綁定在它的位置（例如 `auth_profile:<id>`），搬到別處就解不開。
- 金鑰的設定（SECRET_ENCRYPTION_KEYS）：逗號分隔、1 到 4 個、不可重複，每個都是 url-safe base64
  的 32 bytes（44 個字元）。訊息只說是第幾個，不含金鑰。
- `reveal` 只給要把 secret 送出去的程序使用（M2 的 runner）；API 從不解密，
  tests/unit/test_secret_reveal_callers.py 檢查 src 中的呼叫者。
- 例外不帶明文、金鑰或密文，也不接上 cryptography 的原始例外。
"""

import base64
import json
import re
from collections.abc import Sequence
from typing import Self

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

SETTING_NAME = "SECRET_ENCRYPTION_KEYS"
MAX_KEYS = 4
# url-safe base64 的 32 bytes：43 個字元加上一個 =。先以樣式檢查，因為 base64 的解碼器
# 會略過不認得的字元。
_KEY_TEXT = re.compile(r"[A-Za-z0-9_-]{43}=")
ENVELOPE_VERSION = 1
CONTEXT_MAX_LENGTH = 128
_CONTEXT = re.compile(rf"[!-~]{{1,{CONTEXT_MAX_LENGTH}}}")
# 包裝之後的明文上限：Fernet 適合放得進記憶體的小資料；目標的 secret 遠小於這個值。
MAX_PLAINTEXT_BYTES = 16 * 1024
_ENVELOPE_KEYS = frozenset({"context", "v", "value"})
# Fernet token 的 bytes：版本（1）、時間戳記（8）、IV（16）、密文（16 的倍數）、HMAC（32），
# 再以 base64url 編碼。
_TOKEN_FIXED_BYTES = 1 + 8 + 16 + 32
_BLOCK_BYTES = 16


class InvalidEncryptionKeysError(ValueError):
    """金鑰的設定不合規則；訊息不含金鑰。"""


class SecretUnreadableError(Exception):
    """密文解不開：金鑰不對、內容被改過，或不屬於這個位置（context 不符）。"""


class SecretCipher:
    """以 MultiFernet 加密、解密與重新加密；repr 只顯示金鑰的數量。"""

    def __init__(self, keys: Sequence[Fernet]) -> None:
        if not keys:
            raise InvalidEncryptionKeysError(f"{SETTING_NAME} 至少要有一個金鑰")
        self._fernet = MultiFernet(list(keys))
        self._key_count = len(keys)

    @classmethod
    def from_setting(cls, setting: str) -> Self:
        return cls(parse_keys(setting))

    def __repr__(self) -> str:
        return f"SecretCipher(keys={self._key_count})"

    def seal(self, value: str, *, context: str) -> bytes:
        """以第一個金鑰加密；每次都用新的 IV，同一個值的密文每次都不同。"""
        _check_context(context)
        plaintext = _envelope(value, context)
        if len(plaintext) > MAX_PLAINTEXT_BYTES:
            raise ValueError(f"要加密的內容不可超過 {MAX_PLAINTEXT_BYTES:,} bytes")
        return self._fernet.encrypt(plaintext)

    def reveal(self, token: bytes, *, context: str) -> str:
        """解密並確認 context；不符或解不開時拋出 SecretUnreadableError。"""
        return self._open(token, context)

    def rotate(self, token: bytes, *, context: str) -> bytes:
        """改用第一個金鑰重新加密（保留原本的時間戳記），並確認 context 仍然相符。"""
        _check_context(context)
        try:
            rotated = self._fernet.rotate(token)
        except InvalidToken:
            raise _unreadable() from None
        self._open(rotated, context)
        return rotated

    def _open(self, token: bytes, context: str) -> str:
        _check_context(context)
        try:
            plaintext = self._fernet.decrypt(token)
        except InvalidToken:
            raise _unreadable() from None
        return _unwrap(plaintext, context)


def parse_keys(setting: str) -> tuple[Fernet, ...]:
    """SECRET_ENCRYPTION_KEYS 的內容；不合規則時拋出 InvalidEncryptionKeysError（不含金鑰）。"""
    entries = setting.split(",")
    if len(entries) > MAX_KEYS:
        raise InvalidEncryptionKeysError(
            f"{SETTING_NAME} 最多 {MAX_KEYS} 個金鑰（換版時只需要新、舊兩個）"
        )
    seen: set[bytes] = set()
    keys: list[Fernet] = []
    for position, entry in enumerate(entries, start=1):
        if _KEY_TEXT.fullmatch(entry) is None:
            raise InvalidEncryptionKeysError(
                f"{SETTING_NAME} 的第 {position} 個金鑰不是有效的 Fernet 金鑰"
                "（url-safe base64 編碼的 32 bytes，共 44 個字元；"
                "金鑰之間只用逗號分隔，不可有空白）"
            )
        raw = base64.urlsafe_b64decode(entry)
        if raw in seen:
            raise InvalidEncryptionKeysError(f"{SETTING_NAME} 的第 {position} 個金鑰與前面的重複")
        seen.add(raw)
        keys.append(Fernet(entry))
    return tuple(keys)


def max_token_bytes(plaintext_bytes: int) -> int:
    """明文是 plaintext_bytes 時 Fernet token 的長度：PKCS7 一定會補 padding，再以 base64 編碼。"""
    ciphertext = (plaintext_bytes // _BLOCK_BYTES + 1) * _BLOCK_BYTES
    raw = _TOKEN_FIXED_BYTES + ciphertext
    return 4 * ((raw + 2) // 3)


def max_sealed_bytes(*, context_length: int, value_json_bytes: int) -> int:
    """seal 的結果最多多長（DB 的 CHECK 用）。

    value_json_bytes 是值在 JSON 中最長的長度（含跳脫）。
    """
    overhead = len(_envelope("", ""))
    return max_token_bytes(overhead + context_length + value_json_bytes)


def _envelope(value: str, context: str) -> bytes:
    payload = {"context": context, "v": ENVELOPE_VERSION, "value": value}
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()


def _unwrap(plaintext: bytes, context: str) -> str:
    try:
        payload = json.loads(plaintext)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SecretUnreadableError("密文的內容不是預期的格式") from None
    if not isinstance(payload, dict) or payload.keys() != _ENVELOPE_KEYS:
        raise SecretUnreadableError("密文的內容不是預期的格式")
    version, value = payload["v"], payload["value"]
    # bool 是 int 的子類別：True == 1，必須比對型別。
    if type(version) is not int or version != ENVELOPE_VERSION or not isinstance(value, str):
        raise SecretUnreadableError("密文的內容不是預期的格式")
    if payload["context"] != context:
        raise SecretUnreadableError("密文不屬於這個位置（context 不符）")
    return value


def _check_context(context: str) -> None:
    if _CONTEXT.fullmatch(context) is None:
        raise ValueError(f"context 必須是 1 到 {CONTEXT_MAX_LENGTH} 個 ASCII 可見字元")


def _unreadable() -> SecretUnreadableError:
    return SecretUnreadableError("密文解不開：金鑰不對，或內容被改過")
