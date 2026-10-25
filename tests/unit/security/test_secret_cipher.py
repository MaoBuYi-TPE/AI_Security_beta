"""目標 secret 的加密（docs/DECISIONS.md §12.1）：MultiFernet、context 綁定與金鑰的設定。

金鑰都在執行時以 Fernet.generate_key() 產生，不寫死在測試裡。
"""

import base64
import json

import pytest
from cryptography.fernet import Fernet
from hypothesis import given
from hypothesis import strategies as st

from secscan.security.secret_cipher import (
    MAX_KEYS,
    MAX_PLAINTEXT_BYTES,
    TOKEN_PREFIX,
    InvalidEncryptionKeysError,
    SecretCipher,
    SecretUnreadableError,
    max_sealed_bytes,
    max_token_bytes,
)

CONTEXT = "auth_profile:00000000-0000-4000-8000-000000000001"
OTHER_CONTEXT = "auth_profile:00000000-0000-4000-8000-000000000002"
CANARY = "canary-secret-t08-7f3a"
CONTEXTS = st.from_regex(r"[!-~]{1,128}", fullmatch=True)


def _key() -> str:
    return Fernet.generate_key().decode()


def _cipher(*keys: str) -> SecretCipher:
    return SecretCipher.from_setting(",".join(keys))


def _envelope(payload: object) -> bytes:
    return json.dumps(payload).encode()


# Hypothesis 的每個例子共用同一把金鑰與 token（產生金鑰不是要測的東西）。
TAMPER_KEY = _key()
TAMPER_TOKEN = _cipher(TAMPER_KEY).seal(CANARY, context=CONTEXT)
ROUND_TRIP_KEY = _key()


# --- 加密與解密 -----------------------------------------------------------------------------


def test_sealed_value_is_revealed_with_the_same_context() -> None:
    cipher = _cipher(_key())

    token = cipher.seal(CANARY, context=CONTEXT)

    assert cipher.reveal(token, context=CONTEXT) == CANARY


def test_token_does_not_contain_the_plaintext() -> None:
    token = _cipher(_key()).seal(CANARY, context=CONTEXT)

    assert CANARY.encode() not in token
    assert CANARY.encode() not in base64.urlsafe_b64decode(token)
    assert CONTEXT.encode() not in base64.urlsafe_b64decode(token)


def test_every_seal_uses_a_new_iv() -> None:
    cipher = _cipher(_key())

    assert cipher.seal(CANARY, context=CONTEXT) != cipher.seal(CANARY, context=CONTEXT)


def test_tokens_are_fernet_tokens() -> None:
    """DB 的 CHECK 依賴這個前綴：版本 0x80 加上時間戳記的高位元（西元 4147 年以前都是 0）。"""
    token = _cipher(_key()).seal(CANARY, context=CONTEXT)

    assert token.startswith(TOKEN_PREFIX)
    assert TOKEN_PREFIX == b"gAAAAA"


def test_a_token_moved_to_another_context_cannot_be_revealed() -> None:
    cipher = _cipher(_key())
    token = cipher.seal(CANARY, context=CONTEXT)

    with pytest.raises(SecretUnreadableError) as raised:
        cipher.reveal(token, context=OTHER_CONTEXT)

    assert CANARY not in str(raised.value)
    assert CONTEXT not in str(raised.value)


def test_another_key_cannot_reveal() -> None:
    token = _cipher(_key()).seal(CANARY, context=CONTEXT)

    with pytest.raises(SecretUnreadableError):
        _cipher(_key()).reveal(token, context=CONTEXT)


@given(position=st.integers(min_value=0), mask=st.integers(min_value=1, max_value=255))
def test_changing_any_byte_of_the_token_is_detected(position: int, mask: int) -> None:
    """HMAC 涵蓋 token 解碼後的每一個 byte（版本、時間戳記、IV、密文）：改動任何一個都解不開。

    改的是解碼後的 byte：base64 的文字中，`-` 與 `+` 解出相同的值，改字元不一定改到 token。
    """
    raw = bytearray(base64.urlsafe_b64decode(TAMPER_TOKEN))
    raw[position % len(raw)] ^= mask
    token = base64.urlsafe_b64encode(bytes(raw))

    with pytest.raises(SecretUnreadableError):
        _cipher(TAMPER_KEY).reveal(token, context=CONTEXT)


@pytest.mark.parametrize("token", [b"", b"not-a-token", b"gAAAAA", b"gAAAAA" * 20])
def test_malformed_tokens_are_unreadable(token: bytes) -> None:
    with pytest.raises(SecretUnreadableError):
        _cipher(_key()).reveal(token, context=CONTEXT)


@given(value=st.text(max_size=300), context=CONTEXTS)
def test_any_text_round_trips(value: str, context: str) -> None:
    cipher = _cipher(ROUND_TRIP_KEY)

    assert cipher.reveal(cipher.seal(value, context=context), context=context) == value


# --- 包裝的格式 -----------------------------------------------------------------------------


def test_plaintext_is_a_versioned_envelope_bound_to_the_context() -> None:
    key = _key()
    token = _cipher(key).seal(CANARY, context=CONTEXT)

    envelope = json.loads(Fernet(key).decrypt(token))

    assert envelope == {"context": CONTEXT, "v": 1, "value": CANARY}


@pytest.mark.parametrize(
    "payload",
    [
        {"context": CONTEXT, "v": 2, "value": CANARY},
        {"context": CONTEXT, "v": True, "value": CANARY},
        {"context": CONTEXT, "v": "1", "value": CANARY},
        {"context": CONTEXT, "value": CANARY},
        {"context": CONTEXT, "v": 1, "value": CANARY, "extra": 1},
        {"context": CONTEXT, "v": 1, "value": 123},
        {"context": OTHER_CONTEXT, "v": 1, "value": CANARY},
        [CONTEXT, 1, CANARY],
        CANARY,
    ],
)
def test_unexpected_envelopes_are_unreadable(payload: object) -> None:
    """以正確的金鑰加密、但內容不是預期的格式：只可能是程式錯誤或其他用途的 token。"""
    key = _key()
    token = Fernet(key).encrypt(_envelope(payload))

    with pytest.raises(SecretUnreadableError) as raised:
        _cipher(key).reveal(token, context=CONTEXT)

    assert CANARY not in str(raised.value)


def test_plaintext_that_is_not_json_is_unreadable() -> None:
    key = _key()
    token = Fernet(key).encrypt(b"\xff not json")

    with pytest.raises(SecretUnreadableError):
        _cipher(key).reveal(token, context=CONTEXT)


@pytest.mark.parametrize("context", ["", " ", "auth profile", "設定", "a" * 129, "a\n"])
def test_context_must_be_short_visible_ascii(context: str) -> None:
    cipher = _cipher(_key())

    with pytest.raises(ValueError, match="context"):
        cipher.seal(CANARY, context=context)
    with pytest.raises(ValueError, match="context"):
        cipher.reveal(b"gAAAAA", context=context)


def test_plaintext_size_is_limited_without_echoing_the_value() -> None:
    value = CANARY + "x" * MAX_PLAINTEXT_BYTES

    with pytest.raises(ValueError, match="bytes") as raised:
        _cipher(_key()).seal(value, context=CONTEXT)

    assert CANARY not in str(raised.value)


@pytest.mark.parametrize("plaintext_bytes", [0, 1, 15, 16, 17, 100, 4095, 4096, 8272])
def test_token_length_formula_is_exact(plaintext_bytes: int) -> None:
    token = Fernet(Fernet.generate_key()).encrypt(b"x" * plaintext_bytes)

    assert len(token) == max_token_bytes(plaintext_bytes)


def test_sealed_size_limit_covers_the_worst_case_escaping() -> None:
    """每個字元都要跳脫（例如 "）時，JSON 中的值是原本的兩倍長。"""
    value = '"' * 4096

    token = _cipher(_key()).seal(value, context=CONTEXT)

    assert len(token) == max_sealed_bytes(context_length=len(CONTEXT), value_json_bytes=2 * 4096)


# --- 多個金鑰與換版 -------------------------------------------------------------------------


def test_the_first_key_seals_and_every_key_reveals() -> None:
    old, new = _key(), _key()
    sealed_with_old = _cipher(old).seal(CANARY, context=CONTEXT)

    both = _cipher(new, old)
    sealed_with_both = both.seal(CANARY, context=CONTEXT)

    assert both.reveal(sealed_with_old, context=CONTEXT) == CANARY
    assert _cipher(new).reveal(sealed_with_both, context=CONTEXT) == CANARY
    with pytest.raises(SecretUnreadableError):
        _cipher(old).reveal(sealed_with_both, context=CONTEXT)


def test_rotate_reencrypts_under_the_first_key() -> None:
    old, new = _key(), _key()
    token = _cipher(old).seal(CANARY, context=CONTEXT)

    rotated = _cipher(new, old).rotate(token, context=CONTEXT)

    assert rotated != token
    assert _cipher(new).reveal(rotated, context=CONTEXT) == CANARY
    assert Fernet(new).extract_timestamp(rotated) == Fernet(old).extract_timestamp(token)


def test_rotate_checks_the_context() -> None:
    old, new = _key(), _key()
    token = _cipher(old).seal(CANARY, context=CONTEXT)

    with pytest.raises(SecretUnreadableError):
        _cipher(new, old).rotate(token, context=OTHER_CONTEXT)


def test_rotate_refuses_tokens_that_no_key_can_read() -> None:
    token = _cipher(_key()).seal(CANARY, context=CONTEXT)

    with pytest.raises(SecretUnreadableError):
        _cipher(_key(), _key()).rotate(token, context=CONTEXT)


# --- 金鑰的設定 -----------------------------------------------------------------------------


@pytest.mark.parametrize("count", [1, 2, MAX_KEYS])
def test_one_to_four_keys_are_accepted(count: int) -> None:
    keys = [_key() for _ in range(count)]

    cipher = SecretCipher.from_setting(",".join(keys))

    assert repr(cipher) == f"SecretCipher(keys={count})"


def _invalid_settings() -> list[tuple[str, str]]:
    key = _key()
    return [
        ("empty", ""),
        ("blank", "   "),
        ("too short", key[:-2]),
        ("too long", key + "A"),
        ("no padding", key.rstrip("=")),
        ("standard base64", "+" + key[1:]),
        ("leading space", f" {key}"),
        ("space after comma", f"{_key()}, {key}"),
        ("empty entry", f"{key},,{_key()}"),
        ("trailing comma", f"{key},"),
        ("non-ascii", key[:-2] + "é="),
        ("duplicate", f"{key},{key}"),
        ("too many", ",".join(_key() for _ in range(MAX_KEYS + 1))),
    ]


@pytest.mark.parametrize(("label", "setting"), _invalid_settings())
def test_invalid_key_settings_are_rejected_without_echoing_keys(label: str, setting: str) -> None:
    with pytest.raises(InvalidEncryptionKeysError) as raised:
        SecretCipher.from_setting(setting)

    message = str(raised.value)
    assert "SECRET_ENCRYPTION_KEYS" in message, label
    for entry in setting.split(","):
        if entry.strip():
            assert entry.strip() not in message, label


def test_duplicates_are_detected_by_the_decoded_key() -> None:
    """非標準的 base64（最後一個字元的低位元不是 0）會解出同一把金鑰，也要算重複。"""
    key = _key()
    raw = base64.urlsafe_b64decode(key)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last = alphabet.index(key[42])
    variant = key[:42] + alphabet[last + 1] + "="
    assert base64.urlsafe_b64decode(variant) == raw

    with pytest.raises(InvalidEncryptionKeysError, match="重複"):
        SecretCipher.from_setting(f"{key},{variant}")


def test_a_missing_setting_names_the_variable() -> None:
    with pytest.raises(InvalidEncryptionKeysError, match="缺少 SECRET_ENCRYPTION_KEYS"):
        SecretCipher.from_setting(None)


def test_a_cipher_needs_at_least_one_key() -> None:
    with pytest.raises(InvalidEncryptionKeysError):
        SecretCipher([])


def test_repr_does_not_show_keys() -> None:
    key = _key()

    cipher = SecretCipher.from_setting(key)

    assert key not in repr(cipher)
    assert key not in str(cipher)
