"""平台 API key 的產生、格式檢查與雜湊（docs/DECISIONS.md §9.1）。"""

import hashlib
import hmac
import re
import secrets

import pytest

from secscan.api_keys.domain import KEY_HASH_BYTES
from secscan.security.api_key_tokens import (
    KEY_LABEL,
    contains_platform_key,
    generate_key,
    hash_key,
    key_matches,
    parse_prefix,
)

KEY_SHAPE = re.compile(r"secscan_[0-9a-f]{16}_[0-9a-f]{64}")
SAMPLE_PREFIX = "0123456789abcdef"
SAMPLE_KEY = f"secscan_{SAMPLE_PREFIX}_{'a' * 64}"
SAMPLE_COUNT = 1000


def test_generated_key_has_the_fixed_shape() -> None:
    key = generate_key()

    assert KEY_SHAPE.fullmatch(key.value)
    assert key.value.startswith(f"{KEY_LABEL}_{key.prefix}_")
    assert parse_prefix(key.value) == key.prefix


def test_generated_keys_do_not_repeat() -> None:
    keys = [generate_key() for _ in range(SAMPLE_COUNT)]

    assert len({key.value for key in keys}) == SAMPLE_COUNT
    assert len({key.prefix for key in keys}) == SAMPLE_COUNT


def test_prefix_and_secret_come_from_separate_csprng_draws(monkeypatch: pytest.MonkeyPatch) -> None:
    """prefix 公開存在 DB，必須和 256-bit 的 secret 分開產生，不能是 secret 的一部分。"""
    requested: list[int] = []

    def fake_token_hex(nbytes: int) -> str:
        requested.append(nbytes)
        return f"{len(requested):x}" * (nbytes * 2)

    monkeypatch.setattr(secrets, "token_hex", fake_token_hex)

    key = generate_key()

    assert requested == [8, 32]
    assert key.prefix == "1" * 16
    assert key.value == f"secscan_{'1' * 16}_{'2' * 64}"


def test_generated_key_value_is_hidden_from_repr() -> None:
    key = generate_key()

    assert key.value not in repr(key)
    assert key.prefix in repr(key)


@pytest.mark.parametrize(
    "value",
    [
        "",
        SAMPLE_KEY.upper(),
        SAMPLE_KEY.replace("a" * 64, "A" * 64),
        SAMPLE_KEY.replace("secscan_", "secscam_"),
        SAMPLE_KEY.replace("_", "-"),
        SAMPLE_KEY[:-1],
        SAMPLE_KEY + "a",
        f"secscan_{SAMPLE_PREFIX[:-1]}_{'a' * 65}",
        f"secscan_{SAMPLE_PREFIX}a_{'a' * 63}",
        f" {SAMPLE_KEY}",
        f"{SAMPLE_KEY}\n",
        f"Bearer {SAMPLE_KEY}",
        SAMPLE_KEY.replace("a", "\x00", 1),
        # 全形數字與阿拉伯印度數字：Unicode 的 \d 會把它們當數字，格式檢查不能接受。
        SAMPLE_KEY.replace("0", chr(0xFF10)),
        SAMPLE_KEY.replace("0", chr(0x0660)),
        "secscan_" * 1000,
    ],
    ids=repr,
)
def test_parse_prefix_rejects_anything_but_the_exact_format(value: str) -> None:
    assert parse_prefix(value) is None


def test_parse_prefix_returns_the_public_prefix() -> None:
    assert parse_prefix(SAMPLE_KEY) == SAMPLE_PREFIX


def test_hash_is_sha256_of_the_whole_key() -> None:
    digest = hash_key(SAMPLE_KEY)

    assert digest == hashlib.sha256(SAMPLE_KEY.encode()).digest()
    assert len(digest) == KEY_HASH_BYTES


def test_key_matches_only_its_own_hash() -> None:
    other_secret = SAMPLE_KEY.replace("a" * 64, "b" * 64)

    assert key_matches(SAMPLE_KEY, hash_key(SAMPLE_KEY))
    assert not key_matches(other_secret, hash_key(SAMPLE_KEY))
    assert not key_matches(SAMPLE_KEY, b"")
    assert not key_matches(SAMPLE_KEY, bytes(KEY_HASH_BYTES))


def test_key_matches_compares_in_constant_time(monkeypatch: pytest.MonkeyPatch) -> None:
    """一般的 == 比對會在第一個不同的 byte 就停下，讓回應時間洩漏 hash 的內容。"""
    compared: list[tuple[bytes, bytes]] = []

    def spy(left: bytes, right: bytes) -> bool:
        compared.append((left, right))
        return False

    monkeypatch.setattr(hmac, "compare_digest", spy)

    assert not key_matches(SAMPLE_KEY, hash_key(SAMPLE_KEY))
    assert compared == [(hash_key(SAMPLE_KEY), hash_key(SAMPLE_KEY))]


# --- 文字中是否含平台 key（docs/DECISIONS.md §12.4：平台 key 不可送往被測網站）---------------


@pytest.mark.parametrize(
    "text",
    [SAMPLE_KEY, f"Bearer {SAMPLE_KEY}", f"session={SAMPLE_KEY}; b=1", f"x{SAMPLE_KEY}x"],
)
def test_platform_keys_are_found_anywhere_in_text(text: str) -> None:
    assert contains_platform_key(text)


@pytest.mark.parametrize(
    "text",
    ["", "secscan_", SAMPLE_KEY.upper(), SAMPLE_KEY[:-1], SAMPLE_KEY.replace("_", "-")],
)
def test_text_without_a_complete_platform_key(text: str) -> None:
    assert not contains_platform_key(text)
