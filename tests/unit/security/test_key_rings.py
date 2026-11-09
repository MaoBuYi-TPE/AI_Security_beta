"""三組平台金鑰的規則（KEY-01；docs/DECISIONS.md §30.2）：各自合乎格式、互不共用金鑰。"""

import pytest
from cryptography.fernet import Fernet

from secscan.security.secret_cipher import InvalidEncryptionKeysError, check_distinct_key_rings

RINGS = ("SECRET_ENCRYPTION_KEYS", "EVIDENCE_ENCRYPTION_KEYS", "CONTENT_ENCRYPTION_KEYS")


def _key() -> str:
    return Fernet.generate_key().decode()


def test_separately_generated_rings_pass() -> None:
    check_distinct_key_rings({name: f"{_key()},{_key()}" for name in RINGS})


@pytest.mark.parametrize(("first", "second"), [(0, 1), (0, 2), (1, 2)])
def test_a_key_shared_between_rings_names_both_rings(first: int, second: int) -> None:
    shared = _key()
    settings = {name: _key() for name in RINGS}
    settings[RINGS[first]] = f"{_key()},{shared}"
    settings[RINGS[second]] = shared

    with pytest.raises(InvalidEncryptionKeysError) as raised:
        check_distinct_key_rings(settings)

    message = str(raised.value)
    assert RINGS[first] in message
    assert RINGS[second] in message
    assert shared not in message


def test_the_same_key_written_differently_is_still_shared() -> None:
    """base64 的最後一個字元有未使用的位元：不同的寫法可能是同一把金鑰。"""
    key = _key()
    raw = bytearray(key.encode())
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    raw[42] = ord(alphabet[alphabet.index(key[42]) ^ 1])
    variant = raw.decode()

    with pytest.raises(InvalidEncryptionKeysError, match="相同的金鑰"):
        check_distinct_key_rings({RINGS[0]: key, RINGS[1]: variant})


def test_a_malformed_ring_is_named() -> None:
    with pytest.raises(InvalidEncryptionKeysError, match="EVIDENCE_ENCRYPTION_KEYS 的第 1 個"):
        check_distinct_key_rings({RINGS[0]: _key(), RINGS[1]: "not-a-key"})
