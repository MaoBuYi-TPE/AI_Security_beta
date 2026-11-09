"""secscan-admin check-encryption-keys（KEY-01、KEY-04；docs/DECISIONS.md §30.2）。

設定只來自環境變數（tests/conftest.py 已讓 Settings 不讀 .env）；不連資料庫。
"""

import pytest
from cryptography.fernet import Fernet

from secscan.cli import EXIT_FAILURE, EXIT_OK, main

RINGS = ("SECRET_ENCRYPTION_KEYS", "EVIDENCE_ENCRYPTION_KEYS", "CONTENT_ENCRYPTION_KEYS")


def _key() -> str:
    return Fernet.generate_key().decode()


@pytest.fixture
def keys(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    monkeypatch.setenv("APP_ENV", "test")
    values = {RINGS[0]: _key(), RINGS[1]: f"{_key()},{_key()}", RINGS[2]: _key()}
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    return values


def _no_keys_in(text: str, values: dict[str, str]) -> None:
    for value in values.values():
        for key in value.split(","):
            assert key not in text


def test_three_distinct_rings_pass_and_only_counts_are_shown(
    keys: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["check-encryption-keys"]) == EXIT_OK

    out, err = capsys.readouterr()
    assert out == ""
    assert "SECRET_ENCRYPTION_KEYS 1 個、EVIDENCE_ENCRYPTION_KEYS 2 個" in err
    _no_keys_in(err, keys)


@pytest.mark.parametrize("missing", RINGS)
def test_a_missing_ring_is_named(
    keys: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    missing: str,
) -> None:
    monkeypatch.delenv(missing)

    assert main(["check-encryption-keys"]) == EXIT_FAILURE

    err = capsys.readouterr().err
    assert f"缺少 {missing}" in err
    assert "make env" in err


def test_a_shared_key_names_both_rings_without_echoing_it(
    keys: dict[str, str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(RINGS[2], keys[RINGS[1]].split(",")[1])

    assert main(["check-encryption-keys"]) == EXIT_FAILURE

    err = capsys.readouterr().err
    assert "EVIDENCE_ENCRYPTION_KEYS 與 CONTENT_ENCRYPTION_KEYS 有相同的金鑰" in err
    _no_keys_in(err, keys)


def test_a_malformed_ring_is_named_without_echoing_it(
    keys: dict[str, str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    canary = "canary-not-a-key-but-maybe-secret"
    monkeypatch.setenv(RINGS[1], canary)

    assert main(["check-encryption-keys"]) == EXIT_FAILURE

    err = capsys.readouterr().err
    assert "EVIDENCE_ENCRYPTION_KEYS 的第 1 個金鑰" in err
    assert canary not in err
