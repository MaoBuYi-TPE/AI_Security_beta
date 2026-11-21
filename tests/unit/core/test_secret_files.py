"""`*_FILE` 秘密檔的讀取（CSEC-03 的讀檔部分；docs/SECURITY_AND_TESTING.md §4.3）。

PYTEST_DONT_REWRITE：這個模組處理秘密、canary、環境變數或設定錯誤；不改寫 assert，失敗時只顯示
原始碼與（只有名稱的）訊息，不顯示運算元的值（G1 審查）。
"""

import os
import secrets
import subprocess
import sys
from pathlib import Path

import pytest

from secscan.core.secret_files import (
    CANNOT_OPEN,
    CANNOT_READ,
    EMPTY,
    IS_SYMLINK,
    MAX_SECRET_LENGTH,
    NOT_A_PATH,
    NOT_ONE_LINE,
    NOT_REGULAR,
    TOO_LONG,
    SecretFileError,
    read_secret_file,
    resolve_secret_files,
)

LABEL = "DB_PASSWORD_FILE"
# FIFO 的開檔沒有 O_NONBLOCK 就會卡住（沒有寫入端）：在子程序中加上時限執行，
# 卡住時測試失敗而不是掛住。
FIFO_TIMEOUT_SECONDS = 10


def _canary() -> str:
    return secrets.token_hex(24)


def _write(tmp_path: Path, content: bytes, name: str = "secret") -> Path:
    path = tmp_path / name
    path.write_bytes(content)
    path.chmod(0o600)
    return path


def _rejects(path: str | Path, reason: str) -> SecretFileError:
    with pytest.raises(SecretFileError) as caught:
        read_secret_file(path, label=LABEL)
    error = caught.value
    assert str(error) == f"{LABEL} 指向的秘密檔{reason}"
    # 不帶原本的 OSError（含路徑）或 UnicodeDecodeError（含 bytes）。
    assert error.__context__ is None
    assert error.__cause__ is None
    return error


def test_reads_the_value(tmp_path: Path) -> None:
    canary = _canary()

    assert read_secret_file(_write(tmp_path, canary.encode()), label=LABEL) == canary


def test_accepts_one_trailing_newline(tmp_path: Path) -> None:
    canary = _canary()

    assert read_secret_file(_write(tmp_path, f"{canary}\n".encode()), label=LABEL) == canary


def test_accepts_a_path_object_and_a_string(tmp_path: Path) -> None:
    canary = _canary()
    path = _write(tmp_path, canary.encode())

    assert read_secret_file(str(path), label=LABEL) == read_secret_file(path, label=LABEL)


def test_accepts_every_printable_ascii_character(tmp_path: Path) -> None:
    value = "".join(chr(code) for code in range(0x21, 0x7F))

    assert read_secret_file(_write(tmp_path, value.encode()), label=LABEL) == value


def test_accepts_the_maximum_length(tmp_path: Path) -> None:
    value = "a" * MAX_SECRET_LENGTH

    assert read_secret_file(_write(tmp_path, value.encode()), label=LABEL) == value
    assert read_secret_file(_write(tmp_path, f"{value}\n".encode(), "nl"), label=LABEL) == value


@pytest.mark.parametrize(
    "content",
    [
        b"a" * (MAX_SECRET_LENGTH + 1),
        b"a" * (MAX_SECRET_LENGTH + 1) + b"\n",
        b"a" * (MAX_SECRET_LENGTH * 4),
    ],
    ids=["4096", "4096-newline", "much-larger"],
)
def test_rejects_values_over_the_maximum_length(tmp_path: Path, content: bytes) -> None:
    _rejects(_write(tmp_path, content), TOO_LONG)


@pytest.mark.parametrize("content", [b"", b"\n"], ids=["empty", "newline-only"])
def test_rejects_an_empty_value(tmp_path: Path, content: bytes) -> None:
    _rejects(_write(tmp_path, content), EMPTY)


@pytest.mark.parametrize(
    ("prefix", "suffix"),
    [
        ("", "\r\n"),
        ("", "\r"),
        ("", "\n\n"),
        ("", "\nsecond-line"),
        ("", " "),
        (" ", ""),
        ("", "\t"),
        ("", "\x00"),
        ("", "\x7f"),
        ("", "é"),
    ],
    ids=[
        "crlf",
        "cr",
        "two-newlines",
        "second-line",
        "space",
        "leading-space",
        "tab",
        "nul",
        "del",
        "non-ascii",
    ],
)
def test_rejects_anything_but_one_line_of_printable_ascii(
    tmp_path: Path, prefix: str, suffix: str
) -> None:
    canary = _canary()

    error = _rejects(_write(tmp_path, f"{prefix}{canary}{suffix}".encode()), NOT_ONE_LINE)

    assert canary[:8] not in str(error)


def test_rejects_bytes_that_are_not_utf8(tmp_path: Path) -> None:
    _rejects(_write(tmp_path, b"\xff\xfe" + _canary().encode()), NOT_ONE_LINE)


def test_rejects_a_symlink_even_to_a_valid_file(tmp_path: Path) -> None:
    target = _write(tmp_path, _canary().encode())
    link = tmp_path / "link"
    link.symlink_to(target)

    _rejects(link, IS_SYMLINK)


def test_rejects_a_missing_file(tmp_path: Path) -> None:
    _rejects(tmp_path / "missing", CANNOT_OPEN)


def test_rejects_a_directory(tmp_path: Path) -> None:
    _rejects(tmp_path, NOT_REGULAR)


@pytest.mark.skipif(os.geteuid() == 0, reason="root 讀得到 0000 的檔案")
def test_rejects_an_unreadable_file(tmp_path: Path) -> None:
    path = _write(tmp_path, _canary().encode())
    path.chmod(0o000)
    try:
        _rejects(path, CANNOT_OPEN)
    finally:
        path.chmod(0o600)


def test_rejects_a_read_failure_without_the_os_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write(tmp_path, _canary().encode())

    def _fail(*_args: object) -> bytes:
        raise OSError(5, "Input/output error", str(path))

    monkeypatch.setattr(os, "read", _fail)

    _rejects(path, CANNOT_READ)


def test_rejects_a_fifo_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    script = (
        "import sys\n"
        "from secscan.core.secret_files import SecretFileError, read_secret_file\n"
        "try:\n"
        f"    read_secret_file(sys.argv[1], label={LABEL!r})\n"
        "except SecretFileError as error:\n"
        "    print(error)\n"
    )

    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-c", script, str(fifo)],
        capture_output=True,
        text=True,
        timeout=FIFO_TIMEOUT_SECONDS,
        check=True,
    )

    assert completed.stdout.strip() == f"{LABEL} 指向的秘密檔{NOT_REGULAR}"


def test_resolve_reads_the_file_and_clears_the_file_setting(tmp_path: Path) -> None:
    canary = _canary()
    path = _write(tmp_path, canary.encode())
    original = {"db_password_file": str(path), "db_host": "127.0.0.1"}

    resolved = resolve_secret_files(original, ["db_password"])

    assert resolved == {"db_password": canary, "db_password_file": None, "db_host": "127.0.0.1"}
    # 回傳新的 dict，不修改輸入。
    assert original == {"db_password_file": str(path), "db_host": "127.0.0.1"}


def test_resolve_leaves_unset_settings_alone() -> None:
    original = {"db_password": "from-env", "db_password_file": None}

    assert resolve_secret_files(original, ["db_password", "content_encryption_keys"]) == original


@pytest.mark.parametrize("value", ["", "x"], ids=["empty", "value"])
def test_resolve_rejects_both_the_value_and_the_file(tmp_path: Path, value: str) -> None:
    canary = _canary()
    path = _write(tmp_path, canary.encode())

    with pytest.raises(ValueError, match="只能設定其中一個") as caught:
        resolve_secret_files(
            {"password": value + canary, "password_file": str(path)},
            ["password"],
            env_prefix="DB_OWNER_",
        )

    assert str(caught.value) == "DB_OWNER_PASSWORD 與 DB_OWNER_PASSWORD_FILE 只能設定其中一個"


def test_resolve_rejects_a_file_setting_that_is_not_a_path() -> None:
    with pytest.raises(SecretFileError) as caught:
        resolve_secret_files({"db_password_file": 42}, ["db_password"])

    assert str(caught.value) == f"{LABEL} 指向的秘密檔{NOT_A_PATH}"


def test_resolve_reports_the_prefixed_setting_name(tmp_path: Path) -> None:
    with pytest.raises(SecretFileError) as caught:
        resolve_secret_files(
            {"password_file": str(tmp_path / "missing")}, ["password"], env_prefix="DB_OWNER_"
        )

    assert str(caught.value) == f"DB_OWNER_PASSWORD_FILE 指向的秘密檔{CANNOT_OPEN}"


def test_resolve_passes_through_input_that_is_not_a_mapping() -> None:
    sentinel = object()

    assert resolve_secret_files(sentinel, ["db_password"]) is sentinel
