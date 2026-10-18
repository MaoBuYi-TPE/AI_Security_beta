"""secscan-admin 的參數與設定檢查（不連 DB；實際建立 key 見 tests/integration/test_cli.py）。"""

from pathlib import Path

import pytest

from secscan.cli import EXIT_FAILURE, EXIT_USAGE, main

CANARY_PASSWORD = "canary-db-password-0004"


@pytest.mark.parametrize(
    "args",
    [
        [],
        ["unknown-command"],
        ["create-admin-key"],
        ["create-admin-key", "--name", "   "],
        ["create-admin-key", "--name", "x" * 101],
        ["create-admin-key", "--name", "admin", "--expires-in-days", "0"],
        ["create-admin-key", "--name", "admin", "--expires-in-days", "366"],
        ["create-admin-key", "--name", "admin", "--expires-in-days", "ninety"],
    ],
    ids=[
        "no-command",
        "unknown-command",
        "missing-name",
        "blank-name",
        "long-name",
        "zero-days",
        "beyond-max",
        "not-a-number",
    ],
)
def test_invalid_arguments_are_usage_errors(
    args: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as caught:
        main(args)

    out, err = capsys.readouterr()
    assert caught.value.code == EXIT_USAGE
    assert out == ""
    assert "usage:" in err


def test_invalid_settings_are_reported_without_their_values(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("DB_PORT", "not-a-port")
    monkeypatch.setenv("DB_PASSWORD", CANARY_PASSWORD)

    exit_code = main(["create-admin-key", "--name", "admin"])

    out, err = capsys.readouterr()
    assert exit_code == EXIT_FAILURE
    assert out == ""
    assert "db_port" in err
    assert CANARY_PASSWORD not in err
    assert "not-a-port" not in err


def test_missing_database_password_is_reported(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("APP_ENV", raising=False)

    exit_code = main(["create-admin-key", "--name", "admin"])

    assert exit_code == EXIT_FAILURE
    assert "DB_PASSWORD" in capsys.readouterr().err


def test_output_file_that_cannot_be_created_stops_before_any_key_is_made(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """輸出檔在建立 key 之前就先開好：開不了就不連 DB、不建立 key（這裡連 DB 會被測試守衛擋下）。"""
    monkeypatch.setenv("APP_ENV", "test")
    target = tmp_path / "missing-dir" / "admin.key"

    exit_code = main(["create-admin-key", "--name", "admin", "--output", str(target)])

    out, err = capsys.readouterr()
    assert exit_code == EXIT_FAILURE
    assert out == ""
    assert "沒有建立任何 key" in err
    assert not target.exists()


def test_existing_output_file_is_never_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("APP_ENV", "test")
    target = tmp_path / "admin.key"
    target.write_text("keep me\n", encoding="utf-8")

    exit_code = main(["create-admin-key", "--name", "admin", "--output", str(target)])

    assert exit_code == EXIT_FAILURE
    assert target.read_text(encoding="utf-8") == "keep me\n"
    assert "沒有建立任何 key" in capsys.readouterr().err
