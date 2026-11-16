"""alembic 的 env.py（CSEC-10 的 migration 邊界；CSEC-12 在 commit 8 補上）。

設定錯誤時 env.py 拋出 SettingsError：只有欄位名稱與固定的原因，不帶原本的 ValidationError
（alembic 會印出完整的 traceback，原始的錯誤可能含輸入，例如密碼）。這些測試在連線之前就失敗，
不連任何資料庫。
"""

import argparse
import secrets
import traceback
from pathlib import Path

import pytest
from alembic import command

from secscan.core.config import ENV_FILE, Settings
from secscan.core.settings_errors import SettingsError
from secscan.migrations import alembic_config
from secscan.migrations.credentials import MigrationCredentials, MissingOwnerPasswordError
from tests.conftest import DatabaseAccessBlockedError

FRAGMENT_LENGTH = 8


def _leaks(text: str, canary: str) -> bool:
    lowered = text.lower()
    return any(
        canary[start : start + FRAGMENT_LENGTH] in lowered
        for start in range(len(canary) - FRAGMENT_LENGTH + 1)
    )


def _upgrade_error() -> SettingsError:
    with pytest.raises(SettingsError) as caught:
        command.upgrade(alembic_config(), "head")
    return caught.value


@pytest.mark.parametrize(
    ("variable", "with_file", "expected"),
    [
        ("DB_PORT", False, "設定不正確：db_port："),
        # DB_PASSWORD 與 DB_PASSWORD_FILE 同時設定：原始的輸入就是秘密。
        ("DB_PASSWORD", True, "設定不正確：設定：Value error, DB_PASSWORD 與 DB_PASSWORD_FILE"),
    ],
    ids=["field-error", "value-and-file"],
)
def test_invalid_app_settings_stop_without_the_original_error(
    monkeypatch: pytest.MonkeyPatch, variable: str, with_file: bool, expected: str
) -> None:
    canary = secrets.token_hex(24)
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv(variable, canary)
    if with_file:
        monkeypatch.setenv("DB_PASSWORD_FILE", "/nonexistent/secret")

    error = _upgrade_error()

    assert str(error).startswith(expected)
    assert "errors.pydantic.dev" not in str(error)
    assert error.__context__ is None
    assert error.__cause__ is None
    rendered = "".join(traceback.format_exception(error))
    assert not _leaks(rendered, canary)
    assert not _leaks(repr(error), canary)


def test_invalid_owner_settings_stop_without_the_original_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = secrets.token_hex(24)
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("DB_OWNER_USER", f"Bad-{canary}")
    monkeypatch.setenv("DB_OWNER_PASSWORD", canary)

    error = _upgrade_error()

    assert str(error).startswith("設定不正確：user")
    assert error.__context__ is None
    rendered = "".join(traceback.format_exception(error))
    assert not _leaks(rendered, canary)


# --- CSEC-12：Live 的 alembic 以 -x dotenv=off 執行，不讀 .env ----------------------------------


def _with_dotenv(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> str:
    """工作目錄放含 canary 的 .env；設定類別的 env_file 設回正式的預設值。"""
    canary = secrets.token_hex(24)
    (tmp_path / ".env").write_text(f"DB_OWNER_PASSWORD={canary}\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setitem(Settings.model_config, "env_file", ENV_FILE)
    monkeypatch.setitem(MigrationCredentials.model_config, "env_file", ENV_FILE)
    monkeypatch.setenv("APP_ENV", "test")
    return canary


def _upgrade_with(*x_arguments: str) -> None:
    config = alembic_config()
    config.cmd_opts = argparse.Namespace(x=list(x_arguments))
    command.upgrade(config, "head")


def test_dotenv_is_read_without_the_switch_positive_control(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """正向對照：沒有 -x dotenv=off 時讀得到 .env 的密碼（之後才在連線時被 unit 測試擋下）。"""
    _with_dotenv(monkeypatch, tmp_path)

    with pytest.raises(DatabaseAccessBlockedError):
        _upgrade_with()


def test_dotenv_off_does_not_fall_back_to_the_env_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    canary = _with_dotenv(monkeypatch, tmp_path)

    with pytest.raises(MissingOwnerPasswordError) as caught:
        _upgrade_with("dotenv=off")

    rendered = "".join(traceback.format_exception(caught.value))
    assert not _leaks(rendered, canary)


def test_dotenv_off_reads_the_secret_files(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Live 的 recipe 只以 *_FILE 傳入秘密：讀得到檔案，才會往下走到連線。"""
    _with_dotenv(monkeypatch, tmp_path)
    secret = tmp_path / "db_owner_password"
    secret.write_text(secrets.token_hex(24), encoding="ascii")
    monkeypatch.setenv("DB_OWNER_PASSWORD_FILE", str(secret))

    with pytest.raises(DatabaseAccessBlockedError):
        _upgrade_with("dotenv=off")


def test_an_unknown_dotenv_switch_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "test")

    with pytest.raises(SettingsError, match="dotenv"):
        _upgrade_with("dotenv=yes")
