"""alembic 的 env.py（CSEC-10 的 migration 邊界；CSEC-12 在 commit 8 補上）。

設定錯誤時 env.py 拋出 SettingsError：只有欄位名稱與固定的原因，不帶原本的 ValidationError
（alembic 會印出完整的 traceback，原始的錯誤可能含輸入，例如密碼）。這些測試在連線之前就失敗，
不連任何資料庫。
"""

import secrets
import traceback

import pytest
from alembic import command

from secscan.core.settings_errors import SettingsError
from secscan.migrations import alembic_config

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
