"""設定類別以 `*_FILE` 讀取秘密（CSEC-03 的設定部分、CSEC-10 的縱深防禦、CSEC-13 (c)）。

compose secrets 之後，api、runner、worker 的秘密從 `/run/secrets/<名稱>` 讀取（`X_FILE`），
環境變數不再有值。主機上的流程照舊讀 .env 的 `X`。兩者同時有值時拒絕，不靜默採用其中一個。

PYTEST_DONT_REWRITE：這個模組處理秘密、canary、環境變數或設定錯誤；不改寫 assert，失敗時只顯示
原始碼與（只有名稱的）訊息，不顯示運算元的值（G1 審查）。
"""

import importlib
import pkgutil
import secrets
from collections.abc import Iterator
from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError
from pydantic_settings import BaseSettings

import secscan
from secscan.core.config import SECRET_FILE_FIELDS, Settings
from secscan.core.settings_errors import safe_summary
from secscan.migrations.credentials import MigrationCredentials
from tests.integration.database import IntegrationDbSettings

FRAGMENT_LENGTH = 8
# import 會執行 alembic 的 env.py（需要 alembic context）與每個 migration：不列舉。
_SKIPPED_MODULES = ("secscan.migrations.env", "secscan.migrations.versions")


def _canary() -> str:
    return secrets.token_hex(24)


def _leaks(text: str, canary: str) -> bool:
    lowered = text.lower()
    return any(
        canary[start : start + FRAGMENT_LENGTH] in lowered
        for start in range(len(canary) - FRAGMENT_LENGTH + 1)
    )


def _secret_file(tmp_path: Path, value: str, name: str = "secret") -> Path:
    path = tmp_path / name
    path.write_text(value, encoding="ascii")
    path.chmod(0o600)
    return path


@pytest.mark.parametrize("field", SECRET_FILE_FIELDS)
def test_each_secret_is_read_from_its_file_setting(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, field: str
) -> None:
    canary = _canary()
    monkeypatch.setenv(f"{field.upper()}_FILE", str(_secret_file(tmp_path, f"{canary}\n")))

    settings = Settings(app_env="test", _env_file=None)

    value = getattr(settings, field)
    assert isinstance(value, SecretStr)
    assert value.get_secret_value() == canary
    assert getattr(settings, f"{field}_file") is None
    assert canary not in repr(settings)


def test_the_four_secret_settings_have_file_settings() -> None:
    assert SECRET_FILE_FIELDS == (
        "db_password",
        "secret_encryption_keys",
        "evidence_encryption_keys",
        "content_encryption_keys",
    )
    for field in SECRET_FILE_FIELDS:
        assert f"{field}_file" in Settings.model_fields


def test_a_dump_of_the_settings_validates_again(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    canary = _canary()
    monkeypatch.setenv("DB_PASSWORD_FILE", str(_secret_file(tmp_path, canary)))
    settings = Settings(app_env="test", _env_file=None)

    again = Settings(**settings.model_dump(), _env_file=None)

    assert again == settings


def test_the_file_setting_is_read_from_dotenv(tmp_path: Path) -> None:
    canary = _canary()
    path = _secret_file(tmp_path, canary)
    dotenv = tmp_path / ".env"
    dotenv.write_text(f"APP_ENV=test\nDB_PASSWORD_FILE={path}\n", encoding="utf-8")

    settings = Settings(_env_file=dotenv)

    assert settings.db_password is not None
    assert settings.db_password.get_secret_value() == canary


def test_a_file_setting_satisfies_the_prod_password_requirement(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.setenv("DB_PASSWORD_FILE", str(_secret_file(tmp_path, _canary())))

    assert Settings(_env_file=None).app_env == "prod"


@pytest.mark.parametrize("value", ["", "-set"], ids=["empty", "value"])
def test_both_the_value_and_the_file_are_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, value: str
) -> None:
    canary = _canary()
    monkeypatch.setenv("DB_PASSWORD", f"{canary}{value}" if value else "")
    monkeypatch.setenv("DB_PASSWORD_FILE", str(_secret_file(tmp_path, _canary())))

    with pytest.raises(ValidationError) as caught:
        Settings(app_env="test", _env_file=None)

    summary = safe_summary(caught.value, Settings)
    assert summary == "設定：Value error, DB_PASSWORD 與 DB_PASSWORD_FILE 只能設定其中一個"
    assert not _leaks(summary, canary)
    assert not _leaks(str(caught.value), canary)


def test_a_value_from_dotenv_and_a_file_from_the_environment_are_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """第二道防線（CSEC-13 (c)）：.env 的值不會被 X_FILE 靜默蓋過，反之亦然。"""
    canary = _canary()
    dotenv = tmp_path / ".env"
    dotenv.write_text(f"APP_ENV=test\nCONTENT_ENCRYPTION_KEYS={canary}\n", encoding="utf-8")
    monkeypatch.setenv("CONTENT_ENCRYPTION_KEYS_FILE", str(_secret_file(tmp_path, _canary())))

    with pytest.raises(ValidationError) as caught:
        Settings(_env_file=dotenv)

    assert "只能設定其中一個" in safe_summary(caught.value, Settings)
    assert not _leaks(str(caught.value), canary)


def test_an_unreadable_file_setting_is_described_without_its_content(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    canary = _canary()
    monkeypatch.setenv("SECRET_ENCRYPTION_KEYS_FILE", str(_secret_file(tmp_path, f"{canary} x")))

    with pytest.raises(ValidationError) as caught:
        Settings(app_env="test", _env_file=None)

    summary = safe_summary(caught.value, Settings)
    assert summary.startswith(
        "設定：Value error, SECRET_ENCRYPTION_KEYS_FILE 指向的秘密檔只能有一行"
    )
    assert not _leaks(summary, canary)
    assert not _leaks(str(caught.value), canary)


def test_the_owner_password_is_read_from_its_file_setting(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    canary = _canary()
    monkeypatch.setenv("DB_OWNER_PASSWORD_FILE", str(_secret_file(tmp_path, f"{canary}\n")))

    credentials = MigrationCredentials(_env_file=None)

    assert credentials.password is not None
    assert credentials.password.get_secret_value() == canary
    assert credentials.password_file is None


def test_the_owner_password_and_its_file_are_refused_together(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    canary = _canary()
    monkeypatch.setenv("DB_OWNER_PASSWORD", canary)
    monkeypatch.setenv("DB_OWNER_PASSWORD_FILE", str(_secret_file(tmp_path, _canary())))

    with pytest.raises(ValidationError) as caught:
        MigrationCredentials(_env_file=None)

    summary = safe_summary(caught.value, MigrationCredentials)
    assert summary == (
        "設定：Value error, DB_OWNER_PASSWORD 與 DB_OWNER_PASSWORD_FILE 只能設定其中一個"
    )
    assert not _leaks(str(caught.value), canary)


# --- hide_input_in_errors：每個設定類別（縱深防禦，CSEC-10）-----------------------------------


def _subclasses(cls: type[BaseSettings]) -> Iterator[type[BaseSettings]]:
    for subclass in cls.__subclasses__():
        yield subclass
        yield from _subclasses(subclass)


def _settings_classes() -> list[type[BaseSettings]]:
    """import secscan 的全部模組之後，列舉 secscan.* 的設定類別，再加上整合測試的類別。"""
    for module in pkgutil.walk_packages(secscan.__path__, "secscan."):
        if not module.name.startswith(_SKIPPED_MODULES):
            importlib.import_module(module.name)
    found = {cls for cls in _subclasses(BaseSettings) if cls.__module__.startswith("secscan.")}
    found.add(IntegrationDbSettings)
    return sorted(found, key=lambda cls: f"{cls.__module__}.{cls.__qualname__}")


def test_every_settings_class_is_enumerated() -> None:
    names = {cls.__name__ for cls in _settings_classes()}

    assert {
        "Settings",
        "MigrationCredentials",
        "AdminCredentials",
        "RunnerSettings",
        "WorkerSettings",
        "IntegrationDbSettings",
    } <= names


@pytest.mark.parametrize(
    "settings_class", _settings_classes(), ids=lambda cls: f"{cls.__module__}.{cls.__qualname__}"
)
def test_every_settings_class_hides_input_in_errors(settings_class: type[BaseSettings]) -> None:
    canary = _canary()
    # 每個欄位都給一個不合法、含 canary 的值：欄位層的錯誤會把輸入放進 str(e)，除非設定了隱藏。
    invalid: dict[str, object] = {name: {canary: canary} for name in settings_class.model_fields}

    with pytest.raises(ValidationError) as caught:
        # model_validate 不讀任何設定來源（環境變數、.env），只驗證給定的值。
        settings_class.model_validate(invalid)

    assert settings_class.model_config.get("hide_input_in_errors") is True
    assert not _leaks(str(caught.value), canary)
