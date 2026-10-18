from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from secscan.core.config import ENV_FILE, AppEnv, Settings


def test_defaults_to_prod_when_app_env_is_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.setenv("DB_PASSWORD", "prod-requires-a-password")

    settings = Settings(_env_file=None)

    assert settings.app_env == "prod"
    assert settings.docs_enabled is False


def test_reads_app_env_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "dev")

    assert Settings(_env_file=None).app_env == "dev"


def test_reads_app_env_from_env_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("APP_ENV", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text("APP_ENV=dev\n", encoding="utf-8")

    assert Settings(_env_file=env_file).app_env == "dev"


def test_default_settings_read_dotenv_in_cwd_and_ignore_unrelated_keys(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # 測試環境預設不讀 .env（tests/conftest.py）；這裡還原成正式程式的預設值來驗證它。
    monkeypatch.setitem(Settings.model_config, "env_file", ENV_FILE)
    monkeypatch.delenv("APP_ENV", raising=False)
    (tmp_path / ".env").write_text("APP_ENV=dev\nUNRELATED_KEY=1\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    assert Settings().app_env == "dev"


def test_rejects_unknown_app_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "staging")

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_settings_are_immutable() -> None:
    settings = Settings(app_env="test", _env_file=None)

    with pytest.raises(ValidationError):
        settings.app_env = "dev"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("app_env", "expected"),
    [("dev", True), ("test", False), ("prod", False)],
)
def test_docs_enabled_only_in_dev(app_env: AppEnv, expected: bool) -> None:
    settings = Settings(app_env=app_env, db_password=SecretStr("pw"), _env_file=None)

    assert settings.docs_enabled is expected


def test_database_defaults_point_to_local_dev_db() -> None:
    settings = Settings(app_env="dev", _env_file=None)

    assert settings.db_host == "127.0.0.1"
    assert settings.db_port == 55432
    assert settings.db_name == "secscan"
    assert settings.db_user == "secscan_app"
    assert settings.db_password is None
    assert settings.db_connect_timeout_seconds == 5


def test_reads_database_settings_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DB_HOST", "db.control.internal")
    monkeypatch.setenv("DB_PORT", "5432")
    monkeypatch.setenv("DB_NAME", "secscan_prod")
    monkeypatch.setenv("DB_USER", "secscan_service")
    monkeypatch.setenv("DB_PASSWORD", "pw-from-env")
    monkeypatch.setenv("DB_CONNECT_TIMEOUT_SECONDS", "2")

    settings = Settings(app_env="prod", _env_file=None)

    assert settings.db_host == "db.control.internal"
    assert settings.db_port == 5432
    assert settings.db_name == "secscan_prod"
    assert settings.db_user == "secscan_service"
    assert settings.db_password is not None
    assert settings.db_password.get_secret_value() == "pw-from-env"
    assert settings.db_connect_timeout_seconds == 2


def test_prod_fails_fast_without_db_password() -> None:
    with pytest.raises(ValidationError, match="DB_PASSWORD"):
        Settings(app_env="prod", _env_file=None)


@pytest.mark.parametrize("password", ["", "   "])
def test_prod_rejects_blank_db_password(password: str) -> None:
    with pytest.raises(ValidationError, match="DB_PASSWORD"):
        Settings(app_env="prod", db_password=SecretStr(password), _env_file=None)


@pytest.mark.parametrize("app_env", ["dev", "test"])
def test_non_prod_allows_missing_db_password(app_env: AppEnv) -> None:
    assert Settings(app_env=app_env, _env_file=None).db_password is None


@pytest.mark.parametrize("port", [0, 65536])
def test_rejects_out_of_range_db_port(port: int) -> None:
    with pytest.raises(ValidationError):
        Settings(app_env="test", db_port=port, _env_file=None)


@pytest.mark.parametrize("timeout", [0, 61])
def test_rejects_out_of_range_connect_timeout(timeout: int) -> None:
    with pytest.raises(ValidationError):
        Settings(app_env="test", db_connect_timeout_seconds=timeout, _env_file=None)


@pytest.mark.parametrize("field", ["db_host", "db_name", "db_user"])
def test_rejects_blank_database_identifiers(field: str) -> None:
    with pytest.raises(ValidationError):
        Settings.model_validate({"app_env": "test", field: ""})


def test_settings_repr_masks_db_password() -> None:
    settings = Settings(app_env="test", db_password=SecretStr("super-secret-value"), _env_file=None)

    assert "super-secret-value" not in repr(settings)
    assert "super-secret-value" not in str(settings)
