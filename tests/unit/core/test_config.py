from pathlib import Path

import pytest
from pydantic import ValidationError

from secscan.core.config import AppEnv, Settings


def test_defaults_to_prod_when_app_env_is_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APP_ENV", raising=False)

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
    assert Settings(app_env=app_env, _env_file=None).docs_enabled is expected
