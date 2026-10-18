"""測試環境本身的隔離：不讀 .env、不連 DB，整合測試只連測試專用的伺服器。"""

from pathlib import Path

import psycopg
import pytest
from pydantic import SecretStr, ValidationError

from secscan.core.config import Settings
from secscan.core.db import create_db_engine
from tests.conftest import DatabaseAccessBlockedError
from tests.integration.database import (
    IntegrationDbSettings,
    NotATestServerError,
    ensure_test_cluster,
)


def test_settings_ignore_dotenv_in_working_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / ".env").write_text("DB_PORT=4242\nDB_PASSWORD=from-dotenv\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    settings = Settings.model_validate({"app_env": "test"})

    assert settings.db_port == 55432
    assert settings.db_password is None


def test_unit_tests_cannot_open_database_connections() -> None:
    with pytest.raises(DatabaseAccessBlockedError, match="integration"):
        psycopg.connect("host=127.0.0.1 port=55432 dbname=secscan connect_timeout=1")


def test_unit_tests_cannot_connect_through_the_app_engine() -> None:
    engine = create_db_engine(Settings(app_env="test", _env_file=None))

    with pytest.raises(DatabaseAccessBlockedError):
        engine.connect()


@pytest.mark.parametrize("cluster_name", ["secscan-dev", "", "SECSCAN-TEST", "secscan-test2"])
def test_only_the_test_cluster_is_accepted(cluster_name: str) -> None:
    with pytest.raises(NotATestServerError):
        ensure_test_cluster(cluster_name)


def test_test_cluster_is_accepted() -> None:
    ensure_test_cluster("secscan-test")


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost"])
def test_integration_db_must_be_loopback_accepts(host: str) -> None:
    settings = IntegrationDbSettings(host=host, password=SecretStr("x"), _env_file=None)

    assert settings.host == host


# 0.0.0.0 是要被拒絕的輸入，不是在綁定介面。
@pytest.mark.parametrize("host", ["10.0.0.5", "db.example.edu.tw", "0.0.0.0", "127.0.0.2"])  # noqa: S104
def test_integration_db_must_be_loopback_rejects(host: str) -> None:
    with pytest.raises(ValidationError, match="loopback"):
        IntegrationDbSettings(host=host, password=SecretStr("x"), _env_file=None)
