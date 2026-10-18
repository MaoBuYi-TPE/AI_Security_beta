"""GET /health/ready：DB 可連線且 schema 在目前的 migration 版本才是 200，否則 503。"""

import logging
import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from secscan.core.config import Settings
from secscan.main import create_app
from tests.integration.conftest import app_engine
from tests.integration.database import ProvisionedDatabase

pytestmark = pytest.mark.integration

# 127.0.0.1:1 沒有服務在聽，連線會立刻被拒，用來模擬 DB 不可用。
UNREACHABLE_PORT = 1
REQUEST_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")


def _ready(settings: Settings) -> tuple[int, dict[str, object]]:
    with TestClient(create_app(settings)) as client:
        response = client.get("/health/ready")
    body: dict[str, object] = response.json()
    return response.status_code, body


def test_ready_when_database_is_migrated(migrated_database: ProvisionedDatabase) -> None:
    status, body = _ready(migrated_database.app_settings())

    assert status == 200
    assert body == {"success": True, "data": {"status": "ready"}, "error": None, "meta": None}


def test_not_ready_when_database_is_unreachable(
    migrated_database: ProvisionedDatabase, caplog: pytest.LogCaptureFixture
) -> None:
    settings = migrated_database.app_settings().model_copy(update={"db_port": UNREACHABLE_PORT})

    with caplog.at_level(logging.WARNING, logger="secscan.core.db"):
        status, body = _ready(settings)

    assert status == 503
    error = body["error"]
    assert isinstance(error, dict)
    # 完全相等：只有固定訊息與 request_id，不含主機、port、帳號、資料庫名稱或驅動錯誤。
    assert error == {
        "code": "DEPENDENCY_UNAVAILABLE",
        "message": "資料庫目前無法連線。",
        "request_id": error["request_id"],
    }
    assert REQUEST_ID_PATTERN.match(str(error["request_id"]))
    assert migrated_database.name not in str(body)
    # 伺服器端要留下原因（例外類別），但不能寫入連線字串、帳號或密碼。
    logged = " ".join(record.getMessage() for record in caplog.records)
    assert "OperationalError" in logged
    for secret in (migrated_database.name, migrated_database.password, f"port {UNREACHABLE_PORT}"):
        assert secret not in logged


def test_not_ready_before_migrations_run(fresh_database: ProvisionedDatabase) -> None:
    status, body = _ready(fresh_database.app_settings())

    assert status == 503
    error = body["error"]
    assert isinstance(error, dict)
    assert error["code"] == "DEPENDENCY_UNAVAILABLE"
    assert error["message"] == "資料庫 schema 不是目前版本，請先執行 migration。"


def test_not_ready_when_schema_revision_differs(fresh_database: ProvisionedDatabase) -> None:
    engine = app_engine(fresh_database)
    try:
        with engine.begin() as connection:
            connection.execute(text("CREATE TABLE alembic_version (version_num varchar(32))"))
            connection.execute(text("INSERT INTO alembic_version VALUES ('0000')"))
    finally:
        engine.dispose()

    status, body = _ready(fresh_database.app_settings())

    assert status == 503
    error = body["error"]
    assert isinstance(error, dict)
    assert error["message"] == "資料庫 schema 不是目前版本，請先執行 migration。"
