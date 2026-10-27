"""每個連線都有逾時（docs/DECISIONS.md §13.8）：等鎖或查詢逾時回 503，不會無限期卡住。"""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from secscan.main import create_app
from tests.integration.api_support import Seeder, World
from tests.integration.conftest import app_engine
from tests.integration.database import ProvisionedDatabase

pytestmark = pytest.mark.integration


@pytest.mark.parametrize(
    ("setting", "expected"),
    [
        ("statement_timeout", "30s"),
        ("lock_timeout", "5s"),
        ("idle_in_transaction_session_timeout", "1min"),
    ],
)
def test_app_connections_have_timeouts(db_engine: Engine, setting: str, expected: str) -> None:
    with db_engine.connect() as connection:
        value = connection.execute(text(f"SHOW {setting}")).scalar()

    assert value == expected


@pytest.fixture
def impatient_client(api_database: ProvisionedDatabase) -> Iterator[TestClient]:
    """等鎖 1 秒就放棄的 API（測試不必等 5 秒）。"""
    settings = api_database.app_settings().model_copy(update={"db_lock_timeout_seconds": 1})
    with TestClient(create_app(settings)) as client:
        yield client


def test_a_lock_wait_timeout_is_a_retryable_503(
    impatient_client: TestClient, api_database: ProvisionedDatabase, seed: Seeder, world: World
) -> None:
    """另一個 transaction 持有 target 的鎖時，修改 target 等 1 秒後回 503，不是 500。"""
    target = seed.target(world.operator_a, world.project_a.id)
    engine = app_engine(api_database)
    try:
        with Session(engine) as holder, holder.begin():
            holder.execute(
                text("SELECT id FROM targets WHERE id = :id FOR UPDATE"), {"id": target.id}
            )
            response = impatient_client.patch(
                f"/api/v1/targets/{target.id}",
                json={"name": "renamed"},
                headers=world.operator_a.headers,
            )
    finally:
        engine.dispose()

    assert response.status_code == 503
    assert response.headers["Retry-After"] == "1"
    assert response.json()["error"]["code"] == "DEPENDENCY_UNAVAILABLE"
    [row] = seed.query("SELECT name FROM targets WHERE id = :id", id=target.id)
    assert row.name == target.name
