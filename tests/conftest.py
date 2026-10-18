from collections.abc import Callable, Iterator

import psycopg
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from secscan.core.config import AppEnv, Settings
from secscan.main import create_app

type ClientFactory = Callable[[AppEnv], TestClient]

# 應用程式的 DB 連線設定。測試一律不得沿用開發者 shell 或 .env 裡的值，以免連到開發或正式資料庫；
# 整合測試另有 TEST_DB_* 設定（tests/integration/database.py）。
DB_ENV_KEYS = (
    "DB_HOST",
    "DB_PORT",
    "DB_NAME",
    "DB_USER",
    "DB_PASSWORD",
    "DB_CONNECT_TIMEOUT_SECONDS",
)
# 127.0.0.1:1 沒有服務：就算有測試誤打需要 DB 的端點，也只會立刻失敗。
UNREACHABLE_DB_PORT = 1


class DatabaseAccessBlockedError(RuntimeError):
    """非整合測試嘗試連線資料庫。"""


@pytest.fixture(autouse=True)
def _isolate_app_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Settings 不讀 .env（pytest 在 repo 根目錄執行，那裡有真實的本機密碼），也不讀 DB_* 環境變數。

    要測 .env 讀取行為的測試，自行把 env_file 設回來。
    """
    monkeypatch.setitem(Settings.model_config, "env_file", None)
    for key in DB_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


@pytest.fixture(autouse=True)
def _forbid_database_outside_integration(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    """unit/contract 測試不得連 DB。psycopg 經 libpq 連線，pytest-socket 擋不到，所以另外封鎖。"""
    if request.node.get_closest_marker("integration") is not None:
        return

    def _blocked(*_args: object, **_kwargs: object) -> None:
        raise DatabaseAccessBlockedError("只有標記 integration 的測試可以連線資料庫")

    monkeypatch.setattr(psycopg, "connect", _blocked)
    monkeypatch.setattr(psycopg.Connection, "connect", _blocked)


@pytest.fixture
def make_client() -> Iterator[ClientFactory]:
    """依指定的 APP_ENV 建立測試用 client。

    DB 密碼是假的、port 指向沒有服務的位置：engine 不會在建立時連線，這些測試也不打需要 DB 的端點。
    """
    clients: list[TestClient] = []

    def factory(app_env: AppEnv) -> TestClient:
        settings = Settings(
            app_env=app_env,
            db_port=UNREACHABLE_DB_PORT,
            db_password=SecretStr("not-a-real-password"),
            _env_file=None,
        )
        test_client = TestClient(create_app(settings))
        clients.append(test_client)
        return test_client

    yield factory
    for test_client in clients:
        test_client.close()


@pytest.fixture
def client(make_client: ClientFactory) -> TestClient:
    return make_client("test")
