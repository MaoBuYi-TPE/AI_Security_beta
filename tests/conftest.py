from collections.abc import Callable, Iterator

import pytest
from fastapi.testclient import TestClient

from secscan.core.config import AppEnv, Settings
from secscan.main import create_app

type ClientFactory = Callable[[AppEnv], TestClient]


@pytest.fixture
def make_client() -> Iterator[ClientFactory]:
    """依指定的 APP_ENV 建立測試用 client；不讀取開發者本機的 .env。"""
    clients: list[TestClient] = []

    def factory(app_env: AppEnv) -> TestClient:
        test_client = TestClient(create_app(Settings(app_env=app_env, _env_file=None)))
        clients.append(test_client)
        return test_client

    yield factory
    for test_client in clients:
        test_client.close()


@pytest.fixture
def client(make_client: ClientFactory) -> TestClient:
    return make_client("test")
