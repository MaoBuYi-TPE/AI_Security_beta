from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient

from secscan.core.config import AppEnv

type ClientFactory = Callable[[AppEnv], TestClient]

DOC_PATHS = ["/docs", "/redoc", "/openapi.json"]


def test_live_returns_ok_envelope_without_extra_details(client: TestClient) -> None:
    response = client.get("/health/live")

    assert response.status_code == 200
    # 完全相等：只回存活狀態，不含版本、環境、主機或依賴資訊。
    assert response.json() == {
        "success": True,
        "data": {"status": "ok"},
        "error": None,
        "meta": None,
    }


@pytest.mark.parametrize("app_env", ["test", "prod"])
@pytest.mark.parametrize("path", DOC_PATHS)
def test_api_docs_are_hidden_outside_dev(
    make_client: ClientFactory, app_env: AppEnv, path: str
) -> None:
    assert make_client(app_env).get(path).status_code == 404


@pytest.mark.parametrize("path", DOC_PATHS)
def test_api_docs_are_available_in_dev(make_client: ClientFactory, path: str) -> None:
    assert make_client("dev").get(path).status_code == 200
