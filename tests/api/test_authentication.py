"""/api/v1 一律要平台 API key（docs/DECISIONS.md §9）。這裡的測試不連 DB：

- 每個 /api/v1 路由的依賴樹都有 current_principal；OpenAPI 每個操作都要求驗證。
- 缺少 key、scheme 不對、格式不對：在查 DB 之前就回 401，三者的回應完全相同。
- 驗證在欄位驗證之前；沒有 key 或格式不符時連 body 都不讀（tests/api/test_request_guards.py）。
- 伺服器端記下失敗原因與 request_id，但不記 client 送來的值。
DB 相關的情境（key 不存在、secret 錯誤、撤銷、過期）在 tests/integration/test_api_keys_api.py。
"""

import json
import logging
from typing import cast
from uuid import uuid4

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.dependencies.models import Dependant
from fastapi.routing import RouteContext, iter_route_contexts
from fastapi.testclient import TestClient
from pydantic import SecretStr

from secscan.api_keys.dependencies import authenticated_router, current_principal
from secscan.auth_profiles.dependencies import secret_cipher
from secscan.core.api import API_V1_PREFIX
from secscan.core.config import Settings
from secscan.core.db import DatabaseResources, create_db_engine
from secscan.core.errors import register_error_handlers
from secscan.core.request_id import REQUEST_ID_HEADER, RequestIdMiddleware

# 所有業務端點；新增端點時要同步更新這張表（也會出現在 401 的測試中）。
V1_ROUTES = {
    # T05
    ("POST", "/api/v1/projects"),
    ("GET", "/api/v1/projects"),
    ("GET", "/api/v1/projects/{project_id}"),
    ("GET", "/api/v1/projects/{project_id}/audit-events"),
    ("POST", "/api/v1/projects/{project_id}/keys"),
    ("DELETE", "/api/v1/keys/{key_id}"),
    # T06
    ("POST", "/api/v1/projects/{project_id}/targets"),
    ("GET", "/api/v1/projects/{project_id}/targets"),
    ("GET", "/api/v1/targets/{target_id}"),
    ("PATCH", "/api/v1/targets/{target_id}"),
    ("POST", "/api/v1/targets/{target_id}/scope-grants"),
    ("GET", "/api/v1/targets/{target_id}/scope-grants"),
    ("GET", "/api/v1/scope-grants/{grant_id}"),
    ("POST", "/api/v1/scope-grants/{grant_id}/approve"),
    ("POST", "/api/v1/scope-grants/{grant_id}/revoke"),
    # T07
    ("POST", "/api/v1/targets/{target_id}/api-specs"),
    ("GET", "/api/v1/targets/{target_id}/api-specs"),
    ("GET", "/api/v1/api-specs/{spec_id}"),
    ("GET", "/api/v1/api-specs/{spec_id}/operations"),
    # T08
    ("POST", "/api/v1/targets/{target_id}/auth-profiles"),
    ("GET", "/api/v1/targets/{target_id}/auth-profiles"),
    ("GET", "/api/v1/auth-profiles/{profile_id}"),
    ("PATCH", "/api/v1/auth-profiles/{profile_id}"),
    ("GET", "/api/v1/auth-profiles/{profile_id}/versions"),
}
CANARY = "canary-credential-0003"


def _v1_routes(client: TestClient) -> list[RouteContext]:
    """實際生效的路由（含 include_router 的前綴與 router 層依賴）。

    FastAPI 0.143 的 app.routes 只放 include 進來的 router，不直接放 APIRoute；
    iter_route_contexts 是 FastAPI 產生 OpenAPI 時用的公開函式。
    """
    app = cast(FastAPI, client.app)
    routes = [
        route
        for route in iter_route_contexts(app.routes)
        if (route.path or "").startswith(API_V1_PREFIX)
    ]
    # 找不到任何路由時，下面「每個路由都要驗證」的檢查會空轉通過，所以先擋下。
    assert routes, "找不到任何 /api/v1 路由"
    return routes


def _calls(dependant: Dependant) -> set[object]:
    calls: set[object] = {dependant.call}
    for sub_dependant in dependant.dependencies:
        calls |= _calls(sub_dependant)
    return calls


def _concrete(path: str) -> str:
    return path.replace("{project_id}", str(uuid4())).replace("{key_id}", str(uuid4()))


def test_v1_routes_match_the_documented_endpoints(client: TestClient) -> None:
    listed = {
        (method, str(route.path)) for route in _v1_routes(client) for method in route.methods or ()
    }

    assert listed == V1_ROUTES


def test_every_v1_route_depends_on_api_key_authentication(client: TestClient) -> None:
    routes = _v1_routes(client)

    assert len(routes) == len(V1_ROUTES)
    for route in routes:
        dependant = route.dependant
        assert isinstance(dependant, Dependant), route.path
        assert current_principal in _calls(dependant), route.path


def test_router_level_authentication_covers_routes_without_a_principal_parameter() -> None:
    """之後新增的路由忘了宣告 CurrentPrincipal，掛在 authenticated_router 底下也一樣要 key。"""
    settings = Settings(app_env="test", db_port=1, db_password=SecretStr("x"), _env_file=None)
    app = FastAPI()
    app.add_middleware(RequestIdMiddleware)
    register_error_handlers(app)
    app.state.db = DatabaseResources(engine=create_db_engine(settings), schema_revision="0001")
    forgetful = APIRouter()

    @forgetful.get("/forgot-auth")
    def forgot_auth() -> dict[str, str]:
        return {"status": "exposed"}

    protected = authenticated_router(prefix=API_V1_PREFIX)
    protected.include_router(forgetful)
    app.include_router(protected)

    with TestClient(app) as client:
        response = client.get(f"{API_V1_PREFIX}/forgot-auth")

    assert response.status_code == 401
    assert "exposed" not in response.text


def test_openapi_requires_the_platform_key_and_never_exposes_hashes(client: TestClient) -> None:
    schema = cast(FastAPI, client.app).openapi()

    operations = [
        operation
        for path, methods in schema["paths"].items()
        if path.startswith(API_V1_PREFIX)
        for operation in methods.values()
    ]
    assert len(operations) == len(V1_ROUTES)
    assert all(operation["security"] == [{"PlatformApiKey": []}] for operation in operations)
    assert schema["components"]["securitySchemes"]["PlatformApiKey"] == {
        "type": "http",
        "scheme": "bearer",
        "description": schema["components"]["securitySchemes"]["PlatformApiKey"]["description"],
    }
    assert "key_hash" not in json.dumps(schema)


@pytest.mark.parametrize(("method", "path"), sorted(V1_ROUTES))
def test_requests_without_a_key_are_rejected_before_anything_else(
    client: TestClient, method: str, path: str
) -> None:
    """驗證在欄位驗證之前：合法 JSON 但欄位不符時，沒有 key 仍先得到 401，看不到欄位錯誤。"""
    response = client.request(method, _concrete(path), json={"unexpected": True})

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"


@pytest.mark.parametrize(
    "authorization",
    [
        None,
        f"Basic {CANARY}",
        f"Bearer {CANARY}",
        f"Bearer secscan_{'0' * 16}_{'Z' * 64}",
        "Bearer",
    ],
    ids=["missing", "wrong-scheme", "malformed", "not-hex", "empty"],
)
def test_bad_credentials_get_one_identical_response(
    client: TestClient, authorization: str | None
) -> None:
    baseline = client.get("/api/v1/projects")
    headers = {} if authorization is None else {"Authorization": authorization}

    response = client.get("/api/v1/projects", headers=headers)

    assert response.status_code == baseline.status_code == 401
    assert response.headers["www-authenticate"] == baseline.headers["www-authenticate"]
    error, expected = response.json()["error"], baseline.json()["error"]
    assert error.pop("request_id") != expected.pop("request_id")
    assert error == expected
    assert CANARY not in response.text


def test_rejections_are_logged_with_reason_but_without_the_credential(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="secscan.api_keys.dependencies"):
        response = client.get("/api/v1/projects", headers={"Authorization": f"Bearer {CANARY}"})

    logged = " ".join(record.getMessage() for record in caplog.records)
    assert "reason=malformed" in logged
    assert response.headers[REQUEST_ID_HEADER] in logged
    assert CANARY not in logged


def test_only_writes_to_auth_profiles_get_the_cipher(client: TestClient) -> None:
    """最小權限（審查建議）：查詢的路徑用不到加密元件，就不拿到它。"""
    routes = {
        (method, route.path): route
        for route in _v1_routes(client)
        for method in route.methods or ()
        if "auth-profiles" in (route.path or "")
    }
    with_cipher = {
        key
        for key, route in routes.items()
        if isinstance(route.dependant, Dependant) and secret_cipher in _calls(route.dependant)
    }

    assert len(routes) == 5
    assert with_cipher == {
        ("POST", "/api/v1/targets/{target_id}/auth-profiles"),
        ("PATCH", "/api/v1/auth-profiles/{profile_id}"),
    }
