"""認證設定的端點（docs/API_CONTRACT.md §16）：走真正的 HTTP、驗證、授權與 commit。

T08 DoD：secret 以 MultiFernet 加密、只寫不讀、支援換版、不寫入 log；preflight 定義有驗證。
回應、錯誤訊息、伺服器日誌與 audit 都找不到 secret；其他 project 的 profile 和不存在的一樣回 404。
"""

import json
import logging
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from httpx2 import Response

from secscan.api_keys.domain import Role
from secscan.targets.domain import Target
from tests.integration.api_support import Caller, Seeder, World
from tests.secret_support import bearer_context, shared_cipher

pytestmark = pytest.mark.integration

PROFILES = "/api/v1/auth-profiles"
CANARY = "canary-auth-profile-0308"
ME = {
    "method": "GET",
    "path": "/me",
    "expected_status": 200,
    "expected_json": {"/data/username": "name1", "/data/admin": False, "/status": "success"},
}


def _of_target(target_id: UUID) -> str:
    return f"/api/v1/targets/{target_id}/auth-profiles"


def _body(**fields: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": "VAmPI 一般使用者",
        "role_label": "standard_user",
        "type": "bearer",
        "secret": CANARY,
        "preflight": ME,
    }
    body.update(fields)
    return body


def _create(client: TestClient, caller: Caller, target_id: UUID, **fields: Any) -> Response:
    return client.post(_of_target(target_id), json=_body(**fields), headers=caller.headers)


def _data(response: Response) -> dict[str, Any]:
    body = response.json()
    assert body["success"] is True, body
    data: dict[str, Any] = body["data"]
    return data


def _items(response: Response) -> list[dict[str, Any]]:
    """清單端點的 data。"""
    body = response.json()
    assert body["success"] is True, body
    items: list[dict[str, Any]] = body["data"]
    return items


def _error(response: Response) -> dict[str, Any]:
    body = response.json()
    assert body["success"] is False
    error: dict[str, Any] = body["error"]
    error.pop("request_id")
    return error


def _no_secret(response: Response) -> None:
    assert CANARY not in response.text
    assert all(CANARY not in value for value in response.headers.values())
    assert '"secret"' not in response.text


@pytest.fixture
def target(seed: Seeder, world: World) -> Target:
    return seed.target(world.operator_a, world.project_a.id, "http://vampi-vuln:5000")


# --- 建立 -----------------------------------------------------------------------------------


def test_create_returns_the_profile_without_the_secret(
    api_client: TestClient, seed: Seeder, world: World, target: Target
) -> None:
    response = _create(api_client, world.operator_a, target.id)

    assert response.status_code == 201
    _no_secret(response)
    data = _data(response)
    assert set(data) == {
        "id",
        "target_id",
        "project_id",
        "name",
        "role_label",
        "created_by_key_id",
        "created_at",
        "version",
        "type",
        "header_name",
        "preflight",
        "secret_configured",
        "version_created_by_key_id",
        "version_created_at",
    }
    assert data["target_id"] == str(target.id)
    assert data["project_id"] == str(world.project_a.id)
    assert (data["version"], data["type"], data["header_name"]) == (1, "bearer", None)
    assert data["secret_configured"] is True
    assert data["preflight"] == ME
    assert data["preflight"]["expected_json"]["/data/admin"] is False
    assert data["created_by_key_id"] == str(world.operator_a.principal.key_id)
    [row] = seed.query(
        "SELECT encrypted_secret FROM auth_profile_versions WHERE profile_id = :id", id=data["id"]
    )
    assert CANARY.encode() not in row.encrypted_secret
    token = row.encrypted_secret
    assert shared_cipher().reveal(token, context=bearer_context(UUID(data["id"]))) == CANARY


def test_api_key_header_and_cookie_profiles(
    api_client: TestClient, world: World, target: Target
) -> None:
    api_key = _create(
        api_client,
        world.operator_a,
        target.id,
        role_label="api_user",
        type="api_key_header",
        header_name="X-API-Key",
        secret=f"Token {CANARY}",
    )
    cookie = _create(
        api_client,
        world.operator_a,
        target.id,
        role_label="cookie_user",
        type="cookie",
        secret=f"session={CANARY}; theme=dark",
    )

    assert (api_key.status_code, cookie.status_code) == (201, 201)
    assert _data(api_key)["header_name"] == "X-API-Key"
    assert _data(cookie)["type"] == "cookie"
    _no_secret(api_key)
    _no_secret(cookie)


@pytest.mark.parametrize(
    ("fields", "fragment"),
    [
        ({"secret": f"Bearer {CANARY}"}, "secret"),
        ({"secret": f"{CANARY}\r\nX-Injected: 1"}, "secret"),
        ({"type": "api_key_header", "header_name": "Host"}, "header_name"),
        ({"type": "api_key_header", "header_name": "X-HTTP-Method-Override"}, "header_name"),
        ({"type": "cookie", "secret": f"a={CANARY};b=2"}, "secret"),
        ({"role_label": "anonymous"}, "role_label"),
        ({"preflight": {**ME, "method": "POST"}}, "preflight.method"),
        ({"preflight": {**ME, "path": "/users/{id}"}}, "preflight.path"),
        ({"preflight": {**ME, "expected_json": {}}}, "preflight.expected_json"),
        ({"preflight": {**ME, "expected_status": 302}}, "preflight.expected_status"),
    ],
)
def test_invalid_profiles_are_rejected_without_echoing_the_input(
    api_client: TestClient,
    seed: Seeder,
    world: World,
    target: Target,
    fields: dict[str, Any],
    fragment: str,
) -> None:
    response = _create(api_client, world.operator_a, target.id, **fields)

    assert response.status_code == 422
    error = _error(response)
    assert error["code"] == "INVALID_REQUEST"
    assert error["message"].startswith(fragment)
    _no_secret(response)
    assert seed.query("SELECT 1 FROM auth_profiles WHERE target_id = :id", id=target.id) == []


@pytest.mark.parametrize(
    "body",
    [
        _body(secret=1234),
        _body(secret=None),
        _body(type="basic"),
        _body(extra=CANARY),
        _body(secret=CANARY * 200),
        _body(preflight={**ME, "expected_json": {"/a": 1.5}}),
        _body(preflight={**ME, "expected_json": {"/a": [CANARY]}}),
        _body(preflight={**ME, "expected_status": "200"}),
    ],
)
def test_malformed_bodies_only_report_field_locations(
    api_client: TestClient, world: World, target: Target, body: dict[str, Any]
) -> None:
    response = api_client.post(_of_target(target.id), json=body, headers=world.operator_a.headers)

    assert response.status_code == 422
    assert _error(response)["code"] == "INVALID_REQUEST"
    _no_secret(response)


def test_expected_json_keys_are_not_echoed(
    api_client: TestClient, world: World, target: Target
) -> None:
    """審查發現：expected_json 的 key 是使用者的輸入，原本會出現在 schema 錯誤的欄位位置中。
    值的型別改由 domain 檢查，訊息只說是第幾項。"""
    body = _body(preflight={**ME, "expected_json": {f"/{CANARY}": 1.5}})

    response = api_client.post(_of_target(target.id), json=body, headers=world.operator_a.headers)
    viewer = api_client.post(_of_target(target.id), json=body, headers=world.viewer_a.headers)

    assert response.status_code == 422
    assert "第 1 項" in _error(response)["message"]
    _no_secret(response)
    assert viewer.status_code == 403
    _no_secret(viewer)


def test_the_same_role_twice_is_a_conflict(
    api_client: TestClient, world: World, target: Target
) -> None:
    assert _create(api_client, world.operator_a, target.id).status_code == 201

    response = _create(api_client, world.operator_a, target.id)

    assert response.status_code == 409
    assert _error(response)["code"] == "AUTH_ROLE_CONFLICT"


# --- 權限 -----------------------------------------------------------------------------------


def test_viewers_and_other_projects_cannot_create(
    api_client: TestClient, world: World, target: Target
) -> None:
    viewer = _create(api_client, world.viewer_a, target.id)
    unknown = _create(api_client, world.operator_a, uuid4())
    bad_key = api_client.post(
        _of_target(target.id), json=_body(), headers={"Authorization": "Bearer x"}
    )

    assert (viewer.status_code, _error(viewer)["code"]) == (403, "ROLE_NOT_ALLOWED")
    assert unknown.status_code == 404
    assert bad_key.status_code == 401


def test_other_projects_get_the_same_404_as_missing_profiles(
    api_client: TestClient, seed: Seeder, world: World, target: Target
) -> None:
    profile_id = _data(_create(api_client, world.operator_a, target.id))["id"]
    outsider = seed.member(world.admin, world.project_b.id, Role.OPERATOR)
    missing = api_client.get(f"{PROFILES}/{uuid4()}", headers=world.operator_a.headers)

    for response in (
        api_client.get(f"{PROFILES}/{profile_id}", headers=outsider.headers),
        api_client.get(f"{PROFILES}/{profile_id}/versions", headers=outsider.headers),
        api_client.patch(
            f"{PROFILES}/{profile_id}", json={"secret": "t2"}, headers=outsider.headers
        ),
        api_client.get(_of_target(target.id), headers=outsider.headers),
        _create(api_client, outsider, target.id),
        api_client.get(f"/api/v1/no-such-path/{profile_id}", headers=outsider.headers),
    ):
        assert response.status_code == 404
        assert _error(response) == _error(missing)


# --- 新版本與查詢 ---------------------------------------------------------------------------


def test_patch_makes_a_new_version_and_erases_the_old_secret(
    api_client: TestClient, seed: Seeder, world: World, target: Target
) -> None:
    profile_id = _data(_create(api_client, world.operator_a, target.id))["id"]
    new_preflight = {**ME, "expected_json": {"/status": "success"}}

    secret_patch = api_client.patch(
        f"{PROFILES}/{profile_id}", json={"secret": f"{CANARY}-2"}, headers=world.operator_a.headers
    )
    preflight_patch = api_client.patch(
        f"{PROFILES}/{profile_id}",
        json={"preflight": new_preflight},
        headers=world.operator_a.headers,
    )

    assert (secret_patch.status_code, preflight_patch.status_code) == (200, 200)
    _no_secret(secret_patch)
    assert _data(secret_patch)["version"] == 2
    assert _data(preflight_patch)["version"] == 3
    assert _data(preflight_patch)["preflight"] == new_preflight
    rows = seed.query(
        "SELECT version, encrypted_secret FROM auth_profile_versions "
        "WHERE profile_id = :id ORDER BY version",
        id=profile_id,
    )
    assert [row.encrypted_secret is None for row in rows] == [True, True, False]
    token = rows[2].encrypted_secret
    assert shared_cipher().reveal(token, context=bearer_context(UUID(profile_id))) == f"{CANARY}-2"

    versions = api_client.get(f"{PROFILES}/{profile_id}/versions", headers=world.viewer_a.headers)
    listed = _items(versions)
    assert [entry["version"] for entry in listed] == [3, 2, 1]
    assert [entry["secret_configured"] for entry in listed] == [True, False, False]
    assert listed[1]["secret_erased_at"] is not None
    assert versions.json()["meta"]["total"] == 3
    _no_secret(versions)


@pytest.mark.parametrize(
    ("body", "fragment"),
    [
        ({}, "至少"),
        ({"preflight": ME}, "沒有任何變更"),
        ({"type": "cookie"}, "新的 secret"),
        ({"secret": f"Bearer {CANARY}"}, "secret"),
    ],
)
def test_patch_rules_are_enforced_over_http(
    api_client: TestClient, world: World, target: Target, body: dict[str, Any], fragment: str
) -> None:
    profile_id = _data(_create(api_client, world.operator_a, target.id))["id"]

    response = api_client.patch(
        f"{PROFILES}/{profile_id}", json=body, headers=world.operator_a.headers
    )

    assert response.status_code == 422
    assert fragment in _error(response)["message"]
    _no_secret(response)


@pytest.mark.parametrize(
    "body", [{"secret": None}, {"type": None}, {"preflight": None}, {"name": "x"}]
)
def test_patch_rejects_null_and_unknown_fields(
    api_client: TestClient, world: World, target: Target, body: dict[str, Any]
) -> None:
    profile_id = _data(_create(api_client, world.operator_a, target.id))["id"]

    response = api_client.patch(
        f"{PROFILES}/{profile_id}", json=body, headers=world.operator_a.headers
    )

    assert response.status_code == 422


def test_patch_does_not_ignore_a_null_next_to_a_real_change(
    api_client: TestClient, seed: Seeder, world: World, target: Target
) -> None:
    """突變檢查找到的缺口：null 與真正的變更一起送來時，不能默默忽略 null 而產生新版本。"""
    profile_id = _data(_create(api_client, world.operator_a, target.id))["id"]
    new_preflight = {**ME, "expected_json": {"/status": "success"}}

    response = api_client.patch(
        f"{PROFILES}/{profile_id}",
        json={"secret": None, "preflight": new_preflight},
        headers=world.operator_a.headers,
    )

    assert response.status_code == 422
    rows = seed.query(
        "SELECT version FROM auth_profile_versions WHERE profile_id = :id", id=profile_id
    )
    assert [row.version for row in rows] == [1]


def test_viewers_cannot_patch(api_client: TestClient, world: World, target: Target) -> None:
    profile_id = _data(_create(api_client, world.operator_a, target.id))["id"]

    response = api_client.patch(
        f"{PROFILES}/{profile_id}",
        json={"secret": f"Bearer {CANARY}"},
        headers=world.viewer_a.headers,
    )

    assert (response.status_code, _error(response)["code"]) == (403, "ROLE_NOT_ALLOWED")


def test_profiles_are_listed_per_target_with_paging(
    api_client: TestClient, world: World, target: Target
) -> None:
    created = [
        _data(_create(api_client, world.operator_a, target.id, role_label=f"user_{index}"))["id"]
        for index in range(3)
    ]

    first = api_client.get(f"{_of_target(target.id)}?limit=2", headers=world.viewer_a.headers)
    second = api_client.get(
        f"{_of_target(target.id)}?limit=2&page=2", headers=world.viewer_a.headers
    )
    single = api_client.get(f"{PROFILES}/{created[0]}", headers=world.viewer_a.headers)

    assert [entry["id"] for entry in _items(first) + _items(second)] == created
    assert first.json()["meta"] == {"page": 1, "limit": 2, "total": 3}
    assert _data(single)["id"] == created[0]
    _no_secret(first)


# --- 不寫入 log、不進 audit ------------------------------------------------------------------


def test_the_secret_never_reaches_logs_or_audit(
    api_client: TestClient,
    seed: Seeder,
    world: World,
    target: Target,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.DEBUG):
        profile_id = _data(_create(api_client, world.operator_a, target.id))["id"]
        api_client.patch(
            f"{PROFILES}/{profile_id}",
            json={"secret": f"{CANARY}-2"},
            headers=world.operator_a.headers,
        )
        _create(api_client, world.operator_a, target.id, role_label="x", secret=f"Bearer {CANARY}")
        _create(api_client, world.viewer_a, target.id, role_label="y")
        api_client.post(
            _of_target(target.id),
            json=_body(role_label="z", secret=7),
            headers=world.operator_a.headers,
        )
        api_client.post(
            _of_target(target.id),
            content=json.dumps(_body(role_label="w"))[:-3],
            headers={**world.operator_a.headers, "Content-Type": "application/json"},
        )
        api_client.get(f"{PROFILES}/{profile_id}/versions", headers=world.viewer_a.headers)

    assert CANARY not in caplog.text
    events = seed.query(
        "SELECT action, redacted_changes FROM audit_events "
        "WHERE object_id = :id ORDER BY created_at",
        id=profile_id,
    )
    assert [event.action for event in events] == ["auth_profile.create", "auth_profile.update"]
    assert CANARY not in json.dumps([event.redacted_changes for event in events])
    assert "name1" not in json.dumps([event.redacted_changes for event in events])
