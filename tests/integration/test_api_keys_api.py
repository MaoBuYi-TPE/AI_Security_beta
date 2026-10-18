"""API key 端點與驗證（docs/API_CONTRACT.md §13、docs/DECISIONS.md §9）：真正的 HTTP 與 commit。

T05 DoD：key 高熵且只存 hash、支援過期與撤銷；完整的 key 只顯示一次。
"""

import logging
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from httpx2 import Response

from secscan.api_keys.domain import Role
from secscan.main import create_app
from secscan.security.api_key_tokens import generate_key, hash_key, parse_prefix
from tests.integration.api_support import Seeder, World
from tests.integration.conftest import app_engine, migrate_to_head
from tests.integration.database import ProvisionedDatabase

pytestmark = pytest.mark.integration

PROJECTS = "/api/v1/projects"
SECRET_HEX = 64


def _keys_path(world: World) -> str:
    return f"{PROJECTS}/{world.project_a.id}/keys"


def _error(response: Response) -> dict[str, Any]:
    error: dict[str, Any] = response.json()["error"]
    error.pop("request_id")
    return error


def test_admin_issues_a_key_that_is_shown_only_once(
    api_client: TestClient, world: World, seed: Seeder
) -> None:
    response = api_client.post(
        _keys_path(world), json={"name": "ci-reader", "role": "viewer"}, headers=world.admin.headers
    )

    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store"
    data = response.json()["data"]
    key = data["key"]
    secret = key[-SECRET_HEX:]
    assert parse_prefix(key) == data["prefix"]
    assert set(data) == {
        "id",
        "project_id",
        "role",
        "name",
        "prefix",
        "created_at",
        "expires_at",
        "key",
    }
    assert (data["project_id"], data["role"]) == (str(world.project_a.id), "viewer")
    # 這把 key 可以用，而且只看得到自己的 project。
    listed = api_client.get(PROJECTS, headers={"Authorization": f"Bearer {key}"})
    assert [project["id"] for project in listed.json()["data"]] == [str(world.project_a.id)]
    # DB 只存 hash；api_keys 與 audit_events 的任何欄位都找不到 key 或 secret。
    [stored] = seed.query(
        "SELECT key_hash, row_to_json(api_keys)::text AS row FROM api_keys WHERE id = :id",
        id=data["id"],
    )
    assert stored.key_hash == hash_key(key)
    [audit] = seed.query(
        "SELECT string_agg(row_to_json(audit_events)::text, '') AS rows FROM audit_events "
        "WHERE object_id = :id",
        id=data["id"],
    )
    for row in (stored.row, audit.rows):
        assert key not in row
        assert secret not in row
    # 之後任何回應都拿不回完整的 key。
    audit_events = api_client.get(
        f"{PROJECTS}/{world.project_a.id}/audit-events", headers=world.admin.headers
    )
    for later in (listed, audit_events):
        assert secret not in later.text


def test_issued_key_expires_in_ninety_days_by_default(api_client: TestClient, world: World) -> None:
    response = api_client.post(
        _keys_path(world), json={"name": "ops", "role": "operator"}, headers=world.admin.headers
    )

    data = response.json()["data"]
    lifetime = datetime.fromisoformat(data["expires_at"]) - datetime.fromisoformat(
        data["created_at"]
    )
    assert data["role"] == "operator"
    assert abs(lifetime - timedelta(days=90)) < timedelta(minutes=1)


@pytest.mark.parametrize(
    ("payload", "detail"),
    [
        ({"name": "root", "role": "platform_admin"}, "body.role"),
        ({"name": "ci", "role": "viewer", "expires_at": "2001-01-01T00:00:00Z"}, "expires_at"),
        ({"name": "ci", "role": "viewer", "expires_at": "2999-01-01T00:00:00Z"}, "expires_at"),
        ({"name": "ci", "role": "viewer", "expires_at": "2027-01-01T00:00:00"}, "body.expires_at"),
        ({"name": "ci", "role": "viewer", "key_hash": "00"}, "body.key_hash"),
        ({"name": " ", "role": "viewer"}, "body.name"),
    ],
    ids=["admin-role", "past", "beyond-365-days", "naive", "extra-field", "blank-name"],
)
def test_invalid_key_requests_are_rejected(
    api_client: TestClient, world: World, payload: dict[str, str], detail: str
) -> None:
    response = api_client.post(_keys_path(world), json=payload, headers=world.admin.headers)

    assert response.status_code == 422
    error = _error(response)
    assert error["code"] == "INVALID_REQUEST"
    assert detail in error["message"]


def test_key_for_a_missing_project_is_not_found(api_client: TestClient, world: World) -> None:
    response = api_client.post(
        f"{PROJECTS}/{uuid4()}/keys",
        json={"name": "ci", "role": "viewer"},
        headers=world.admin.headers,
    )
    no_route = api_client.get("/api/v1/no-such-thing", headers=world.admin.headers)

    assert response.status_code == 404
    assert _error(response) == _error(no_route)
    assert "fk_" not in response.text


def test_revoked_key_stops_working_and_revocation_is_idempotent(
    api_client: TestClient, world: World, seed: Seeder
) -> None:
    victim = seed.member(world.admin, world.project_a.id, Role.VIEWER)
    path = f"/api/v1/keys/{victim.principal.key_id}"
    assert api_client.get(PROJECTS, headers=victim.headers).status_code == 200

    first = api_client.delete(path, headers=world.admin.headers)
    after = api_client.get(PROJECTS, headers=victim.headers)
    second = api_client.delete(path, headers=world.admin.headers)
    unknown = api_client.get(PROJECTS, headers={"Authorization": f"Bearer {generate_key().value}"})

    assert (first.status_code, first.content) == (204, b"")
    assert second.status_code == 204
    assert after.status_code == 401
    assert _error(after) == _error(unknown)
    [count] = seed.query(
        "SELECT count(*) AS n FROM audit_events WHERE action = 'api_key.revoke' "
        "AND object_id = :id",
        id=victim.principal.key_id,
    )
    assert count.n == 1


def test_revoking_a_missing_key_is_not_found(api_client: TestClient, world: World) -> None:
    response = api_client.delete(f"/api/v1/keys/{uuid4()}", headers=world.admin.headers)

    assert response.status_code == 404


def test_expired_key_gets_its_own_error(api_client: TestClient, world: World, seed: Seeder) -> None:
    victim = seed.member(world.admin, world.project_a.id, Role.OPERATOR)
    seed.execute(
        "UPDATE api_keys SET created_at = now() - interval '2 days', "
        "expires_at = now() - interval '1 day' WHERE id = :id",
        id=victim.principal.key_id,
    )

    response = api_client.get(PROJECTS, headers=victim.headers)

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert _error(response)["code"] == "API_KEY_EXPIRED"


def test_expired_key_with_a_wrong_secret_looks_like_any_bad_key(
    api_client: TestClient, world: World, seed: Seeder
) -> None:
    """先比對 secret 再判斷到期：只知道 prefix 的人看不出這把 key 已過期。"""
    victim = seed.member(world.admin, world.project_a.id, Role.OPERATOR)
    seed.execute(
        "UPDATE api_keys SET created_at = now() - interval '2 days', "
        "expires_at = now() - interval '1 day' WHERE id = :id",
        id=victim.principal.key_id,
    )
    forged = f"{victim.key[:-SECRET_HEX]}{'0' * SECRET_HEX}"

    response = api_client.get(PROJECTS, headers={"Authorization": f"Bearer {forged}"})
    missing = api_client.get(PROJECTS)

    assert response.status_code == 401
    assert _error(response) == _error(missing)


def test_failed_lookups_are_indistinguishable_and_never_logged(
    api_client: TestClient, world: World, seed: Seeder, caplog: pytest.LogCaptureFixture
) -> None:
    revoked = seed.member(world.admin, world.project_a.id, Role.VIEWER)
    api_client.delete(f"/api/v1/keys/{revoked.principal.key_id}", headers=world.admin.headers)
    presented = {
        "unknown_key": generate_key().value,
        "hash_mismatch": f"{world.viewer_a.key[:-SECRET_HEX]}{'0' * SECRET_HEX}",
        "revoked": revoked.key,
    }

    with caplog.at_level(logging.INFO, logger="secscan.api_keys.dependencies"):
        missing = api_client.get(PROJECTS)
        responses = {
            reason: api_client.get(PROJECTS, headers={"Authorization": f"Bearer {key}"})
            for reason, key in presented.items()
        }

    for response in responses.values():
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == missing.headers["www-authenticate"]
        assert _error(response) == _error(missing)
    logged = " ".join(record.getMessage() for record in caplog.records)
    for reason, key in presented.items():
        assert f"reason={reason}" in logged
        assert key not in logged
        assert key[-SECRET_HEX:] not in logged


def test_a_commit_failure_is_reported_as_500_not_201(
    fresh_database: ProvisionedDatabase,
) -> None:
    """commit 失敗時，client 不能先拿到 201（request session 的 scope 必須是 function）。

    以 DEFERRABLE 的 constraint trigger 讓特定名稱在 commit 時才失敗：INSERT 與 audit 都成功，
    路由也正常回傳，直到 commit 才出錯。
    """
    migrate_to_head(fresh_database)
    seed = Seeder(engine := app_engine(fresh_database))
    try:
        admin = seed.admin()
        seed.execute(
            "CREATE FUNCTION reject_at_commit() RETURNS trigger LANGUAGE plpgsql AS $$ "
            "BEGIN IF NEW.name = 'fail-at-commit' THEN RAISE EXCEPTION 'rejected at commit'; "
            "END IF; RETURN NULL; END $$"
        )
        seed.execute(
            "CREATE CONSTRAINT TRIGGER projects_reject_at_commit AFTER INSERT ON projects "
            "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_at_commit()"
        )
        app = create_app(fresh_database.app_settings())
        with TestClient(app, raise_server_exceptions=False) as client:
            response = client.post(PROJECTS, json={"name": "fail-at-commit"}, headers=admin.headers)

        [count] = seed.query("SELECT count(*) AS n FROM projects WHERE name = 'fail-at-commit'")
    finally:
        engine.dispose()

    assert response.status_code == 500
    assert response.json()["error"]["code"] == "INTERNAL_ERROR"
    assert count.n == 0
