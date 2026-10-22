"""scope grant 端點（docs/API_CONTRACT.md §14）：審批流程走真正的 HTTP、驗證、授權與 commit。

T06 DoD：轉換正確、LAB_ONLY 時 IP 在 LAB_CIDR 內、留下 audit；其他 project 的 grant 與不存在的
一樣回 404。
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from httpx2 import Response

from secscan.targets.domain import Target
from tests.integration.api_support import Caller, Seeder, World

pytestmark = pytest.mark.integration

GRANTS = "/api/v1/scope-grants"


def _of_target(target_id: UUID) -> str:
    return f"/api/v1/targets/{target_id}/scope-grants"


def _body(target: Target, **overrides: object) -> dict[str, Any]:
    return {
        "allowed_origins": [str(target.origin)],
        "allowed_ips": ["10.89.7.20"],
        "allowed_paths": ["/users/v1", "/books/v1/{book_title}"],
        "excluded_paths": ["/users/v1/_debug"],
        "allowed_methods": ["GET", "HEAD"],
        "budget": {"max_requests": 1000},
        "authorization_reference": "LAB-ASSET-001",
        "valid_until": (datetime.now(UTC) + timedelta(days=7)).isoformat(),
        **overrides,
    }


def _error(response: Response) -> dict[str, Any]:
    body = response.json()
    assert body["success"] is False
    error: dict[str, Any] = body["error"]
    error.pop("request_id")
    return error


def _decide(client: TestClient, caller: Caller, grant_id: object, action: str) -> Response:
    payload = {"note": "已核對 lab"} if action == "approve" else {"reason": "實驗結束"}
    return client.post(f"{GRANTS}/{grant_id}/{action}", json=payload, headers=caller.headers)


def _audit(client: TestClient, world: World, grant_id: str) -> list[dict[str, Any]]:
    events = client.get(
        f"/api/v1/projects/{world.project_a.id}/audit-events",
        params={"limit": 100},
        headers=world.admin.headers,
    ).json()["data"]
    return [event for event in reversed(events) if event["object_id"] == grant_id]


def test_request_approve_and_revoke(api_client: TestClient, seed: Seeder, world: World) -> None:
    target = seed.target(world.operator_a, world.project_a.id)

    requested = api_client.post(
        _of_target(target.id), json=_body(target), headers=world.operator_a.headers
    )
    grant = requested.json()["data"]
    seen_by_viewer = api_client.get(f"{GRANTS}/{grant['id']}", headers=world.viewer_a.headers)
    by_operator = _decide(api_client, world.operator_a, grant["id"], "approve")
    approved = _decide(api_client, world.admin, grant["id"], "approve")
    approved_again = _decide(api_client, world.admin, grant["id"], "approve")
    revoked = _decide(api_client, world.admin, grant["id"], "revoke")
    revoked_again = _decide(api_client, world.admin, grant["id"], "revoke")
    approve_revoked = _decide(api_client, world.admin, grant["id"], "approve")
    listed = api_client.get(_of_target(target.id), headers=world.viewer_a.headers)

    assert requested.status_code == 201
    assert (grant["status"], grant["version"], grant["project_id"]) == (
        "pending",
        1,
        str(world.project_a.id),
    )
    assert grant["budget"] == {
        "requests_per_second": 2,
        "max_requests": 1000,
        "max_duration_seconds": 1500,
    }
    assert seen_by_viewer.json()["data"] == grant
    assert by_operator.status_code == 403
    assert approved.status_code == 200
    assert approved.json()["data"]["status"] == "approved"
    assert approved.json()["data"]["approved_by_key_id"] == str(world.admin.principal.key_id)
    assert approved_again.status_code == 409
    assert _error(approved_again)["code"] == "INVALID_STATE_TRANSITION"
    assert (revoked.status_code, revoked_again.status_code) == (200, 200)
    assert revoked.json()["data"]["status"] == "revoked"
    assert revoked_again.json()["data"] == revoked.json()["data"]
    assert approve_revoked.status_code == 409
    assert [item["id"] for item in listed.json()["data"]] == [grant["id"]]
    assert [event["action"] for event in _audit(api_client, world, grant["id"])] == [
        "scope_grant.create",
        "scope_grant.approve",
        "scope_grant.revoke",
    ]


def test_expired_status_is_derived_when_read(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    """過期不需要改 DB：直接寫入一筆期限已過的申請，讀出來就是 expired，也不能核准。"""
    target = seed.target(world.operator_a, world.project_a.id)
    [row] = seed.query(
        "INSERT INTO scope_grants (target_id, version, status, allowed_origins, allowed_ips, "
        "allowed_paths, allow_all_paths, excluded_paths, allowed_methods, requests_per_second, "
        "max_requests, max_duration_seconds, authorization_reference, valid_from, valid_until, "
        "requested_by_key_id) VALUES (:target, 1, 'pending', ARRAY[:origin], "
        "ARRAY['10.89.7.20']::inet[], ARRAY['/users/v1'], false, ARRAY[]::varchar[], "
        "ARRAY['GET'], 2, 5000, 1500, 'LAB-1', now() - interval '2 days', "
        "now() - interval '1 day', :key) RETURNING id",
        target=target.id,
        origin=str(target.origin),
        key=world.operator_a.principal.key_id,
    )

    fetched = api_client.get(f"{GRANTS}/{row.id}", headers=world.viewer_a.headers)
    approve = _decide(api_client, world.admin, row.id, "approve")

    assert fetched.json()["data"]["status"] == "expired"
    assert approve.status_code == 409
    assert _error(approve)["code"] == "INVALID_STATE_TRANSITION"


@pytest.mark.parametrize("address", ["192.168.1.10", "10.89.7.0", "10.89.7.255", "10.89.8.1"])
def test_ips_must_be_lab_hosts(
    api_client: TestClient, seed: Seeder, world: World, address: str
) -> None:
    target = seed.target(world.operator_a, world.project_a.id)

    response = api_client.post(
        _of_target(target.id),
        json=_body(target, allowed_ips=[address]),
        headers=world.operator_a.headers,
    )

    assert response.status_code == 422
    assert _error(response)["code"] == "SCOPE_OUTSIDE_LAB"
    assert "10.89.7.0/24" in response.text


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"allowed_origins": ["https://vampi-vuln:5000"]}, "INVALID_TARGET"),
        ({"allowed_origins": ["http://admin:hunter2-secret@lab"]}, "INVALID_TARGET"),
        ({"allowed_paths": ["/users/../admin"]}, "INVALID_REQUEST"),
        ({"allowed_methods": ["TRACE"]}, "INVALID_REQUEST"),
        ({"budget": {"max_requests": 5001}}, "INVALID_REQUEST"),
        ({"valid_until": "2027-01-01T00:00:00"}, "INVALID_REQUEST"),
        ({"valid_until": "9999-12-31T23:59:59-05:00"}, "INVALID_REQUEST"),
        ({"status": "approved"}, "INVALID_REQUEST"),
        ({"version": 7}, "INVALID_REQUEST"),
    ],
    ids=[
        "https",
        "userinfo",
        "dot-segment",
        "trace",
        "over-budget",
        "naive-time",
        "end-of-time",
        "status",
        "version",
    ],
)
def test_invalid_requests(
    api_client: TestClient,
    seed: Seeder,
    world: World,
    overrides: dict[str, object],
    code: str,
) -> None:
    target = seed.target(world.operator_a, world.project_a.id)

    response = api_client.post(
        _of_target(target.id), json=_body(target, **overrides), headers=world.operator_a.headers
    )

    assert response.status_code == 422
    assert _error(response)["code"] == code
    assert "hunter2-secret" not in response.text
    assert (
        api_client.get(_of_target(target.id), headers=world.admin.headers).json()["meta"]["total"]
        == 0
    )


def test_viewer_cannot_request_or_decide(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    target = seed.target(world.operator_a, world.project_a.id)
    grant = seed.grant(world.operator_a, target)

    requested = api_client.post(
        _of_target(target.id), json=_body(target), headers=world.viewer_a.headers
    )

    assert requested.status_code == 403
    for action in ("approve", "revoke"):
        response = _decide(api_client, world.viewer_a, grant.id, action)
        assert response.status_code == 403
        assert _error(response)["code"] == "ROLE_NOT_ALLOWED"


def test_other_project_grants_look_exactly_like_missing_ones(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    foreign_target = seed.target(world.admin, world.project_b.id)
    foreign = seed.grant(world.admin, foreign_target)
    headers = world.operator_a.headers
    missing = api_client.get(f"{GRANTS}/{uuid4()}", headers=headers)

    responses = [
        api_client.get(f"{GRANTS}/{foreign.id}", headers=headers),
        api_client.get(_of_target(foreign_target.id), headers=headers),
        api_client.post(_of_target(foreign_target.id), json=_body(foreign_target), headers=headers),
        _decide(api_client, world.operator_a, foreign.id, "approve"),
        _decide(api_client, world.operator_a, foreign.id, "revoke"),
        _decide(api_client, world.operator_a, uuid4(), "approve"),
    ]

    assert {response.status_code for response in responses} == {404}
    assert all(_error(response) == _error(missing) for response in responses)
    [row] = seed.query("SELECT status FROM scope_grants WHERE id = :id", id=foreign.id)
    assert row.status == "pending"
