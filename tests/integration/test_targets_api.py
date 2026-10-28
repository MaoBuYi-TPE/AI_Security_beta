"""targets 端點（docs/API_CONTRACT.md §14）：走真正的 HTTP、驗證、授權與 commit。

其他 project 的 target 與不存在的 target、不存在的路徑回應完全相同（只差 request_id）。
"""

from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from httpx2 import Response

from tests.integration.api_support import Seeder, World, unique_name

pytestmark = pytest.mark.integration

TARGETS = "/api/v1/targets"
TARGET_FIELDS = {
    "id",
    "project_id",
    "name",
    "kind",
    "canonical_origin",
    "environment",
    "enabled",
    "created_at",
}


def _in_project(project_id: UUID) -> str:
    return f"/api/v1/projects/{project_id}/targets"


def _body(**overrides: object) -> dict[str, object]:
    return {
        "name": unique_name("VAmPI"),
        "kind": "api",
        "base_url": f"http://{unique_name('vampi')}:5000",
        **overrides,
    }


def _error(response: Response) -> dict[str, Any]:
    body = response.json()
    assert body["success"] is False
    error: dict[str, Any] = body["error"]
    error.pop("request_id")
    return error


def test_operator_creates_and_reads_a_target(api_client: TestClient, world: World) -> None:
    host = unique_name("vampi")
    payload = _body(base_url=f"HTTP://{host.upper()}:5000/", environment="lab")

    created = api_client.post(
        _in_project(world.project_a.id), json=payload, headers=world.operator_a.headers
    )
    target = created.json()["data"]
    fetched = api_client.get(f"{TARGETS}/{target['id']}", headers=world.viewer_a.headers)
    listed = api_client.get(_in_project(world.project_a.id), headers=world.viewer_a.headers)

    assert created.status_code == 201
    assert set(target) == TARGET_FIELDS
    assert target["canonical_origin"] == f"http://{host}:5000"
    assert (target["kind"], target["environment"], target["enabled"]) == ("api", "lab", True)
    assert target["created_at"].endswith("Z")
    assert fetched.json()["data"] == target
    assert target in listed.json()["data"]
    assert listed.json()["meta"]["total"] >= 1


def test_viewer_cannot_create_a_target(api_client: TestClient, world: World) -> None:
    response = api_client.post(
        _in_project(world.project_a.id), json=_body(), headers=world.viewer_a.headers
    )

    assert response.status_code == 403
    assert _error(response)["code"] == "ROLE_NOT_ALLOWED"


def test_other_project_looks_exactly_like_a_missing_one(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    foreign = seed.target(world.admin, world.project_b.id)
    headers = world.operator_a.headers
    missing_path = api_client.get("/api/v1/no-such-resource", headers=headers)

    responses = [
        api_client.post(_in_project(world.project_b.id), json=_body(), headers=headers),
        api_client.post(_in_project(uuid4()), json=_body(), headers=headers),
        api_client.get(_in_project(world.project_b.id), headers=headers),
        api_client.get(f"{TARGETS}/{foreign.id}", headers=headers),
        api_client.get(f"{TARGETS}/{uuid4()}", headers=headers),
        api_client.patch(f"{TARGETS}/{foreign.id}", json={"enabled": False}, headers=headers),
    ]

    assert {response.status_code for response in responses} == {404}
    assert all(_error(response) == _error(missing_path) for response in responses)
    assert seed.query("SELECT enabled FROM targets WHERE id = :id", id=foreign.id)[0].enabled


def test_invalid_base_url_is_rejected_without_echoing_it(
    api_client: TestClient, world: World
) -> None:
    payload = _body(base_url="http://admin:hunter2-secret@vampi-vuln:5000")

    response = api_client.post(
        _in_project(world.project_a.id), json=payload, headers=world.operator_a.headers
    )

    assert response.status_code == 422
    assert _error(response)["code"] == "INVALID_TARGET"
    assert "hunter2-secret" not in response.text


@pytest.mark.parametrize(
    "base_url", ["http://192.168.1.10:5000", "http://10.89.7.255", "http://10.89.7.254:8080"]
)
def test_ip_hosts_outside_the_lab_are_rejected(
    api_client: TestClient, world: World, base_url: str
) -> None:
    response = api_client.post(
        _in_project(world.project_a.id),
        json=_body(base_url=base_url),
        headers=world.operator_a.headers,
    )

    assert response.status_code == 422
    assert _error(response)["code"] == "SCOPE_OUTSIDE_LAB"


def test_duplicate_origin_is_a_conflict(api_client: TestClient, world: World) -> None:
    payload = _body()
    url = _in_project(world.project_a.id)

    api_client.post(url, json=payload, headers=world.operator_a.headers)
    response = api_client.post(
        url, json=_body(base_url=payload["base_url"]), headers=world.admin.headers
    )

    assert response.status_code == 409
    assert _error(response)["code"] == "TARGET_ORIGIN_CONFLICT"
    assert "uq_" not in response.text


@pytest.mark.parametrize(
    "payload",
    [
        {"kind": "api", "base_url": "http://lab"},
        _body(kind="graphql"),
        _body(environment="prod"),
        _body(canonical_origin="http://lab"),
        _body(project_id=str(uuid4())),
    ],
    ids=["missing-name", "kind", "environment", "canonical-origin", "project-id"],
)
def test_invalid_target_payload(
    api_client: TestClient, world: World, payload: dict[str, object]
) -> None:
    response = api_client.post(
        _in_project(world.project_a.id), json=payload, headers=world.operator_a.headers
    )

    assert response.status_code == 422
    assert _error(response)["code"] == "INVALID_REQUEST"


def test_operator_disables_a_target_and_it_is_audited(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    target = seed.target(world.operator_a, world.project_a.id)
    url = f"{TARGETS}/{target.id}"

    disabled = api_client.patch(url, json={"enabled": False}, headers=world.operator_a.headers)
    viewer = api_client.patch(url, json={"enabled": True}, headers=world.viewer_a.headers)
    origin_change = api_client.patch(
        url, json={"base_url": "http://other:5000"}, headers=world.operator_a.headers
    )
    empty = api_client.patch(url, json={}, headers=world.operator_a.headers)
    events = api_client.get(
        f"/api/v1/projects/{world.project_a.id}/audit-events", headers=world.admin.headers
    ).json()["data"]

    assert disabled.status_code == 200
    assert disabled.json()["data"]["enabled"] is False
    assert viewer.status_code == 403
    assert (origin_change.status_code, empty.status_code) == (422, 422)
    [update] = [
        event
        for event in events
        if event["action"] == "target.update" and event["object_id"] == str(target.id)
    ]
    assert update["changes"] == {"enabled": {"from": True, "to": False}}
    assert update["actor_key_id"] == str(world.operator_a.principal.key_id)
