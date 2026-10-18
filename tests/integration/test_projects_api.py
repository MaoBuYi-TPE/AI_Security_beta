"""projects 端點（docs/API_CONTRACT.md §13）：走真正的 HTTP、驗證、授權與 commit。

T05 DoD「A 專案不能讀 B 專案的資料」：其他 project 的回應與不存在的 project、不存在的路徑
完全相同（只差 request_id）。
"""

from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from httpx2 import Response

from tests.integration.api_support import Caller, Seeder, World, unique_name

pytestmark = pytest.mark.integration

PROJECTS = "/api/v1/projects"


def _member(world: World, role: str) -> Caller:
    return world.viewer_a if role == "viewer" else world.operator_a


def _error(response: Response) -> dict[str, Any]:
    body = response.json()
    assert body["success"] is False
    error: dict[str, Any] = body["error"]
    error.pop("request_id")
    return error


def test_admin_creates_and_reads_a_project(api_client: TestClient, world: World) -> None:
    name = unique_name("API 教學靶場")

    created = api_client.post(PROJECTS, json={"name": name}, headers=world.admin.headers)
    project = created.json()["data"]
    fetched = api_client.get(f"{PROJECTS}/{project['id']}", headers=world.admin.headers)

    assert created.status_code == 201
    assert created.json()["meta"] is None
    assert project["name"] == name
    assert set(project) == {"id", "name", "created_at"}
    assert project["created_at"].endswith("Z")
    assert fetched.status_code == 200
    assert fetched.json()["data"] == project


def test_duplicate_project_name_is_a_conflict(api_client: TestClient, world: World) -> None:
    response = api_client.post(
        PROJECTS, json={"name": world.project_a.name}, headers=world.admin.headers
    )

    assert response.status_code == 409
    assert _error(response)["code"] == "PROJECT_NAME_CONFLICT"
    assert "uq_" not in response.text


@pytest.mark.parametrize(
    "payload",
    [{}, {"name": "   "}, {"name": "　"}, {"name": "lab\u0000"}, {"name": "lab", "id": "x"}],
    ids=["missing", "blank", "fullwidth-blank", "nul", "extra-field"],
)
def test_invalid_project_payload_is_rejected(
    api_client: TestClient, world: World, payload: dict[str, str]
) -> None:
    response = api_client.post(PROJECTS, json=payload, headers=world.admin.headers)

    assert response.status_code == 422
    assert _error(response)["code"] == "INVALID_REQUEST"


@pytest.mark.parametrize("role", ["viewer", "operator"])
def test_members_list_only_their_own_project(
    api_client: TestClient, world: World, role: str
) -> None:
    response = api_client.get(PROJECTS, headers=_member(world, role).headers)

    body = response.json()
    assert response.status_code == 200
    assert [project["id"] for project in body["data"]] == [str(world.project_a.id)]
    assert body["meta"] == {"page": 1, "limit": 25, "total": 1}


def test_admin_lists_every_project_page_by_page(api_client: TestClient, world: World) -> None:
    """依建立時間由舊到新：最後兩頁（每頁一筆）正好是剛建立的 A 與 B。"""
    total = api_client.get(PROJECTS, params={"limit": 1}, headers=world.admin.headers).json()[
        "meta"
    ]["total"]

    pages = [
        api_client.get(PROJECTS, params={"limit": 1, "page": page}, headers=world.admin.headers)
        for page in (total - 1, total)
    ]

    assert total >= 2
    assert [page.json()["data"][0]["id"] for page in pages] == [
        str(world.project_a.id),
        str(world.project_b.id),
    ]
    assert pages[1].json()["meta"] == {"page": total, "limit": 1, "total": total}


@pytest.mark.parametrize("role", ["viewer", "operator"])
def test_other_projects_are_indistinguishable_from_missing_ones(
    api_client: TestClient, world: World, role: str
) -> None:
    headers = _member(world, role).headers

    own = api_client.get(f"{PROJECTS}/{world.project_a.id}", headers=headers)
    hidden = api_client.get(f"{PROJECTS}/{world.project_b.id}", headers=headers)
    missing = api_client.get(f"{PROJECTS}/{uuid4()}", headers=headers)
    no_route = api_client.get(f"{PROJECTS}/{world.project_a.id}/no-such-thing", headers=headers)

    assert own.status_code == 200
    assert hidden.status_code == missing.status_code == no_route.status_code == 404
    assert _error(hidden) == _error(missing) == _error(no_route)
    assert world.project_b.name not in hidden.text


@pytest.mark.parametrize("role", ["viewer", "operator"])
@pytest.mark.parametrize(
    ("method", "target", "payload", "status"),
    [
        ("POST", "projects", {"name": "mine"}, 403),
        ("POST", "own-keys", {"name": "escalate", "role": "operator"}, 403),
        ("POST", "other-keys", {"name": "escalate", "role": "operator"}, 404),
        ("GET", "own-audit", None, 403),
        ("GET", "other-audit", None, 404),
        ("DELETE", "key", None, 403),
    ],
)
def test_members_cannot_use_admin_endpoints(
    api_client: TestClient,
    world: World,
    role: str,
    method: str,
    target: str,
    payload: dict[str, str] | None,
    status: int,
) -> None:
    """自己的 project（或全域操作）角色不足 → 403；其他 project → 404。"""
    a, b = world.project_a.id, world.project_b.id
    path = {
        "projects": PROJECTS,
        "own-keys": f"{PROJECTS}/{a}/keys",
        "other-keys": f"{PROJECTS}/{b}/keys",
        "own-audit": f"{PROJECTS}/{a}/audit-events",
        "other-audit": f"{PROJECTS}/{b}/audit-events",
        "key": f"/api/v1/keys/{world.viewer_a.principal.key_id}",
    }[target]
    caller = _member(world, role)

    response = api_client.request(method, path, json=payload, headers=caller.headers)

    assert response.status_code == status
    expected = "ROLE_NOT_ALLOWED" if status == 403 else "RESOURCE_NOT_FOUND"
    assert _error(response)["code"] == expected
    # 被拒絕的操作沒有留下任何效果：viewer 的 key 仍可使用。
    assert api_client.get(PROJECTS, headers=world.viewer_a.headers).status_code == 200


def test_admin_reads_audit_events_newest_first(api_client: TestClient, world: World) -> None:
    path = f"{PROJECTS}/{world.project_a.id}/audit-events"

    response = api_client.get(path, headers=world.admin.headers)
    oldest = api_client.get(path, params={"limit": 1, "page": 3}, headers=world.admin.headers)

    body = response.json()
    assert response.status_code == 200
    assert [event["action"] for event in body["data"]] == [
        "api_key.create",
        "api_key.create",
        "project.create",
    ]
    assert body["meta"] == {"page": 1, "limit": 25, "total": 3}
    assert [event["object_id"] for event in body["data"]] == [
        str(world.operator_a.principal.key_id),
        str(world.viewer_a.principal.key_id),
        str(world.project_a.id),
    ]
    assert {event["actor_key_id"] for event in body["data"]} == {str(world.admin.principal.key_id)}
    assert oldest.json()["data"][0]["action"] == "project.create"
    for caller in (world.viewer_a, world.operator_a):
        assert caller.key[-64:] not in response.text


def test_audit_events_of_a_missing_project_are_not_found(
    api_client: TestClient, world: World
) -> None:
    response = api_client.get(f"{PROJECTS}/{uuid4()}/audit-events", headers=world.admin.headers)

    assert response.status_code == 404


def test_requests_commit_their_changes(api_client: TestClient, world: World, seed: Seeder) -> None:
    """request transaction 成功結束時會 commit：其他連線看得到新的 project 與 audit。"""
    name = unique_name("committed")

    created = api_client.post(PROJECTS, json={"name": name}, headers=world.admin.headers)

    project_id = created.json()["data"]["id"]
    rows = seed.query(
        "SELECT (SELECT count(*) FROM projects WHERE id = :id) AS projects, "
        "(SELECT count(*) FROM audit_events WHERE object_id = :id) AS events",
        id=project_id,
    )
    assert (rows[0].projects, rows[0].events) == (1, 1)
