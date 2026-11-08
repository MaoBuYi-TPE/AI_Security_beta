"""T21 的全域管理檢視：稽核查詢與待核准清單只限 platform_admin。"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from secscan.api_keys.domain import Role
from tests.integration.api_support import Seeder, World

pytestmark = pytest.mark.integration


def test_global_audit_events_are_admin_only_and_filterable(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    target = seed.target(world.operator_a, world.project_a.id)
    seed.grant(world.operator_a, target)
    url = "/api/v1/audit-events"
    for caller in (world.viewer_a, world.operator_a):
        assert api_client.get(url, headers=caller.headers).status_code == 403
    assert api_client.get(url).status_code == 401
    everything = api_client.get(f"{url}?limit=100", headers=world.admin.headers).json()
    assert everything["meta"]["total"] >= 3
    times = [item["created_at"] for item in everything["data"]]
    assert times == sorted(times, reverse=True)
    filtered = api_client.get(
        f"{url}?project_id={world.project_a.id}&action=scope_grant.create",
        headers=world.admin.headers,
    ).json()
    assert filtered["meta"]["total"] == 1
    assert filtered["data"][0]["action"] == "scope_grant.create"
    by_object = api_client.get(
        f"{url}?object_type=target&object_id={target.id}", headers=world.admin.headers
    ).json()
    assert {item["object_id"] for item in by_object["data"]} == {str(target.id)}
    future = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    later = api_client.get(
        f"{url}?created_after={future.replace('+', '%2B')}", headers=world.admin.headers
    ).json()
    assert later["meta"]["total"] == 0
    assert (
        api_client.get(f"{url}?action={'x' * 65}", headers=world.admin.headers).status_code == 422
    )


def test_pending_grants_are_listed_across_projects_for_admins(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    target_a = seed.target(world.operator_a, world.project_a.id)
    pending = seed.grant(world.operator_a, target_a)
    approved = seed.approve(world.admin, seed.grant(world.operator_a, target_a))
    operator_b = seed.member(world.admin, world.project_b.id, Role.OPERATOR)
    target_b = seed.target(operator_b, world.project_b.id)
    other = seed.grant(operator_b, target_b)
    url = "/api/v1/scope-grants/pending"
    for caller in (world.viewer_a, world.operator_a, operator_b):
        assert api_client.get(url, headers=caller.headers).status_code == 403
    listed = api_client.get(f"{url}?limit=100", headers=world.admin.headers).json()
    ids = [item["id"] for item in listed["data"]]
    assert str(pending.id) in ids
    assert str(other.id) in ids
    assert str(approved.id) not in ids
    assert ids.index(str(pending.id)) < ids.index(str(other.id))
    assert all(item["status"] == "pending" for item in listed["data"])
    # 一般的 grant 路由不受影響。
    assert (
        api_client.get(
            f"/api/v1/scope-grants/{pending.id}", headers=world.operator_a.headers
        ).status_code
        == 200
    )
    assert (
        api_client.get(f"/api/v1/scope-grants/{uuid4()}", headers=world.admin.headers).status_code
        == 404
    )
