"""GET /api/v1/scanners（docs/DECISIONS.md §14.7）：任何有效的平台 key 都可以讀，內容不分 project。

每個測試用自己的資料庫：存活的判斷看的是整張 runner_instances。
"""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.main import create_app
from secscan.scanners.domain.instances import (
    Capabilities,
    CapabilityIssue,
    EngineCapability,
    InstanceRole,
)
from secscan.scanners.service import Fleet
from secscan.scans.domain.catalog import Engine as ScanEngine
from tests.integration.api_support import Seeder, World
from tests.integration.database import ProvisionedDatabase

pytestmark = pytest.mark.integration

IMAGE = "busybox:1.38.0@sha256:" + "ab" * 32


@pytest.fixture
def client(queue_database: ProvisionedDatabase) -> Iterator[TestClient]:
    with TestClient(create_app(queue_database.app_settings())) as test_client:
        yield test_client


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


def _beat(engine: Engine, role: InstanceRole, capabilities: Capabilities) -> None:
    Fleet(
        sessionmaker(engine, expire_on_commit=False),
        owner=f"{role.value}:test",
        role=role,
        software_version="0.1.0",
    ).beat(capabilities)


def _engines(body: dict[str, object]) -> dict[str, dict[str, object]]:
    data = body["data"]
    assert isinstance(data, dict)
    return {item["engine"]: item for item in data["engines"]}


@pytest.mark.parametrize("role", ["admin", "operator_a", "viewer_a"])
def test_every_valid_key_can_read_the_scanners(client: TestClient, world: World, role: str) -> None:
    response = client.get("/api/v1/scanners", headers=getattr(world, role).headers)

    assert response.status_code == 200
    body = response.json()
    assert body["meta"] is None
    assert list(_engines(body)) == ["zap", "nuclei", "schemathesis", "fake"]


def test_without_a_runner_nothing_is_available(client: TestClient, world: World) -> None:
    body = client.get("/api/v1/scanners", headers=world.viewer_a.headers).json()

    engines = _engines(body)
    assert engines["zap"] == {
        "engine": "zap",
        "integrated": False,
        "available": False,
        "image": None,
        "profiles": [],
        "unavailable_reason": "NOT_INTEGRATED",
    }
    assert engines["fake"]["unavailable_reason"] == "RUNNER_UNAVAILABLE"
    assert body["data"]["runner"] == {"alive": False, "last_heartbeat_at": None}
    assert body["data"]["worker"] == {"alive": False, "last_heartbeat_at": None}


def test_a_live_runner_makes_fake_available(
    client: TestClient, world: World, queue_engine: Engine
) -> None:
    _beat(
        queue_engine,
        InstanceRole.RUNNER,
        Capabilities(engines=(EngineCapability(ScanEngine.FAKE, IMAGE, None),)),
    )
    _beat(queue_engine, InstanceRole.WORKER, Capabilities(engines=()))

    body = client.get("/api/v1/scanners", headers=world.viewer_a.headers).json()

    assert _engines(body)["fake"] == {
        "engine": "fake",
        "integrated": True,
        "available": True,
        "image": IMAGE,
        "profiles": ["api_active_lab", "web_active_lab"],
        "unavailable_reason": None,
    }
    assert body["data"]["runner"]["alive"] is True
    assert body["data"]["worker"]["alive"] is True
    assert body["data"]["runner"]["last_heartbeat_at"].endswith("Z")


@pytest.mark.parametrize(
    "issue", [CapabilityIssue.SCAN_NETWORK_NOT_ISOLATED, CapabilityIssue.GUARD_UNAVAILABLE]
)
def test_a_capability_issue_is_reported(
    client: TestClient, world: World, queue_engine: Engine, issue: CapabilityIssue
) -> None:
    _beat(
        queue_engine,
        InstanceRole.RUNNER,
        Capabilities(engines=(EngineCapability(ScanEngine.FAKE, IMAGE, issue),)),
    )

    fake = _engines(client.get("/api/v1/scanners", headers=world.viewer_a.headers).json())["fake"]

    assert (fake["available"], fake["unavailable_reason"]) == (False, issue.value)


def test_a_missing_key_is_refused(client: TestClient) -> None:
    assert client.get("/api/v1/scanners").status_code == 401
