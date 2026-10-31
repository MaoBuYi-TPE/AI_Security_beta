"""GET /api/v1/scan-profiles（docs/DECISIONS.md §19.10）：任何有效的平台 key；內容不分 project。

每個測試用自己的資料庫：可用與否看最近存活的 runner。
"""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.main import create_app
from secscan.scanners.domain.instances import Capabilities, EngineCapability, InstanceRole
from secscan.scanners.domain.zap.policy import API_RULES, WEB_RULES
from secscan.scanners.service import Fleet
from secscan.scans.domain.catalog import Engine as ScanEngine
from tests.integration.api_support import Seeder, World
from tests.integration.database import ProvisionedDatabase

pytestmark = pytest.mark.integration

PROFILES = "/api/v1/scan-profiles"
ZAP_IMAGE = "zaproxy/zap-stable:20261016@sha256:" + "cd" * 32


@pytest.fixture
def client(queue_database: ProvisionedDatabase) -> Iterator[TestClient]:
    with TestClient(create_app(queue_database.app_settings())) as test_client:
        yield test_client


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


def _beat(engine: Engine, capability: EngineCapability) -> None:
    Fleet(
        sessionmaker(engine),
        owner="runner-profiles",
        role=InstanceRole.RUNNER,
        software_version="test",
    ).beat(Capabilities(engines=(capability,)))


def test_without_a_runner_nothing_can_be_used(client: TestClient, world: World) -> None:
    response = client.get(PROFILES, headers=world.viewer_a.headers)

    assert response.status_code == 200
    assert response.json()["data"] == []


def test_a_live_runner_lists_what_can_be_used(
    client: TestClient, world: World, queue_engine: Engine
) -> None:
    _beat(queue_engine, EngineCapability(ScanEngine.ZAP, ZAP_IMAGE, None, version="2.17.0"))

    body = client.get(PROFILES, headers=world.viewer_a.headers).json()

    profiles = {item["profile"]: item for item in body["data"]}
    assert set(profiles) == {"api_active_lab", "web_active_lab"}
    api = profiles["api_active_lab"]
    assert api["requires_spec"] is True
    assert set(api["target_kinds"]) == {"api", "hybrid"}
    [zap] = api["engines"]
    assert (zap["engine"], zap["version"], zap["image"]) == ("zap", "2.17.0", ZAP_IMAGE)
    assert zap["rule_count"] == len(API_RULES)
    assert len(zap["definition_sha256"]) == 64
    assert zap["grant_requirements"] == []
    [web_zap] = profiles["web_active_lab"]["engines"]
    assert web_zap["rule_count"] == len(WEB_RULES)
    assert web_zap["grant_requirements"] == ["GET /"]


def test_a_key_is_required(client: TestClient) -> None:
    assert client.get(PROFILES).status_code == 401
