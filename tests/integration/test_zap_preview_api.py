"""zap 的預覽開關與 profile 的規則（docs/DECISIONS.md §18.7、§18.9）。

zap 在 T15 才對操作者開放：沒有開關時 POST /scans 回 ENGINE_UNSUPPORTED；只給 live 測試的
SCAN_PREVIEW_ENGINES=zap 開啟時才接受。web profile 的 spider 從 / 開始：grant 必須允許 GET /。
"""

from collections.abc import Iterator
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from secscan.main import create_app
from secscan.scans.domain.catalog import ScanProfile
from secscan.targets.domain import TargetKind
from tests.integration.api_support import Caller, Scannable, Seeder, World
from tests.integration.database import ProvisionedDatabase

pytestmark = pytest.mark.integration

SCANS = "/api/v1/scans"


@pytest.fixture(scope="module")
def preview_client(api_database: ProvisionedDatabase) -> Iterator[TestClient]:
    settings = api_database.app_settings().model_copy(update={"scan_preview_engines": ("zap",)})
    with TestClient(create_app(settings)) as client:
        yield client


def _create(client: TestClient, caller: Caller, body: dict[str, object]) -> Any:
    headers = {**caller.headers, "Idempotency-Key": str(uuid4())}
    return client.post(SCANS, json=body, headers=headers)


def _api_body(scannable: Scannable) -> dict[str, object]:
    return {
        "target_id": str(scannable.target.id),
        "scope_grant_id": str(scannable.grant.id),
        "api_spec_id": str(scannable.spec.id),
        "auth_profile_id": None,
        "profile": ScanProfile.API_ACTIVE_LAB.value,
        "engines": ["zap"],
    }


def _web_body(seed: Seeder, world: World, paths: tuple[str, ...]) -> dict[str, object]:
    target = seed.target(world.operator_a, world.project_a.id, kind=TargetKind.WEB)
    grant = seed.approve(world.admin, seed.grant(world.operator_a, target, paths=paths))
    return {
        "target_id": str(target.id),
        "scope_grant_id": str(grant.id),
        "api_spec_id": None,
        "auth_profile_id": None,
        "profile": ScanProfile.WEB_ACTIVE_LAB.value,
        "engines": ["zap"],
    }


def test_zap_is_refused_without_the_preview_switch(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    response = _create(api_client, world.operator_a, _api_body(seed.scannable(world)))

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "ENGINE_UNSUPPORTED"


def test_the_preview_switch_accepts_a_zap_api_scan(
    preview_client: TestClient, seed: Seeder, world: World
) -> None:
    response = _create(preview_client, world.operator_a, _api_body(seed.scannable(world)))

    assert response.status_code == 202
    scan = response.json()["data"]
    assert [run["engine"] for run in scan["engines"]] == ["zap"]
    assert scan["fixture"] is False
    assert scan["auth_role"] == "anonymous"


def test_zap_on_the_web_profile_needs_get_on_the_root(
    preview_client: TestClient, seed: Seeder, world: World
) -> None:
    response = _create(preview_client, world.operator_a, _web_body(seed, world, ("/shop",)))

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "PROFILE_INCOMPATIBLE"
    assert "GET /" in error["message"]


def test_zap_on_the_web_profile_starts_from_an_allowed_root(
    preview_client: TestClient, seed: Seeder, world: World
) -> None:
    response = _create(preview_client, world.operator_a, _web_body(seed, world, ("/", "/shop")))

    assert response.status_code == 202


def test_the_seed_rule_only_applies_to_zap(
    preview_client: TestClient, seed: Seeder, world: World
) -> None:
    body = {**_web_body(seed, world, ("/shop",)), "engines": ["fake"]}

    assert _create(preview_client, world.operator_a, body).status_code == 202


def test_scanners_report_zap_from_the_runner_probe_under_the_preview_switch(
    preview_client: TestClient, world: World
) -> None:
    response = preview_client.get("/api/v1/scanners", headers=world.viewer_a.headers)

    assert response.status_code == 200
    [zap] = [item for item in response.json()["data"]["engines"] if item["engine"] == "zap"]
    assert zap["integrated"] is False
    assert zap["available"] is False
    assert zap["unavailable_reason"] in {"RUNNER_UNAVAILABLE", "ENGINE_PROBE_PENDING"}
    assert "version" in zap
