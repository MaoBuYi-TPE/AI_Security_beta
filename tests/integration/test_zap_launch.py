"""zap 的 run 在 prepare 時拿到的輸入（docs/DECISIONS.md §18.6）：scan profile 與規格。

- api profile：上傳時正規化的文件、base path，以及 scan 建立時凍結為 eligible 的 operation
  （method 與含 base path 的 path）。過濾在 transaction 之外由 runner 進行。
- web profile、其他引擎：沒有規格。
每個測試用自己的資料庫（queue_database）。
"""

import json
from datetime import UTC, datetime

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.scanners.domain.zap.policy import ZAP_IMAGE
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.catalog import ScanProfile
from secscan.scans.domain.lifecycle import RunStatus
from secscan.scans.domain.model import Lease
from secscan.scans.domain.request import BudgetRequest, ScanRequest
from secscan.scans.queue import Launch, ScanQueue
from secscan.targets.domain import Target, TargetKind
from tests.integration.api_support import LAB, Seeder, World

pytestmark = pytest.mark.integration

OWNER = "runner-zap-launch"
ZAP = frozenset({ScanEngine.ZAP})
SPEC = json.dumps(
    {
        "openapi": "3.0.3",
        "info": {"title": "lab", "version": "1"},
        "servers": [{"url": "http://placeholder.invalid/api"}],
        "paths": {
            "/items": {"get": {"responses": {"200": {"description": "ok"}}}},
            "/items/{id}": {
                "get": {"responses": {"200": {"description": "ok"}}},
                "delete": {"responses": {"204": {"description": "gone"}}},
            },
        },
    }
).encode()


@pytest.fixture
def queue(queue_engine: Engine) -> ScanQueue:
    return ScanQueue(
        sessionmaker(queue_engine, expire_on_commit=False),
        lab=LAB,
        clock=lambda: datetime.now(UTC),
    )


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


def _request(
    target: Target, grant_id: object, spec_id: object, profile: ScanProfile
) -> ScanRequest:
    return ScanRequest(
        target_id=target.id,
        scope_grant_id=grant_id,  # type: ignore[arg-type]
        api_spec_id=spec_id,  # type: ignore[arg-type]
        auth_profile_id=None,
        profile=profile,
        engines=(ScanEngine.ZAP,),
        budget=BudgetRequest(),
    )


def _launched(queue: ScanQueue, engines: frozenset[ScanEngine] = ZAP) -> tuple[Lease, Launch]:
    lease = queue.claim(OWNER, engines)
    assert lease is not None
    launch = queue.prepare_launch(lease, image_ref=str(ZAP_IMAGE))
    assert launch.progress.run_status is RunStatus.RUNNING
    return lease, launch


def test_an_api_run_gets_the_stored_document_and_the_eligible_operations(
    queue: ScanQueue, queue_seed: Seeder, world: World
) -> None:
    target = queue_seed.target(world.operator_a, world.project_a.id)
    grant = queue_seed.approve(
        world.admin,
        queue_seed.grant(world.operator_a, target, paths=("/api/items", "/api/items/{id}")),
    )
    spec = queue_seed.spec(world.operator_a, target, content=SPEC)
    request = _request(target, grant.id, spec.id, ScanProfile.API_ACTIVE_LAB)
    queue_seed.create_scan(world.operator_a, request)

    _, launch = _launched(queue)

    assert launch.scan_profile is ScanProfile.API_ACTIVE_LAB
    assert launch.spec is not None
    assert launch.spec.base_path == "/api"
    # grant 只允許 GET：DELETE 在 scan 建立時就判斷為不在範圍內。
    assert launch.spec.eligible == frozenset({("GET", "/api/items"), ("GET", "/api/items/{id}")})
    document = json.loads(launch.spec.document)
    assert document["servers"] == [{"url": f"{target.origin}/api"}]
    assert set(document["paths"]) == {"/items", "/items/{id}"}


def test_a_web_run_has_no_spec(queue: ScanQueue, queue_seed: Seeder, world: World) -> None:
    target = queue_seed.target(world.operator_a, world.project_a.id, kind=TargetKind.WEB)
    grant = queue_seed.approve(
        world.admin, queue_seed.grant(world.operator_a, target, paths=("/",))
    )
    request = _request(target, grant.id, None, ScanProfile.WEB_ACTIVE_LAB)
    queue_seed.create_scan(world.operator_a, request)

    _, launch = _launched(queue)

    assert launch.scan_profile is ScanProfile.WEB_ACTIVE_LAB
    assert launch.spec is None


def test_other_engines_do_not_load_the_spec(
    queue: ScanQueue, queue_seed: Seeder, world: World
) -> None:
    queue_seed.scan(world.operator_a, queue_seed.scannable(world))

    _, launch = _launched(queue, frozenset({ScanEngine.FAKE}))

    assert launch.scan_profile is ScanProfile.API_ACTIVE_LAB
    assert launch.spec is None
