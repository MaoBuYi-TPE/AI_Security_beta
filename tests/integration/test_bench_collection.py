"""harness 經真的 API 收集（BENCH-04 的 integration；docs/DECISIONS.md §29）。

和 Live 走同一段程式（benchmarks.collect）：只是 fetch 換成 TestClient。建立有子預算的 zap 與 nuclei
scan，經佇列寫入觀察並連結 finding，再以 API 收集、建立比較快照。
"""

from collections.abc import Iterator, Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from benchmarks.collect import (
    CollectError,
    collect_comparison,
    collect_scan,
    normalize_comparison,
    normalize_scan,
)
from benchmarks.models import EngineCap
from secscan.findings.service import FindingLinker
from secscan.main import create_app
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunStatus
from secscan.scans.domain.observation import ObservationInput
from secscan.scans.queue import ScanQueue
from tests.integration.api_support import LAB, Caller, Seeder, World
from tests.integration.database import ProvisionedDatabase
from tests.integration.finding_support import (
    NUCLEI_XCTO,
    ZAP_SQLI,
    ZAP_XCTO,
    parsed_run,
    web_target,
)

pytestmark = pytest.mark.integration

API = "/api/v1"
SPLIT = [
    {"engine": "zap", "max_requests": 760, "max_duration_seconds": 380},
    {"engine": "nuclei", "max_requests": 440, "max_duration_seconds": 220},
]


@pytest.fixture
def client(queue_database: ProvisionedDatabase) -> Iterator[TestClient]:
    with TestClient(create_app(queue_database.app_settings())) as opened:
        yield opened


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


def _fetch(client: TestClient, caller: Caller) -> Any:
    def fetch(path: str) -> Mapping[str, Any]:
        response = client.get(API + path, headers=caller.headers)
        assert response.status_code == 200, response.text
        body: Mapping[str, Any] = response.json()
        return body

    return fetch


def _scan(
    client: TestClient,
    engine: Engine,
    world: World,
    target_grant: tuple[Any, UUID],
    observations: Mapping[ScanEngine, tuple[ObservationInput, ...]],
) -> str:
    target, grant_id = target_grant
    body = {
        "target_id": str(target.id),
        "scope_grant_id": str(grant_id),
        "profile": "web_active_lab",
        "engines": ["zap", "nuclei"],
        "budget": {"requests_per_second": 2, "max_requests": 1_200, "max_duration_seconds": 600},
        "engine_budgets": SPLIT,
    }
    headers = {**world.operator_a.headers, "Idempotency-Key": str(uuid4())}
    created = client.post(f"{API}/scans", json=body, headers=headers)
    assert created.status_code == 202, created.text
    sessions = sessionmaker(engine, expire_on_commit=False)
    queue = ScanQueue(sessions, lab=LAB, clock=lambda: datetime.now(UTC))
    for scanner in (ScanEngine.ZAP, ScanEngine.NUCLEI):
        lease = parsed_run(queue, scanner, observations[scanner])
        FindingLinker(sessions).link(lease)
        queue.advance(lease, RunStatus.SUCCEEDED)
    return str(created.json()["data"]["id"])


def test_a_scan_is_collected_through_the_api_with_caps_usage_and_sources(
    client: TestClient, queue_engine: Engine, queue_seed: Seeder, world: World
) -> None:
    target = web_target(queue_seed, world)
    scan_id = _scan(
        client,
        queue_engine,
        world,
        target,
        {ScanEngine.ZAP: (ZAP_SQLI, ZAP_XCTO), ScanEngine.NUCLEI: (NUCLEI_XCTO,)},
    )

    record = normalize_scan(*collect_scan(_fetch(client, world.viewer_a), scan_id))

    assert (record.status, record.fixture, record.observation_count) == ("completed", False, 3)
    zap, nuclei = record.runs
    assert (zap.cap, nuclei.cap) == (EngineCap(760, 380), EngineCap(440, 220))
    assert (zap.requests_allotted, zap.seconds_allotted, zap.requests_sent) == (760, 380, 1)
    assert (nuclei.requests_allotted, nuclei.seconds_allotted) == (440, 220)
    assert all(run.plan_hash is None and run.observation_count is not None for run in record.runs)
    by_engines = sorted(finding.engines for finding in record.findings)
    # 缺 header 的觀察在同一個 scan 同一個位置由 nuclei 佐證，併成一個 finding（§25.14）。
    assert by_engines == [("nuclei", "zap"), ("zap",)]
    assert sum(finding.observations for finding in record.findings) == 3


def test_a_comparison_is_created_and_collected_through_the_api(
    client: TestClient, queue_engine: Engine, queue_seed: Seeder, world: World
) -> None:
    target = web_target(queue_seed, world)
    baseline = _scan(
        client,
        queue_engine,
        world,
        target,
        {ScanEngine.ZAP: (ZAP_SQLI, ZAP_XCTO), ScanEngine.NUCLEI: (NUCLEI_XCTO,)},
    )
    current = _scan(
        client, queue_engine, world, target, {ScanEngine.ZAP: (ZAP_XCTO,), ScanEngine.NUCLEI: ()}
    )
    created = client.post(
        f"{API}/scan-comparisons",
        json={"baseline_scan_id": baseline, "current_scan_id": current},
        headers=world.operator_a.headers,
    )
    assert created.status_code == 201, created.text

    record = normalize_comparison(
        *collect_comparison(_fetch(client, world.viewer_a), created.json()["data"]["id"])
    )

    assert (record.baseline_scan_id, record.current_scan_id) == (baseline, current)
    classifications = sorted(item.classification for item in record.items)
    # 沒有完整覆蓋的證據：不推定 not_observed（T22）。
    assert "not_observed" not in classifications
    assert len(record.items) == 2


def test_a_fake_scan_cannot_be_collected_for_an_experiment(
    client: TestClient, queue_seed: Seeder, world: World
) -> None:
    scan = queue_seed.scan(world.operator_a, queue_seed.scannable(world))
    cancelled = client.post(f"{API}/scans/{scan.id}/cancel", headers=world.operator_a.headers)
    assert cancelled.status_code == 200, cancelled.text

    with pytest.raises(CollectError, match="fixture"):
        normalize_scan(*collect_scan(_fetch(client, world.viewer_a), str(scan.id)))
