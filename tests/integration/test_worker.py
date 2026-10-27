"""worker（docs/DECISIONS.md §14.6）：T10 只把 fake 的 collected 標成 succeeded，不讀任何檔案。

每個測試用自己的資料庫（queue_database）。
"""

from datetime import UTC, datetime

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunStatus, ScanStatus
from secscan.scans.domain.model import Lease
from secscan.scans.queue import RunReport, ScanQueue
from secscan.worker.service import Worker
from tests.integration.api_support import LAB, Seeder, World

pytestmark = pytest.mark.integration

FAKE = frozenset({ScanEngine.FAKE})
IMAGE = "busybox:1.38.0@sha256:" + "ab" * 32


def _now() -> datetime:
    return datetime.now(UTC)


@pytest.fixture
def queue(queue_engine: Engine) -> ScanQueue:
    return ScanQueue(sessionmaker(queue_engine, expire_on_commit=False), lab=LAB, clock=_now)


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


def _collected(queue: ScanQueue, seed: Seeder, world: World) -> Lease:
    seed.scan(world.operator_a, seed.scannable(world))
    lease = queue.claim("runner-1", FAKE)
    assert lease is not None
    queue.prepare_launch(lease, image_ref=IMAGE)
    queue.advance(lease, RunStatus.COLLECTING)
    queue.advance(lease, RunStatus.COLLECTED)
    return lease


def test_the_worker_completes_collected_fake_runs(
    queue: ScanQueue, queue_seed: Seeder, world: World
) -> None:
    first = _collected(queue, queue_seed, world)
    second = _collected(queue, queue_seed, world)
    seen: list[RunReport] = []

    reports = Worker(queue, owner="worker-1").drain(on_report=seen.append)

    assert {report.run_id for report in reports} == {first.run_id, second.run_id}
    assert all(report.run_status is RunStatus.SUCCEEDED for report in reports)
    assert all(report.scan_status is ScanStatus.COMPLETED for report in reports)
    assert seen == reports


def test_the_worker_stops_at_the_limit(queue: ScanQueue, queue_seed: Seeder, world: World) -> None:
    _collected(queue, queue_seed, world)
    _collected(queue, queue_seed, world)

    assert len(Worker(queue, owner="worker-1").drain(limit=1)) == 1
    assert len(Worker(queue, owner="worker-1").drain()) == 1
    assert Worker(queue, owner="worker-1").drain() == []


def test_the_worker_retries_expired_parsing(
    queue: ScanQueue, queue_seed: Seeder, world: World
) -> None:
    lease = _collected(queue, queue_seed, world)
    parsing = queue.claim_collected("crashed-worker", FAKE)
    assert parsing is not None
    queue_seed.execute(
        "UPDATE scanner_runs SET lease_expires_at = now() - interval '1 second' WHERE id = :id",
        id=lease.run_id,
    )

    [report] = Worker(queue, owner="worker-1").drain()

    assert (report.run_id, report.run_status) == (lease.run_id, RunStatus.SUCCEEDED)


def test_the_worker_ignores_engines_it_cannot_parse(
    queue: ScanQueue, queue_seed: Seeder, world: World
) -> None:
    _collected(queue, queue_seed, world)

    assert Worker(queue, owner="worker-1", engines=frozenset({ScanEngine.ZAP})).drain() == []
