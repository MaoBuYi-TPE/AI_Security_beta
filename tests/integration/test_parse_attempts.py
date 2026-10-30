"""解析重試的上限（docs/DECISIONS.md §17.6）。

- lease 過期的 normalizing：第 1、2 次退回 collected，第 3 次 failed（PARSE_ATTEMPTS_EXHAUSTED）。
  嘗試次數 = 這個 run 轉到 normalizing 的 run.status 事件數（不需要另外的欄位）。
- worker 遇到單一 run 的非預期例外：只記 run_id 與例外的類別，繼續處理其他 run；DB 的錯誤照舊
  讓程序結束。
每個測試用自己的資料庫（queue_database）。
"""

import logging
from datetime import UTC, datetime
from uuid import UUID

import pytest
from sqlalchemy import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from secscan.runner.fake import FakeRunner
from secscan.scanners.domain.fake import FakeScript
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import MAX_PARSE_ATTEMPTS, RunStatus
from secscan.scans.domain.model import Lease
from secscan.scans.queue import CoverageInputs, ScanQueue
from secscan.worker.service import Worker
from tests.integration.api_support import LAB, Seeder, World

pytestmark = pytest.mark.integration

OWNER = "worker-attempts-1"
FAKE = frozenset({ScanEngine.FAKE})
CANARY = "canary-tool-output-0001"


@pytest.fixture
def queue(queue_engine: Engine) -> ScanQueue:
    return ScanQueue(
        sessionmaker(queue_engine, expire_on_commit=False), lab=LAB, clock=lambda: datetime.now(UTC)
    )


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


def _collected(queue: ScanQueue, seed: Seeder, world: World) -> Lease:
    seed.scan(world.operator_a, seed.scannable(world))
    lease = queue.claim(OWNER, FAKE)
    assert lease is not None
    queue.prepare(lease)
    queue.advance(lease, RunStatus.COLLECTING)
    queue.advance(lease, RunStatus.COLLECTED)
    return lease


def _expire(seed: Seeder, run_id: UUID) -> None:
    seed.execute(
        "UPDATE scanner_runs SET lease_expires_at = now() - interval '1 second' WHERE id = :id",
        id=run_id,
    )


def _status(seed: Seeder, run_id: UUID) -> tuple[str, str | None]:
    [row] = seed.query("SELECT status, error_code FROM scanner_runs WHERE id = :id", id=run_id)
    return row.status, row.error_code


def _crash_while_parsing(queue: ScanQueue, seed: Seeder, run_id: UUID) -> None:
    """worker 認領之後中斷：lease 過期，由對帳處理。"""
    parsing = queue.claim_collected(OWNER, FAKE, run_id=run_id)
    assert parsing is not None
    _expire(seed, run_id)
    assert queue.reconcile_expired_parsing(FAKE) == 1


def test_the_third_lost_attempt_fails_the_run(
    queue: ScanQueue, queue_seed: Seeder, world: World
) -> None:
    lease = _collected(queue, queue_seed, world)
    assert MAX_PARSE_ATTEMPTS == 3

    _crash_while_parsing(queue, queue_seed, lease.run_id)
    assert _status(queue_seed, lease.run_id) == ("collected", None)
    _crash_while_parsing(queue, queue_seed, lease.run_id)
    assert _status(queue_seed, lease.run_id) == ("collected", None)
    _crash_while_parsing(queue, queue_seed, lease.run_id)

    assert _status(queue_seed, lease.run_id) == ("failed", "PARSE_ATTEMPTS_EXHAUSTED")
    assert queue.claim_collected(OWNER, FAKE) is None


def test_attempts_are_counted_per_run(queue: ScanQueue, queue_seed: Seeder, world: World) -> None:
    first = _collected(queue, queue_seed, world)
    second = _collected(queue, queue_seed, world)
    _crash_while_parsing(queue, queue_seed, first.run_id)
    _crash_while_parsing(queue, queue_seed, first.run_id)

    _crash_while_parsing(queue, queue_seed, second.run_id)

    assert _status(queue_seed, second.run_id) == ("collected", None)


def test_the_in_process_reconcile_applies_the_same_limit(
    queue: ScanQueue, queue_seed: Seeder, world: World
) -> None:
    lease = _collected(queue, queue_seed, world)
    for _ in range(MAX_PARSE_ATTEMPTS):
        assert queue.claim_collected(OWNER, FAKE, run_id=lease.run_id) is not None
        _expire(queue_seed, lease.run_id)
        FakeRunner(queue, owner=OWNER, script=FakeScript()).reconcile()

    assert _status(queue_seed, lease.run_id) == ("failed", "PARSE_ATTEMPTS_EXHAUSTED")


def test_the_worker_moves_on_after_an_unexpected_error(
    queue: ScanQueue, queue_seed: Seeder, world: World, caplog: pytest.LogCaptureFixture
) -> None:
    broken = _collected(queue, queue_seed, world)
    healthy = _collected(queue, queue_seed, world)
    coverage_inputs = queue.coverage_inputs

    def failing(lease: Lease) -> CoverageInputs:
        if lease.run_id == broken.run_id:
            raise ValueError(f"tool output: {CANARY}")
        return coverage_inputs(lease)

    queue.coverage_inputs = failing  # type: ignore[method-assign]

    with caplog.at_level(logging.WARNING, logger="secscan.worker.service"):
        reports = Worker(queue, owner=OWNER).drain()

    assert [report.run_id for report in reports] == [healthy.run_id]
    assert _status(queue_seed, broken.run_id) == ("normalizing", None)  # lease 過期之後重試
    [record] = [record for record in caplog.records if str(broken.run_id) in record.message]
    assert "ValueError" in record.message
    assert CANARY not in caplog.text


def test_a_database_error_still_stops_the_worker(
    queue: ScanQueue, queue_seed: Seeder, world: World
) -> None:
    _collected(queue, queue_seed, world)

    def unavailable(lease: Lease) -> CoverageInputs:
        raise OperationalError("SELECT 1", {}, Exception("connection lost"))

    queue.coverage_inputs = unavailable  # type: ignore[method-assign]

    with pytest.raises(OperationalError):
        Worker(queue, owner=OWNER).drain()
