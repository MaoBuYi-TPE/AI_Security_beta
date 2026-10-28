"""runner 與 worker 的心跳（docs/DECISIONS.md §14.7）：每個程序一列，30 秒內有心跳才算存活。

每個測試用自己的資料庫（queue_database）：存活的判斷看的是整張表。
"""

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.scanners.domain.instances import (
    Capabilities,
    CapabilityIssue,
    EngineCapability,
    InstanceRole,
)
from secscan.scanners.service import Fleet, ScannerCatalog, ScannerOverview
from secscan.scans.domain.catalog import Engine as ScanEngine
from tests.integration.api_support import Seeder

pytestmark = pytest.mark.integration

IMAGE = "busybox:1.38.0@sha256:" + "ab" * 32
READY = Capabilities(engines=(EngineCapability(ScanEngine.FAKE, IMAGE, None),))
BROKEN = Capabilities(
    engines=(EngineCapability(ScanEngine.FAKE, IMAGE, CapabilityIssue.IMAGE_MISSING),)
)


def _fleet(engine: Engine, owner: str, role: InstanceRole = InstanceRole.RUNNER) -> Fleet:
    return Fleet(
        sessionmaker(engine, expire_on_commit=False),
        owner=owner,
        role=role,
        software_version="0.1.0",
    )


def _describe(engine: Engine) -> ScannerOverview:
    with sessionmaker(engine, expire_on_commit=False).begin() as session:
        return ScannerCatalog(session).describe()


def test_a_beat_keeps_one_row_per_owner(queue_engine: Engine, queue_seed: Seeder) -> None:
    fleet = _fleet(queue_engine, "runner:a")

    fleet.beat(BROKEN)
    first = queue_seed.query("SELECT heartbeat_at FROM runner_instances")[0].heartbeat_at
    fleet.beat(READY)

    [row] = queue_seed.query(
        "SELECT role, software_version, capabilities, heartbeat_at FROM runner_instances"
    )
    assert (row.role, row.software_version) == ("runner", "0.1.0")
    assert row.capabilities == {"engines": {"fake": {"image": IMAGE, "issue": None}}}
    assert row.heartbeat_at >= first


def test_the_catalog_reads_the_latest_live_runner(queue_engine: Engine, queue_seed: Seeder) -> None:
    _fleet(queue_engine, "runner:old").beat(BROKEN)
    _fleet(queue_engine, "runner:new").beat(READY)

    overview = _describe(queue_engine)

    assert overview.runner.alive
    fake = next(status for status in overview.engines if status.engine is ScanEngine.FAKE)
    assert (fake.available, fake.image) == (True, IMAGE)


def test_a_silent_runner_is_not_alive(queue_engine: Engine, queue_seed: Seeder) -> None:
    _fleet(queue_engine, "runner:a").beat(READY)
    queue_seed.execute(
        "UPDATE runner_instances SET created_at = now() - interval '1 hour', "
        "heartbeat_at = now() - interval '31 seconds'"
    )

    overview = _describe(queue_engine)

    assert not overview.runner.alive
    assert overview.runner.last_heartbeat_at is not None
    fake = next(status for status in overview.engines if status.engine is ScanEngine.FAKE)
    assert (fake.available, fake.unavailable_reason) == (False, "RUNNER_UNAVAILABLE")


def test_workers_are_reported_separately(queue_engine: Engine) -> None:
    _fleet(queue_engine, "worker:a", InstanceRole.WORKER).beat(Capabilities(engines=()))

    overview = _describe(queue_engine)

    assert overview.worker.alive
    assert not overview.runner.alive
    assert overview.runner.last_heartbeat_at is None


def test_pruning_removes_rows_silent_for_a_week(queue_engine: Engine, queue_seed: Seeder) -> None:
    _fleet(queue_engine, "runner:gone").beat(READY)
    queue_seed.execute(
        "UPDATE runner_instances SET created_at = now() - interval '8 days', "
        "heartbeat_at = now() - interval '8 days'"
    )
    fleet = _fleet(queue_engine, "runner:now")
    fleet.beat(READY)

    assert fleet.prune() == 1
    assert [row.owner for row in queue_seed.query("SELECT owner FROM runner_instances")] == [
        "runner:now"
    ]
