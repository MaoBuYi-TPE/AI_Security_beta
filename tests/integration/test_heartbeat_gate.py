"""心跳重新判斷 gate（docs/DECISIONS.md §17.5；SEC-01 後半）。

lease 有效、沒有要求取消時，心跳以不加鎖的讀取重新判斷 grant、target 與建立者的 key，回報停止的
原因：撤銷 grant、到期、停用 target、origin 改變、LAB_CIDR 不符、撤銷建立者的 key。
不加鎖：撤銷還沒 commit 時心跳不等待（也看不到它）；commit 之後下一次心跳就看得到。
每個測試用自己的資料庫（queue_database）。
"""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Network

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from secscan.api_keys.models import ApiKeyModel
from secscan.api_keys.service import ApiKeyService
from secscan.grants.models import ScopeGrantModel
from secscan.grants.service import ScopeGrantService
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunErrorCode
from secscan.scans.domain.model import Lease
from secscan.scans.queue import Heartbeat, QueueOperations, ScanQueue
from secscan.targets.domain import LabNetwork, TargetUpdate
from secscan.targets.models import TargetModel
from secscan.targets.service import TargetService
from tests.integration.api_support import LAB, Scannable, Seeder, World
from tests.integration.database import ProvisionedDatabase
from tests.integration.locks import Race

pytestmark = pytest.mark.integration

OWNER = "runner-heartbeat-1"
FAKE = frozenset({ScanEngine.FAKE})
RACER = "secscan-heartbeat-racer"


def _now() -> datetime:
    return datetime.now(UTC)


def _queue(
    engine: Engine, *, lab: LabNetwork = LAB, clock: Callable[[], datetime] = _now
) -> ScanQueue:
    return ScanQueue(sessionmaker(engine, expire_on_commit=False), lab=lab, clock=clock)


@pytest.fixture
def queue(queue_engine: Engine) -> ScanQueue:
    return _queue(queue_engine)


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


@pytest.fixture
def scannable(queue_seed: Seeder, world: World) -> Scannable:
    return queue_seed.scannable(world)


@pytest.fixture
def lease(queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable) -> Lease:
    """running 的 fake run（in-process 的 prepare）。"""
    queue_seed.scan(world.operator_a, scannable)
    lease = queue.claim(OWNER, FAKE)
    assert lease is not None
    queue.prepare(lease)
    return lease


def _revoke(engine: Engine, world: World, scannable: Scannable) -> None:
    with Session(engine, expire_on_commit=False) as session, session.begin():
        ScopeGrantService(session, lab=LAB).revoke(
            world.admin.principal, scannable.grant.id, reason="停止", now=_now(), request_id=None
        )


def _disable(engine: Engine, world: World, scannable: Scannable) -> None:
    with Session(engine, expire_on_commit=False) as session, session.begin():
        TargetService(session, lab=LAB).update(
            world.operator_a.principal,
            scannable.target.id,
            TargetUpdate(enabled=False),
            request_id=None,
        )


def _move_origin(engine: Engine, world: World, scannable: Scannable) -> None:
    Seeder(engine).execute(
        "UPDATE targets SET canonical_origin = 'http://elsewhere:5000' WHERE id = :id",
        id=scannable.target.id,
    )


def _revoke_creator(engine: Engine, world: World, scannable: Scannable) -> None:
    with Session(engine, expire_on_commit=False) as session, session.begin():
        ApiKeyService(session).revoke(
            world.admin.principal, world.operator_a.principal.key_id, request_id=None
        )


def test_a_valid_run_has_no_stop_reason(queue: ScanQueue, lease: Lease) -> None:
    assert queue.heartbeat(lease) == Heartbeat(valid=True, cancel_requested=False)


@pytest.mark.parametrize(
    ("change", "error_code"),
    [
        (_revoke, RunErrorCode.SCOPE_REVOKED),
        (_disable, RunErrorCode.TARGET_DISABLED),
        (_move_origin, RunErrorCode.SCOPE_MISMATCH),
        (_revoke_creator, RunErrorCode.CREATOR_KEY_REVOKED),
    ],
    ids=["revoked", "disabled", "moved", "creator-revoked"],
)
def test_the_heartbeat_reports_why_the_run_must_stop(
    queue: ScanQueue,
    queue_engine: Engine,
    lease: Lease,
    world: World,
    scannable: Scannable,
    change: Callable[[Engine, World, Scannable], None],
    error_code: RunErrorCode,
) -> None:
    change(queue_engine, world, scannable)

    assert queue.heartbeat(lease) == Heartbeat(
        valid=True, cancel_requested=False, stop_reason=error_code
    )


def test_an_expired_grant_stops_the_run(
    queue_engine: Engine, lease: Lease, scannable: Scannable
) -> None:
    late = _queue(queue_engine, clock=lambda: scannable.grant.window.valid_until)

    assert late.heartbeat(lease).stop_reason is RunErrorCode.SCOPE_EXPIRED


def test_ips_outside_the_current_lab_stop_the_run(queue_engine: Engine, lease: Lease) -> None:
    elsewhere = _queue(queue_engine, lab=LabNetwork(IPv4Network("10.99.0.0/24")))

    assert elsewhere.heartbeat(lease).stop_reason is RunErrorCode.SCOPE_OUTSIDE_LAB


def test_a_cancel_is_reported_instead_of_the_gate(
    queue: ScanQueue,
    queue_engine: Engine,
    queue_seed: Seeder,
    lease: Lease,
    world: World,
    scannable: Scannable,
) -> None:
    """取消優先：要求取消的 scan 走取消的路徑（§17.5 的順序）。"""
    _revoke(queue_engine, world, scannable)
    queue_seed.execute(
        "UPDATE scans SET cancel_requested_at = now() WHERE id = :id", id=lease.scan_id
    )

    assert queue.heartbeat(lease) == Heartbeat(valid=True, cancel_requested=True)


def test_an_invalid_lease_has_no_stop_reason(
    queue: ScanQueue,
    queue_engine: Engine,
    queue_seed: Seeder,
    lease: Lease,
    world: World,
    scannable: Scannable,
) -> None:
    _revoke_creator(queue_engine, world, scannable)
    queue_seed.execute(
        "UPDATE scanner_runs SET lease_expires_at = now() - interval '1 second' WHERE id = :id",
        id=lease.run_id,
    )

    assert queue.heartbeat(lease) == Heartbeat(valid=False, cancel_requested=False)


def test_the_heartbeat_does_not_wait_for_a_pending_revocation(
    queue: ScanQueue,
    queue_engine: Engine,
    queue_database: ProvisionedDatabase,
    lease: Lease,
    world: World,
    scannable: Scannable,
) -> None:
    """撤銷持有 grant 的 FOR UPDATE 還沒 commit：心跳不等它，commit 之後的心跳就看得到。"""

    def beat(session: Session) -> Heartbeat:
        return QueueOperations(session, lab=LAB).heartbeat(lease, clock=_now)

    with Session(queue_engine, expire_on_commit=False) as holder, holder.begin():
        ScopeGrantService(holder, lab=LAB).revoke(
            world.admin.principal, scannable.grant.id, reason="停止", now=_now(), request_id=None
        )
        race = Race(queue_database, RACER, beat)
        race.start()
        race.join()

    assert race.errors == []
    assert race.results == [Heartbeat(valid=True, cancel_requested=False)]
    assert queue.heartbeat(lease).stop_reason is RunErrorCode.SCOPE_REVOKED


def test_the_heartbeat_reads_fresh_values_in_a_shared_session(
    queue_engine: Engine, lease: Lease, world: World, scannable: Scannable
) -> None:
    """呼叫端的 session 持有已載入的 grant、target 與 key（identity map 中的舊值）：撤銷之後
    心跳仍讀到新的值。identity map 是弱參照，沒有持有時不會重用舊的物件，所以這裡刻意持有。
    """
    with Session(queue_engine, expire_on_commit=False) as session:
        with session.begin():
            held = (
                session.get(ScopeGrantModel, scannable.grant.id),
                session.get(TargetModel, scannable.target.id),
                session.get(ApiKeyModel, world.operator_a.principal.key_id),
            )
            operations = QueueOperations(session, lab=LAB)
            assert operations.heartbeat(lease, clock=_now).stop_reason is None
        _revoke(queue_engine, world, scannable)
        _revoke_creator(queue_engine, world, scannable)
        with session.begin():
            later = operations.heartbeat(lease, clock=lambda: _now() + timedelta(seconds=1))
            assert all(model is not None for model in held)

    assert later.stop_reason is RunErrorCode.SCOPE_REVOKED


def test_the_heartbeat_reads_a_fresh_creator_key_in_a_shared_session(
    queue_engine: Engine, lease: Lease, world: World, scannable: Scannable
) -> None:
    with Session(queue_engine, expire_on_commit=False) as session:
        with session.begin():
            held = session.get(ApiKeyModel, world.operator_a.principal.key_id)
            operations = QueueOperations(session, lab=LAB)
            assert operations.heartbeat(lease, clock=_now).stop_reason is None
        _revoke_creator(queue_engine, world, scannable)
        with session.begin():
            later = operations.heartbeat(lease, clock=_now)
            assert held is not None

    assert later.stop_reason is RunErrorCode.CREATOR_KEY_REVOKED


def test_the_heartbeat_reads_a_fresh_target_in_a_shared_session(
    queue_engine: Engine, lease: Lease, world: World, scannable: Scannable
) -> None:
    with Session(queue_engine, expire_on_commit=False) as session:
        with session.begin():
            held = session.get(TargetModel, scannable.target.id)
            operations = QueueOperations(session, lab=LAB)
            assert operations.heartbeat(lease, clock=_now).stop_reason is None
        _disable(queue_engine, world, scannable)
        with session.begin():
            later = operations.heartbeat(lease, clock=_now)
            assert held is not None

    assert later.stop_reason is RunErrorCode.TARGET_DISABLED
