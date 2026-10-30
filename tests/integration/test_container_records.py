"""容器的紀錄：runner 記下刪除、對帳找待處理的容器並結算（docs/DECISIONS.md §17.2、§17.4）。

- 待處理：記下容器、還沒確認刪除，而且不是「runner 階段且 lease 還有效」。
- 結算：仍在 runner 階段（lease 已過期）→ interrupted（LEASE_EXPIRED）、用量留空；其他狀態只記下
  刪除的時間。條件已經改變（別人先結算）就不動。
- 沒有容器、或容器已確認刪除的 runner 階段 run：lease 過期就 interrupted，不必呼叫 Docker。
每個測試用自己的資料庫（queue_database）。
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine, Row
from sqlalchemy.orm import Session, sessionmaker

from secscan.scans.containers import ContainerRecords
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus, ScanStatus
from secscan.scans.domain.model import Lease
from secscan.scans.queue import Heartbeat, LeaseLostError, QueueOperations, RunUsage, ScanQueue
from secscan.scans.run_records import RunRecords
from secscan.scans.service import ScanService
from tests.integration.api_support import LAB, Seeder, World
from tests.integration.database import ProvisionedDatabase
from tests.integration.locks import Race, wait_until_waiting_for_a_lock

pytestmark = pytest.mark.integration

OWNER = "runner-records-1"
FAKE = frozenset({ScanEngine.FAKE})
IMAGE = "busybox:1.38.0@sha256:" + "ab" * 32
USAGE = RunUsage(requests_sent=3, requests_denied=0, traffic_seconds=2)
RACER = "secscan-settle-racer"
R = RunStatus
S = ScanStatus


@pytest.fixture
def queue(queue_engine: Engine) -> ScanQueue:
    return ScanQueue(
        sessionmaker(queue_engine, expire_on_commit=False), lab=LAB, clock=lambda: datetime.now(UTC)
    )


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


def _claim(queue: ScanQueue, seed: Seeder, world: World) -> Lease:
    """新的 target 與 scan，認領它唯一的 fake run（preparing）。"""
    seed.scan(world.operator_a, seed.scannable(world))
    lease = queue.claim(OWNER, FAKE)
    assert lease is not None
    return lease


def _launched(queue: ScanQueue, seed: Seeder, world: World) -> Lease:
    """running、記下了容器。"""
    lease = _claim(queue, seed, world)
    assert queue.prepare_launch(lease, image_ref=IMAGE).progress.run_status is R.RUNNING
    return lease


def _expire(seed: Seeder, run_id: UUID) -> None:
    seed.execute(
        "UPDATE scanner_runs SET lease_expires_at = now() - interval '1 second' WHERE id = :id",
        id=run_id,
    )


def _run(seed: Seeder, run_id: UUID) -> Row[Any]:
    [row] = seed.query(
        "SELECT r.status, r.error_code, r.lease_owner, r.container_removed_at, r.requests_sent, "
        "s.status AS scan_status FROM scanner_runs r JOIN scans s ON s.id = r.scan_id "
        "WHERE r.id = :id",
        id=run_id,
    )
    return row


def _events(seed: Seeder, run_id: UUID) -> list[tuple[str, str | None]]:
    rows = seed.query(
        "SELECT payload->>'status' AS status, payload->>'error_code' AS error_code "
        "FROM scan_events WHERE scanner_run_id = :id ORDER BY sequence",
        id=run_id,
    )
    return [(row.status, row.error_code) for row in rows]


# --- runner 記下刪除 ---------------------------------------------------------------------------


def test_the_runner_records_a_confirmed_removal_with_the_usage(
    queue: ScanQueue, queue_seed: Seeder, world: World
) -> None:
    lease = _launched(queue, queue_seed, world)

    queue.record_usage(lease, USAGE, container_removed=True)
    first = _run(queue_seed, lease.run_id).container_removed_at
    queue.record_usage(lease, USAGE, container_removed=True)

    assert first is not None
    assert _run(queue_seed, lease.run_id).container_removed_at == first


def test_an_unconfirmed_removal_is_not_recorded(
    queue: ScanQueue, queue_seed: Seeder, world: World
) -> None:
    lease = _launched(queue, queue_seed, world)

    queue.record_usage(lease, USAGE, container_removed=False)

    run = _run(queue_seed, lease.run_id)
    assert (run.requests_sent, run.container_removed_at) == (3, None)


def test_a_lost_lease_records_nothing(queue: ScanQueue, queue_seed: Seeder, world: World) -> None:
    lease = _launched(queue, queue_seed, world)
    _expire(queue_seed, lease.run_id)

    with pytest.raises(LeaseLostError):
        queue.record_usage(lease, USAGE, container_removed=True)

    assert _run(queue_seed, lease.run_id).container_removed_at is None


# --- 待處理 ------------------------------------------------------------------------------------


def test_pending_lists_containers_that_are_not_confirmed_removed(
    queue: ScanQueue, queue_seed: Seeder, world: World
) -> None:
    alive = _launched(queue, queue_seed, world)
    expired = _launched(queue, queue_seed, world)
    _expire(queue_seed, expired.run_id)
    collected = _launched(queue, queue_seed, world)
    queue.advance(collected, R.COLLECTING)
    queue.advance(collected, R.COLLECTED)
    failed = _launched(queue, queue_seed, world)
    queue.advance(failed, R.FAILED, error_code=RunErrorCode.ENGINE_FAILED)
    removed = _launched(queue, queue_seed, world)
    queue.record_usage(removed, USAGE, container_removed=True)
    _expire(queue_seed, removed.run_id)
    in_process = _claim(queue, queue_seed, world)
    queue.prepare(in_process)
    _expire(queue_seed, in_process.run_id)

    pending = queue.pending_containers(limit=20)

    assert [item.run_id for item in pending] == [expired.run_id, collected.run_id, failed.run_id]
    assert pending[0].name == f"secscan-run-{expired.run_id}"
    assert pending[0].scan_id == expired.scan_id
    assert alive.run_id not in {item.run_id for item in pending}


def test_pending_is_bounded_and_oldest_first(
    queue: ScanQueue, queue_seed: Seeder, world: World
) -> None:
    leases = [_launched(queue, queue_seed, world) for _ in range(3)]
    for lease in leases:
        _expire(queue_seed, lease.run_id)

    pending = queue.pending_containers(limit=2)

    assert [item.run_id for item in pending] == [lease.run_id for lease in leases[:2]]


# --- 結算 --------------------------------------------------------------------------------------


def test_settling_an_expired_run_interrupts_it(
    queue: ScanQueue, queue_seed: Seeder, world: World
) -> None:
    lease = _launched(queue, queue_seed, world)
    _expire(queue_seed, lease.run_id)

    assert queue.settle_container(lease.run_id) is True

    run = _run(queue_seed, lease.run_id)
    assert (run.status, run.error_code, run.lease_owner) == ("interrupted", "LEASE_EXPIRED", None)
    assert run.container_removed_at is not None
    assert run.requests_sent is None  # 用量不明：之後的 run 以分到的數量扣除
    assert run.scan_status == S.INTERRUPTED.value
    assert _events(queue_seed, lease.run_id)[-1] == ("interrupted", "LEASE_EXPIRED")


def test_a_cancelled_scan_whose_runner_is_lost_is_interrupted(
    queue: ScanQueue, queue_seed: Seeder, world: World
) -> None:
    """要求過取消也一樣：runner 遺失時無法證明 10 秒內停止了新的出站（§17.2）。"""
    lease = _launched(queue, queue_seed, world)
    queue_seed.execute(
        "UPDATE scans SET cancel_requested_at = now() WHERE id = :id",
        id=lease.scan_id,
    )
    queue.advance(lease, R.CANCELLING)
    _expire(queue_seed, lease.run_id)

    assert queue.settle_container(lease.run_id) is True

    run = _run(queue_seed, lease.run_id)
    assert (run.status, run.scan_status) == ("interrupted", S.INTERRUPTED.value)


def test_settling_a_finished_run_only_records_the_removal(
    queue: ScanQueue, queue_seed: Seeder, world: World
) -> None:
    lease = _launched(queue, queue_seed, world)
    queue.advance(lease, R.COLLECTING)
    queue.advance(lease, R.COLLECTED)
    failed = _launched(queue, queue_seed, world)
    queue.advance(failed, R.FAILED, error_code=RunErrorCode.ENGINE_FAILED)

    assert queue.settle_container(lease.run_id) is True
    assert queue.settle_container(failed.run_id) is True

    collected, finished = _run(queue_seed, lease.run_id), _run(queue_seed, failed.run_id)
    assert (collected.status, finished.status) == ("collected", "failed")
    assert collected.container_removed_at is not None
    assert finished.container_removed_at is not None
    assert _events(queue_seed, lease.run_id)[-1] == ("collected", None)


def test_a_run_is_settled_only_once(queue: ScanQueue, queue_seed: Seeder, world: World) -> None:
    lease = _launched(queue, queue_seed, world)
    _expire(queue_seed, lease.run_id)

    assert queue.settle_container(lease.run_id) is True
    assert queue.settle_container(lease.run_id) is False

    assert _events(queue_seed, lease.run_id).count(("interrupted", "LEASE_EXPIRED")) == 1


def test_a_live_lease_is_not_settled(queue: ScanQueue, queue_seed: Seeder, world: World) -> None:
    lease = _launched(queue, queue_seed, world)

    assert queue.settle_container(lease.run_id) is False
    assert queue.settle_container(uuid4()) is False

    run = _run(queue_seed, lease.run_id)
    assert (run.status, run.container_removed_at) == ("running", None)


def test_the_owner_cannot_resume_after_settlement(
    queue: ScanQueue, queue_seed: Seeder, world: World
) -> None:
    lease = _launched(queue, queue_seed, world)
    _expire(queue_seed, lease.run_id)
    queue.settle_container(lease.run_id)

    assert queue.heartbeat(lease).valid is False
    with pytest.raises(LeaseLostError):
        queue.advance(lease, R.COLLECTING)
    with pytest.raises(LeaseLostError):
        queue.record_usage(lease, USAGE, container_removed=True)


# --- 沒有容器、或容器已確認刪除 ---------------------------------------------------------------


def test_runs_without_a_live_container_are_interrupted_without_docker(
    queue: ScanQueue, queue_seed: Seeder, world: World
) -> None:
    removed = _launched(queue, queue_seed, world)
    queue.record_usage(removed, USAGE, container_removed=True)
    queue.advance(removed, R.COLLECTING)
    _expire(queue_seed, removed.run_id)
    preparing = _claim(queue, queue_seed, world)
    _expire(queue_seed, preparing.run_id)
    live = _launched(queue, queue_seed, world)
    _expire(queue_seed, live.run_id)

    assert queue.reconcile_expired_runner(FAKE) == 2

    assert _run(queue_seed, removed.run_id).status == "interrupted"
    assert _run(queue_seed, preparing.run_id).error_code == "LEASE_EXPIRED"
    assert _run(queue_seed, live.run_id).status == "running"  # 容器可能還在執行：留給對帳


def test_the_runner_reconcile_leaves_parsing_to_the_worker(
    queue: ScanQueue, queue_seed: Seeder, world: World
) -> None:
    lease = _launched(queue, queue_seed, world)
    queue.record_usage(lease, USAGE, container_removed=True)
    queue.advance(lease, R.COLLECTING)
    queue.advance(lease, R.COLLECTED)
    parsing = queue.claim_collected(OWNER, FAKE)
    assert parsing is not None
    _expire(queue_seed, parsing.run_id)

    assert queue.reconcile_expired_runner(FAKE) == 0
    assert _run(queue_seed, parsing.run_id).status == "normalizing"


def test_the_in_process_reconcile_also_covers_removed_containers(
    queue: ScanQueue, queue_seed: Seeder, world: World
) -> None:
    lease = _launched(queue, queue_seed, world)
    queue.record_usage(lease, USAGE, container_removed=True)
    _expire(queue_seed, lease.run_id)

    assert queue.reconcile_expired(FAKE) == 1
    assert _run(queue_seed, lease.run_id).status == "interrupted"


# --- 啟動時的清理 ------------------------------------------------------------------------------


def test_unsettled_runs_are_the_ones_still_in_use(
    queue: ScanQueue, queue_seed: Seeder, world: World
) -> None:
    pending = _launched(queue, queue_seed, world)
    _expire(queue_seed, pending.run_id)
    leased = _claim(queue, queue_seed, world)
    settled = _launched(queue, queue_seed, world)
    queue.record_usage(settled, USAGE, container_removed=True)
    queue.advance(settled, R.FAILED, error_code=RunErrorCode.ENGINE_FAILED)
    unknown = uuid4()

    unsettled = queue.unsettled_runs({pending.run_id, leased.run_id, settled.run_id, unknown})

    assert unsettled == {pending.run_id, leased.run_id}
    assert queue.unsettled_runs(set()) == frozenset()


# --- 並行（以獨立連線在背景執行，pg_stat_activity 確認它在等列鎖） ----------------------------


def _settling(
    queue_engine: Engine, run_id: UUID, queue_seed: Seeder, racer: Race[Any], *, waits: bool
) -> None:
    """持有結算的 transaction（scan 與 run 都鎖住、還沒 commit）時讓對手開始。

    waits：對手要等鎖（確認它在等）；否則它在結算 commit 之前就結束。
    """
    with Session(queue_engine, expire_on_commit=False) as holder, holder.begin():
        assert ContainerRecords(holder).settle(run_id) is True
        racer.start()
        if waits:
            wait_until_waiting_for_a_lock(queue_seed, RACER)
        else:
            racer.join()
    racer.join()


def test_two_reconcilers_racing_settle_once(
    queue: ScanQueue,
    queue_engine: Engine,
    queue_database: ProvisionedDatabase,
    queue_seed: Seeder,
    world: World,
) -> None:
    lease = _launched(queue, queue_seed, world)
    _expire(queue_seed, lease.run_id)
    racer = Race(
        queue_database, RACER, lambda session: ContainerRecords(session).settle(lease.run_id)
    )

    _settling(queue_engine, lease.run_id, queue_seed, racer, waits=True)

    assert (racer.errors, racer.results) == ([], [False])
    assert _events(queue_seed, lease.run_id).count(("interrupted", "LEASE_EXPIRED")) == 1


def test_a_frozen_owner_waking_during_settlement_loses_its_lease(
    queue: ScanQueue,
    queue_engine: Engine,
    queue_database: ProvisionedDatabase,
    queue_seed: Seeder,
    world: World,
) -> None:
    """結算還沒 commit 時 owner 醒來心跳：lease 已過期，條件在舊的資料上就不成立，不必等鎖就失效
    （過期的 lease 不能延長），之後也不能再寫入。"""
    lease = _launched(queue, queue_seed, world)
    _expire(queue_seed, lease.run_id)

    def beat(session: Session) -> Heartbeat:
        return QueueOperations(session, lab=LAB).heartbeat(lease, clock=lambda: datetime.now(UTC))

    racer = Race(queue_database, RACER, beat)

    _settling(queue_engine, lease.run_id, queue_seed, racer, waits=False)

    assert (racer.errors, racer.results) == ([], [Heartbeat(valid=False, cancel_requested=False)])
    assert _run(queue_seed, lease.run_id).status == "interrupted"


def test_a_frozen_owner_cannot_record_usage_during_settlement(
    queue: ScanQueue,
    queue_engine: Engine,
    queue_database: ProvisionedDatabase,
    queue_seed: Seeder,
    world: World,
) -> None:
    lease = _launched(queue, queue_seed, world)
    _expire(queue_seed, lease.run_id)

    def record(session: Session) -> None:
        RunRecords(session).record_usage(lease, USAGE, container_removed=True)

    racer = Race(queue_database, RACER, record)

    _settling(queue_engine, lease.run_id, queue_seed, racer, waits=False)

    assert [type(error) for error in racer.errors] == [LeaseLostError]
    assert _run(queue_seed, lease.run_id).requests_sent is None


def test_a_cancel_during_settlement_sees_the_interrupted_scan(
    queue: ScanQueue,
    queue_engine: Engine,
    queue_database: ProvisionedDatabase,
    queue_seed: Seeder,
    world: World,
) -> None:
    """取消等 scan 的鎖；結算 commit 之後 scan 已終止，取消不改變任何東西。"""
    lease = _launched(queue, queue_seed, world)
    _expire(queue_seed, lease.run_id)

    def cancel(session: Session) -> ScanStatus:
        scan = ScanService(session, lab=LAB).cancel(
            world.operator_a.principal, lease.scan_id, request_id=None
        )
        return scan.status

    racer = Race(queue_database, RACER, cancel)

    _settling(queue_engine, lease.run_id, queue_seed, racer, waits=True)

    assert (racer.errors, racer.results) == ([], [S.INTERRUPTED])
    [row] = queue_seed.query(
        "SELECT cancel_requested_at FROM scans WHERE id = :id", id=lease.scan_id
    )
    assert row.cancel_requested_at is None
