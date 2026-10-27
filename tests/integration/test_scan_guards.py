"""佇列與 scan 的防線（M1 審查後補上，docs/DECISIONS.md §13.4、§13.5）。

- 已要求取消、但 runner 遺失（lease 過期）的 scan 是 interrupted，不是 cancelled。
- 沒有要求取消就不能轉到 cancelling；只有 prepare（重新判斷 gate）能讓 run 開始執行。
- 建立 scan 的 key 被撤銷之後，它排隊中的 scan 不會開始（fail closed）。
- run 與凍結的 operation 只能在建立 scan 的 transaction 中寫入；認領不碰已終止的 scan。
每個測試用自己的資料庫（queue_database）。
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import Engine, Row, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from secscan.api_keys.service import ApiKeyService
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus, ScanStatus
from secscan.scans.domain.model import Lease
from secscan.scans.queue import Progress, ScanQueue
from secscan.scans.service import ScanService
from tests.integration.api_support import LAB, Scannable, Seeder, World

pytestmark = pytest.mark.integration

OWNER = "runner-guard-test"
FAKE_ONLY = frozenset({ScanEngine.FAKE})
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


@pytest.fixture
def scannable(queue_seed: Seeder, world: World) -> Scannable:
    return queue_seed.scannable(world)


def _claimed(queue: ScanQueue) -> Lease:
    lease = queue.claim(OWNER, FAKE_ONLY)
    assert lease is not None
    return lease


def _run(seed: Seeder, run_id: UUID) -> Row[Any]:
    [row] = seed.query(
        "SELECT status, error_code, lease_owner FROM scanner_runs WHERE id = :id", id=run_id
    )
    return row


def _scan_status(seed: Seeder, scan_id: UUID) -> str:
    [row] = seed.query("SELECT status FROM scans WHERE id = :id", id=scan_id)
    return str(row.status)


def _cancel(engine: Engine, world: World, scan_id: UUID) -> None:
    with Session(engine, expire_on_commit=False) as session, session.begin():
        ScanService(session, lab=LAB).cancel(world.operator_a.principal, scan_id, request_id=None)


def test_a_cancelled_scan_whose_runner_is_lost_is_interrupted(
    queue: ScanQueue, queue_engine: Engine, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    """確認停止之後才是 cancelled（CLAUDE.md §8）：runner 沒有確認、lease 過期時，
    無法證明流量已停。"""
    scan = queue_seed.scan(world.operator_a, scannable)
    lease = _claimed(queue)
    queue.prepare(lease)
    _cancel(queue_engine, world, scan.id)
    queue_seed.execute(
        "UPDATE scanner_runs SET lease_expires_at = now() - interval '1 second' WHERE id = :id",
        id=lease.run_id,
    )

    assert queue.reconcile_expired(FAKE_ONLY) == 1
    assert _scan_status(queue_seed, scan.id) == "interrupted"
    assert _run(queue_seed, lease.run_id).error_code == "LEASE_EXPIRED"


def test_a_run_cannot_start_cancelling_without_a_cancel_request(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    scan = queue_seed.scan(world.operator_a, scannable)
    lease = _claimed(queue)
    queue.prepare(lease)

    with pytest.raises(ValueError, match="取消"):
        queue.advance(lease, R.CANCELLING)
    assert _run(queue_seed, lease.run_id).status == "running"
    assert _scan_status(queue_seed, scan.id) == "running"


def test_only_prepare_can_start_a_run(
    queue: ScanQueue, queue_engine: Engine, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    """advance 不能跳過 prepare 的 gate：撤銷 grant 之後直接 advance 到 running 會被拒絕
    （審查發現）。"""
    scan = queue_seed.scan(world.operator_a, scannable)
    lease = _claimed(queue)

    with pytest.raises(ValueError, match="prepare"):
        queue.advance(lease, R.RUNNING)
    assert _run(queue_seed, lease.run_id).status == "preparing"
    assert queue.prepare(lease) == Progress(R.RUNNING, S.RUNNING)
    assert _scan_status(queue_seed, scan.id) == "running"


def test_a_scan_of_a_revoked_key_does_not_start(
    queue: ScanQueue, queue_engine: Engine, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    """外洩的 key 被撤銷之後，它排進佇列的 scan 也不會開始（審查發現）。"""
    scan = queue_seed.scan(world.operator_a, scannable)
    lease = _claimed(queue)
    with Session(queue_engine, expire_on_commit=False) as session, session.begin():
        ApiKeyService(session).revoke(
            world.admin.principal, world.operator_a.principal.key_id, request_id=None
        )

    assert queue.prepare(lease) == Progress(R.FAILED, S.FAILED)
    assert _run(queue_seed, lease.run_id).error_code == RunErrorCode.CREATOR_KEY_REVOKED.value
    assert _scan_status(queue_seed, scan.id) == "failed"


@pytest.mark.parametrize(
    "statement",
    [
        "INSERT INTO scanner_runs (scan_id, engine, sequence, status) "
        "VALUES (:id, 'zap', 2, 'queued')",
        "INSERT INTO scan_operations (scan_id, ordinal, method, path) "
        "VALUES (:id, 999, 'GET', '/late')",
    ],
    ids=["run", "operation"],
)
def test_runs_and_operations_are_only_added_while_creating_the_scan(
    queue_seed: Seeder, world: World, scannable: Scannable, statement: str
) -> None:
    """事後加入的 run 會排進佇列、加入的 operation 會改變 coverage 的分母（審查發現）。"""
    scan = queue_seed.scan(world.operator_a, scannable)

    with pytest.raises(IntegrityError, match="creating"):
        queue_seed.execute(statement, id=scan.id)


def test_a_run_of_a_finished_scan_is_never_claimed(
    queue: ScanQueue, queue_engine: Engine, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    """萬一已終止的 scan 有排隊中的 run（只有停用 trigger 才做得到），也不會卡住佇列：
    認領之後的 settle 會被 scans_guard 擋下，FIFO 每次又選到同一個 run（安全審查發現）。

    以 failed 結束（沒有取消的要求），才不會被「要求過取消」的條件先排除。
    """
    scan = queue_seed.scan(world.operator_a, scannable)
    lease = _claimed(queue)
    queue.advance(lease, R.FAILED, error_code=RunErrorCode.ENGINE_FAILED)
    assert _scan_status(queue_seed, scan.id) == "failed"
    with Session(queue_engine) as session, session.begin():
        session.connection().exec_driver_sql(
            "ALTER TABLE scanner_runs DISABLE TRIGGER scanner_runs_guard_rows"
        )
        session.execute(
            text(
                "INSERT INTO scanner_runs (scan_id, engine, sequence, status) "
                "VALUES (:id, 'zap', 2, 'queued')"
            ),
            {"id": scan.id},
        )
        session.connection().exec_driver_sql(
            "ALTER TABLE scanner_runs ENABLE TRIGGER scanner_runs_guard_rows"
        )

    assert queue.claim(OWNER, frozenset(ScanEngine)) is None
