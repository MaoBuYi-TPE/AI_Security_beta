"""併發（docs/DECISIONS.md §13.2、§13.5）：先到的在 transaction 中持有鎖，後到的在背景執行；
以 pg_stat_activity 確認後到的正在等鎖（不靠固定時間的 sleep），再讓先到的 commit。

- 同時建立：同一個 target 只有一個成功；同一個 key 回同一個 scan，不同內容回 409。
- 建立與撤銷、停用、PATCH profile：兩個方向都不會建立出不該存在的快照。
- 取消與認領：取消持有鎖時認領跳過它；認領持有鎖時取消等它，之後是 cancelling。
每個測試用自己的資料庫（queue_database）。
"""

from collections.abc import Callable
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from secscan.auth_profiles.domain.credentials import SecretValue
from secscan.auth_profiles.domain.model import AuthProfile, ChangeInput
from secscan.auth_profiles.service import AuthProfileService
from secscan.core.errors import AppError, ErrorCode
from secscan.grants.domain.lifecycle import ScopeGrant
from secscan.grants.service import ScopeGrantService
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunStatus, ScanStatus
from secscan.scans.domain.model import Lease, Scan
from secscan.scans.domain.request import BudgetRequest
from secscan.scans.queue import QueueOperations
from secscan.scans.service import ScanService
from secscan.targets.domain import Target, TargetUpdate
from secscan.targets.service import TargetService
from tests.integration.api_support import LAB, Scannable, Seeder, World
from tests.integration.database import ProvisionedDatabase
from tests.integration.locks import Race, wait_until_waiting_for_a_lock
from tests.secret_support import shared_cipher

pytestmark = pytest.mark.integration

RACER = "secscan-scan-racer"
FAKE = frozenset({ScanEngine.FAKE})


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


@pytest.fixture
def scannable(queue_seed: Seeder, world: World) -> Scannable:
    return queue_seed.scannable(world)


def _now() -> datetime:
    return datetime.now(UTC)


def _create(
    world: World, scannable: Scannable, key: str, **overrides: object
) -> Callable[[Session], Scan]:
    def work(session: Session) -> Scan:
        return ScanService(session, lab=LAB).create(
            world.operator_a.principal,
            scannable.request(**overrides),
            idempotency_key=key,
            clock=_now,
            request_id=None,
        )

    return work


def _only_error[T](race: Race[T]) -> AppError:
    assert race.results == []
    [error] = race.errors
    assert isinstance(error, AppError)
    return error


def _hold_then_race[T](
    engine: Engine,
    database: ProvisionedDatabase,
    seed: Seeder,
    first: Callable[[Session], object],
    second: Callable[[Session], T],
) -> tuple[object, Race[T]]:
    """first 在持有鎖的 transaction 中執行；second 在背景等鎖，first commit 之後才繼續。"""
    race = Race(database, RACER, second)
    with Session(engine, expire_on_commit=False) as holder, holder.begin():
        result = first(holder)
        race.start()
        wait_until_waiting_for_a_lock(seed, RACER)
    race.join()
    return result, race


# --- 同時建立 ------------------------------------------------------------------------------


def test_concurrent_creates_for_one_target_let_only_one_through(
    queue_engine: Engine,
    queue_database: ProvisionedDatabase,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    """後到的在部分唯一索引上等先到的 commit，之後得到清楚的 409，而不是 500。"""
    first, race = _hold_then_race(
        queue_engine,
        queue_database,
        queue_seed,
        _create(world, scannable, str(uuid4())),
        _create(world, scannable, str(uuid4())),
    )

    error = _only_error(race)
    assert (error.status_code, error.code) == (409, ErrorCode.TARGET_BUSY)
    assert isinstance(first, Scan)
    assert queue_seed.query("SELECT id FROM scans WHERE target_id = :id", id=scannable.target.id)[
        0
    ].id == (first.id)


def test_concurrent_creates_with_the_same_key_return_the_same_scan(
    queue_engine: Engine,
    queue_database: ProvisionedDatabase,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    key = str(uuid4())
    first, race = _hold_then_race(
        queue_engine,
        queue_database,
        queue_seed,
        _create(world, scannable, key),
        _create(world, scannable, key),
    )

    assert race.errors == []
    [second] = race.results
    assert isinstance(first, Scan)
    assert second.id == first.id
    assert len(queue_seed.query("SELECT id FROM scans WHERE idempotency_key = :k", k=key)) == 1


def test_concurrent_creates_with_the_same_key_and_other_content_conflict(
    queue_engine: Engine,
    queue_database: ProvisionedDatabase,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    key = str(uuid4())
    _, race = _hold_then_race(
        queue_engine,
        queue_database,
        queue_seed,
        _create(world, scannable, key),
        _create(world, scannable, key, budget=BudgetRequest(max_requests=10)),
    )

    error = _only_error(race)
    assert (error.status_code, error.code) == (409, ErrorCode.IDEMPOTENCY_CONFLICT)


# --- 建立與撤銷、停用 ----------------------------------------------------------------------


def _revoke(world: World, grant: ScopeGrant) -> Callable[[Session], ScopeGrant]:
    def work(session: Session) -> ScopeGrant:
        return ScopeGrantService(session, lab=LAB).revoke(
            world.admin.principal, grant.id, reason="停止", now=_now(), request_id=None
        )

    return work


def _disable(world: World, target: Target) -> Callable[[Session], Target]:
    def work(session: Session) -> Target:
        return TargetService(session, lab=LAB).update(
            world.operator_a.principal, target.id, TargetUpdate(enabled=False), request_id=None
        )

    return work


def test_a_revocation_waits_for_a_scan_being_created(
    queue_engine: Engine,
    queue_database: ProvisionedDatabase,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    """建立 scan 持有 grant 的 FOR SHARE：撤銷等它 commit；之後 runner 啟動前就會擋下。"""
    scan, race = _hold_then_race(
        queue_engine,
        queue_database,
        queue_seed,
        _create(world, scannable, str(uuid4())),
        _revoke(world, scannable.grant),
    )

    assert race.errors == []
    assert isinstance(scan, Scan)
    with Session(queue_engine, expire_on_commit=False) as session, session.begin():
        operations = QueueOperations(session, lab=LAB)
        lease = operations.claim("runner", FAKE)
        assert lease is not None
        assert operations.prepare(lease, clock=_now).run_status is RunStatus.FAILED


@pytest.mark.parametrize(
    ("change", "status", "code"),
    [
        ("revoke", 403, ErrorCode.SCOPE_NOT_APPROVED),
        ("disable", 409, ErrorCode.TARGET_DISABLED),
    ],
)
def test_a_scan_waiting_for_a_revocation_or_disable_is_refused(
    queue_engine: Engine,
    queue_database: ProvisionedDatabase,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    change: str,
    status: int,
    code: ErrorCode,
) -> None:
    first = (
        _revoke(world, scannable.grant) if change == "revoke" else _disable(world, scannable.target)
    )
    _, race = _hold_then_race(
        queue_engine,
        queue_database,
        queue_seed,
        first,
        _create(world, scannable, str(uuid4())),
    )

    error = _only_error(race)
    assert (error.status_code, error.code) == (status, code)


# --- 建立與 PATCH profile ------------------------------------------------------------------


def _patch(world: World, profile: AuthProfile) -> Callable[[Session], AuthProfile]:
    def work(session: Session) -> AuthProfile:
        return AuthProfileService(session, cipher=shared_cipher()).update(
            world.operator_a.principal,
            profile.id,
            ChangeInput(secret=SecretValue("t2")),
            request_id=None,
        )

    return work


def test_a_patch_waits_for_a_scan_binding_the_current_version(
    queue_engine: Engine,
    queue_database: ProvisionedDatabase,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    """建立 scan 以 FOR SHARE 鎖住 profile：PATCH 等它 commit，scan 綁定的是版本 1。"""
    scan, race = _hold_then_race(
        queue_engine,
        queue_database,
        queue_seed,
        _create(world, scannable, str(uuid4())),
        _patch(world, scannable.profile),
    )

    assert race.errors == []
    assert isinstance(scan, Scan)
    assert scan.auth is not None
    assert scan.auth.version == 1
    assert race.results[0].current.version == 2


def test_a_scan_created_while_a_patch_is_open_binds_the_new_version(
    queue_engine: Engine,
    queue_database: ProvisionedDatabase,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    """PATCH 先拿到鎖：建立 scan 等它 commit，再讀目前的版本，不會綁到剛被清除的版本 1。"""
    _, race = _hold_then_race(
        queue_engine,
        queue_database,
        queue_seed,
        _patch(world, scannable.profile),
        _create(world, scannable, str(uuid4())),
    )

    assert race.errors == []
    [scan] = race.results
    assert scan.auth is not None
    assert scan.auth.version == 2


# --- 取消與認領 ----------------------------------------------------------------------------


def _cancel(world: World, scan: Scan) -> Callable[[Session], Scan]:
    def work(session: Session) -> Scan:
        return ScanService(session, lab=LAB).cancel(
            world.operator_a.principal, scan.id, request_id=None
        )

    return work


def _claim(session: Session) -> Lease | None:
    return QueueOperations(session, lab=LAB).claim("runner", FAKE)


def test_a_claim_skips_a_scan_being_cancelled(
    queue_engine: Engine,
    queue_database: ProvisionedDatabase,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    scan = queue_seed.scan(world.operator_a, scannable)
    race = Race(queue_database, RACER, _claim)

    with Session(queue_engine, expire_on_commit=False) as holder, holder.begin():
        _cancel(world, scan)(holder)
        race.start()
        race.join()  # SKIP LOCKED：不等待，立刻得到「沒有工作」

    assert (race.errors, race.results) == ([], [None])
    with Session(queue_engine, expire_on_commit=False) as session, session.begin():
        assert _claim(session) is None


def test_a_cancel_waits_for_a_claim_and_then_asks_the_runner(
    queue_engine: Engine,
    queue_database: ProvisionedDatabase,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    scan = queue_seed.scan(world.operator_a, scannable)

    lease, race = _hold_then_race(
        queue_engine, queue_database, queue_seed, _claim, _cancel(world, scan)
    )

    assert race.errors == []
    [cancelled] = race.results
    assert isinstance(lease, Lease)
    assert cancelled.status is ScanStatus.CANCELLING
    assert cancelled.runs[0].status is RunStatus.PREPARING
    rows = queue_seed.query(
        "SELECT sequence FROM scan_events WHERE scan_id = :id ORDER BY sequence", id=scan.id
    )
    sequences = [row.sequence for row in rows]
    assert sequences == list(range(1, len(sequences) + 1))


def test_a_scan_is_invisible_to_runners_until_it_commits(
    queue_engine: Engine,
    queue_database: ProvisionedDatabase,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    """scan 與 run 在同一個 transaction 寫入：commit 之前 runner 認領不到，commit 之後才有工作。"""
    race = Race(queue_database, RACER, _claim)

    with Session(queue_engine, expire_on_commit=False) as holder, holder.begin():
        scan = _create(world, scannable, str(uuid4()))(holder)
        race.start()
        race.join()

    assert (race.errors, race.results) == ([], [None])
    with Session(queue_engine, expire_on_commit=False) as session, session.begin():
        lease = _claim(session)
    assert lease is not None
    assert lease.scan_id == scan.id
