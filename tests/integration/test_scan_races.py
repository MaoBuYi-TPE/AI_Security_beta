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
from sqlalchemy import Engine, text
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
    """後到的在 target 的鎖上等先到的 commit，持有鎖時再查一次忙碌，得到清楚的 409。"""
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


def test_one_key_used_for_two_targets_at_once_conflicts(
    queue_engine: Engine,
    queue_database: ProvisionedDatabase,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    """key 的範圍是 project：兩個 target 的建立不在同一把鎖上排隊，後到的在 key 的唯一索引上
    等先到的 commit；撞到索引之後重查 key，得到 409（不是 500）。"""
    other = queue_seed.scannable(world)
    key = str(uuid4())
    _, race = _hold_then_race(
        queue_engine,
        queue_database,
        queue_seed,
        _create(world, scannable, key),
        _create(world, other, key),
    )

    error = _only_error(race)
    assert (error.status_code, error.code) == (409, ErrorCode.IDEMPOTENCY_CONFLICT)
    assert len(queue_seed.query("SELECT id FROM scans WHERE idempotency_key = :k", k=key)) == 1


# 直接寫入一個進行中的 scan（不經 service，所以不鎖 target），複製已終止的 scan 的快照。
_ACTIVE_COPY = """
INSERT INTO scans (project_id, target_id, target_origin, scope_grant_id, api_spec_id,
    auth_profile_id, auth_profile_version, auth_role, scan_profile, requests_per_second,
    max_requests, max_duration_seconds, status, idempotency_key, request_sha256,
    created_by_key_id)
SELECT project_id, target_id, target_origin, scope_grant_id, api_spec_id,
    auth_profile_id, auth_profile_version, auth_role, scan_profile, requests_per_second,
    max_requests, max_duration_seconds, 'queued', :key, request_sha256, created_by_key_id
FROM scans WHERE id = :id
"""


@pytest.mark.parametrize("same_key", [False, True], ids=["other-key", "same-key"])
def test_a_scan_written_without_the_target_lock_is_still_caught_by_the_index(
    queue_engine: Engine,
    queue_database: ProvisionedDatabase,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    same_key: bool,
) -> None:
    """target 的鎖沒有排隊時（例如直接寫 DB），仍以唯一索引為準：後到的在索引上等，撞到之後
    先重查 key（同一個 key、同樣的內容：回那個 scan），否則回 409 TARGET_BUSY（不是 500）。"""
    finished = queue_seed.scan(world.operator_a, scannable)
    with Session(queue_engine, expire_on_commit=False) as session, session.begin():
        ScanService(session, lab=LAB).cancel(
            world.operator_a.principal, finished.id, request_id=None
        )
    key = str(uuid4())

    def insert_directly(session: Session) -> object:
        scan_id = session.execute(
            text(_ACTIVE_COPY + " RETURNING id"),
            {"key": key if same_key else str(uuid4()), "id": finished.id},
        ).scalar_one()
        session.execute(
            text(
                "INSERT INTO scanner_runs (scan_id, engine, sequence, status) "
                "VALUES (:id, 'fake', 1, 'queued')"
            ),
            {"id": scan_id},
        )
        return scan_id

    inserted, race = _hold_then_race(
        queue_engine, queue_database, queue_seed, insert_directly, _create(world, scannable, key)
    )

    if same_key:
        assert race.errors == []
        assert [scan.id for scan in race.results] == [inserted]
    else:
        error = _only_error(race)
        assert (error.status_code, error.code) == (409, ErrorCode.TARGET_BUSY)


def test_creates_for_one_target_queue_on_the_target_before_the_gate(
    queue_engine: Engine,
    queue_database: ProvisionedDatabase,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    """同一個 target 的建立彼此排隊（target 以 FOR NO KEY UPDATE 鎖住），不同時持有 grant 的
    FOR SHARE：持續送出的建立請求不能讓撤銷一直等不到鎖（安全審查發現）。

    後到的停在 target 的鎖上，還沒走到 gate：clock 只被取得鎖之前的忙碌預查讀過一次，
    gate 在取得鎖之後才讀時間。
    """
    read_at: list[datetime] = []

    def recording_clock() -> datetime:
        read_at.append(_now())
        return read_at[-1]

    def second(session: Session) -> Scan:
        return ScanService(session, lab=LAB).create(
            world.operator_a.principal,
            scannable.request(),
            idempotency_key=str(uuid4()),
            clock=recording_clock,
            request_id=None,
        )

    race = Race(queue_database, RACER, second)
    with Session(queue_engine, expire_on_commit=False) as holder, holder.begin():
        _create(world, scannable, str(uuid4()))(holder)
        race.start()
        wait_until_waiting_for_a_lock(queue_seed, RACER)
        assert len(read_at) == 1
    race.join()

    error = _only_error(race)
    assert (error.status_code, error.code) == (409, ErrorCode.TARGET_BUSY)


def test_a_busy_target_is_refused_without_taking_any_lock(
    queue_engine: Engine,
    queue_database: ProvisionedDatabase,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    """target 已有進行中的 scan：在取得任何鎖之前就回 409，不和撤銷、停用搶鎖
    （安全審查發現）。"""
    queue_seed.scan(world.operator_a, scannable)
    race = Race(queue_database, RACER, _create(world, scannable, str(uuid4())))

    with Session(queue_engine, expire_on_commit=False) as holder, holder.begin():
        holder.execute(
            text("SELECT id FROM targets WHERE id = :id FOR UPDATE"), {"id": scannable.target.id}
        )
        race.start()
        race.join()  # 等鎖的話會逾時：holder 在 join 之後才 commit

    error = _only_error(race)
    assert (error.status_code, error.code) == (409, ErrorCode.TARGET_BUSY)


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
        _create(world, scannable, str(uuid4()), auth_profile_id=scannable.profile.id),
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
        _create(world, scannable, str(uuid4()), auth_profile_id=scannable.profile.id),
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
