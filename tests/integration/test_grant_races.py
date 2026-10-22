"""併發：version 連號、核准與撤銷互斥、掃描 gate 與撤銷或停用的先後（DECISIONS §10.4、§10.6）。

兩個獨立的連線：先到的在 transaction 中持有鎖，後到的在背景執行；以 pg_stat_activity 確認
後到的正在等列鎖（不靠固定時間的 sleep），再讓先到的 commit，最後檢查後到的看到什麼。
"""

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from secscan.core.errors import AppError, ErrorCode
from secscan.grants.domain.lifecycle import GrantStatus, ScopeGrant
from secscan.grants.service import ScopeGrantService
from secscan.targets.domain import Target, TargetUpdate
from secscan.targets.service import TargetService
from tests.integration.api_support import LAB, Seeder, World, lab_grant_request
from tests.integration.conftest import app_engine
from tests.integration.database import ProvisionedDatabase
from tests.integration.locks import Race, wait_until_waiting_for_a_lock

pytestmark = pytest.mark.integration

RACER = "secscan-grant-racer"


@pytest.fixture
def engine(api_database: ProvisionedDatabase) -> Iterator[Engine]:
    engine = app_engine(api_database)
    yield engine
    engine.dispose()


def _grants(session: Session) -> ScopeGrantService:
    return ScopeGrantService(session, lab=LAB)


def _now() -> datetime:
    return datetime.now(UTC)


def _approved(seed: Seeder, world: World) -> tuple[Target, ScopeGrant]:
    target = seed.target(world.operator_a, world.project_a.id)
    return target, seed.approve(world.admin, seed.grant(world.operator_a, target))


def _only_error(race: Race[ScopeGrant]) -> AppError:
    assert race.results == []
    [error] = race.errors
    assert isinstance(error, AppError)
    return error


def test_concurrent_requests_get_consecutive_versions(
    engine: Engine, api_database: ProvisionedDatabase, seed: Seeder, world: World
) -> None:
    """後到的申請等先到的 commit，再取下一個 version；不會撞號而失敗。"""
    target = seed.target(world.operator_a, world.project_a.id)

    def request(session: Session) -> ScopeGrant:
        return _grants(session).request(
            world.operator_a.principal,
            target.id,
            lab_grant_request(target),
            now=_now(),
            request_id=None,
        )

    race = Race(api_database, RACER, request)
    with Session(engine, expire_on_commit=False) as holder, holder.begin():
        first = request(holder)
        race.start()
        wait_until_waiting_for_a_lock(seed, RACER)
    race.join()

    assert race.errors == []
    [second] = race.results
    assert (first.version, second.version) == (1, 2)


def test_revocation_waits_for_a_concurrent_approval(
    engine: Engine, api_database: ProvisionedDatabase, seed: Seeder, world: World
) -> None:
    target = seed.target(world.operator_a, world.project_a.id)
    grant = seed.grant(world.operator_a, target)
    race = Race(
        api_database,
        RACER,
        lambda session: _grants(session).revoke(
            world.admin.principal, grant.id, reason="停止", now=_now(), request_id=None
        ),
    )

    with Session(engine, expire_on_commit=False) as holder, holder.begin():
        approved = _grants(holder).approve(
            world.admin.principal, grant.id, note="ok", now=_now(), request_id=None
        )
        race.start()
        wait_until_waiting_for_a_lock(seed, RACER)
    race.join()

    assert race.errors == []
    [revoked] = race.results
    assert approved.status is GrantStatus.APPROVED
    assert revoked.status is GrantStatus.REVOKED
    assert revoked.approved_at == approved.approved_at
    rows = seed.query(
        "SELECT action, redacted_changes->>'previous_state' AS previous FROM audit_events "
        "WHERE object_id = :id ORDER BY created_at",
        id=grant.id,
    )
    assert [(row.action, row.previous) for row in rows] == [
        ("scope_grant.create", None),
        ("scope_grant.approve", None),
        ("scope_grant.revoke", "approved"),
    ]


def test_revocation_that_started_first_still_succeeds_after_an_approval(
    engine: Engine, seed: Seeder, world: World
) -> None:
    """撤銷的 transaction 先開始、核准先 commit：撤銷仍然成功，撤銷時間不早於核准時間。

    PostgreSQL 的 now() 是 transaction 開始的時間。撤銷若記成 now()，會早於核准時間、違反
    CHECK（decision_times）而回 500。不需要執行緒：撤銷先送一個查詢固定 now()，核准在另一個
    transaction 完成並 commit 之後，撤銷才拿鎖。
    """
    target = seed.target(world.operator_a, world.project_a.id)
    grant = seed.grant(world.operator_a, target)

    with Session(engine, expire_on_commit=False) as revoker, revoker.begin():
        revoker.execute(text("SELECT 1"))
        approved = seed.approve(world.admin, grant)
        revoked = _grants(revoker).revoke(
            world.admin.principal, grant.id, reason="停止", now=_now(), request_id=None
        )

    assert revoked.status is GrantStatus.REVOKED
    assert approved.approved_at is not None
    assert revoked.revoked_at is not None
    assert revoked.revoked_at >= approved.approved_at


def test_approval_after_a_concurrent_revocation_is_a_conflict(
    engine: Engine, api_database: ProvisionedDatabase, seed: Seeder, world: World
) -> None:
    target = seed.target(world.operator_a, world.project_a.id)
    grant = seed.grant(world.operator_a, target)
    race = Race(
        api_database,
        RACER,
        lambda session: _grants(session).approve(
            world.admin.principal, grant.id, note="ok", now=_now(), request_id=None
        ),
    )

    with Session(engine, expire_on_commit=False) as holder, holder.begin():
        _grants(holder).revoke(
            world.admin.principal, grant.id, reason="停止", now=_now(), request_id=None
        )
        race.start()
        wait_until_waiting_for_a_lock(seed, RACER)
    race.join()

    error = _only_error(race)
    assert (error.status_code, error.code) == (409, ErrorCode.INVALID_STATE_TRANSITION)
    [row] = seed.query("SELECT status FROM scope_grants WHERE id = :id", id=grant.id)
    assert row.status == "revoked"


def test_revocation_waits_for_a_scan_being_created(
    engine: Engine, api_database: ProvisionedDatabase, seed: Seeder, world: World
) -> None:
    """建立 scan 的 transaction 持有 FOR SHARE，撤銷要等它結束。

    T09 會在同一個 transaction 中呼叫 gate 並建立 scan。
    """
    target, grant = _approved(seed, world)
    race = Race(
        api_database,
        RACER,
        lambda session: _grants(session).revoke(
            world.admin.principal, grant.id, reason="停止", now=_now(), request_id=None
        ),
    )

    with Session(engine, expire_on_commit=False) as holder, holder.begin():
        usable = _grants(holder).require_usable(
            world.operator_a.principal, target_id=target.id, grant_id=grant.id, now=_now()
        )
        race.start()
        wait_until_waiting_for_a_lock(seed, RACER)
    race.join()

    assert usable.id == grant.id
    assert race.errors == []
    assert race.results[0].status is GrantStatus.REVOKED


def test_gate_refuses_once_a_concurrent_revocation_commits(
    engine: Engine, api_database: ProvisionedDatabase, seed: Seeder, world: World
) -> None:
    target, grant = _approved(seed, world)
    race = Race(
        api_database,
        RACER,
        lambda session: _grants(session).require_usable(
            world.operator_a.principal, target_id=target.id, grant_id=grant.id, now=_now()
        ),
    )

    with Session(engine, expire_on_commit=False) as holder, holder.begin():
        _grants(holder).revoke(
            world.admin.principal, grant.id, reason="停止", now=_now(), request_id=None
        )
        race.start()
        wait_until_waiting_for_a_lock(seed, RACER)
    race.join()

    error = _only_error(race)
    assert (error.status_code, error.code) == (403, ErrorCode.SCOPE_NOT_APPROVED)


def test_gate_refuses_once_a_concurrent_disable_commits(
    engine: Engine, api_database: ProvisionedDatabase, seed: Seeder, world: World
) -> None:
    target, grant = _approved(seed, world)
    race = Race(
        api_database,
        RACER,
        lambda session: _grants(session).require_usable(
            world.operator_a.principal, target_id=target.id, grant_id=grant.id, now=_now()
        ),
    )

    with Session(engine, expire_on_commit=False) as holder, holder.begin():
        TargetService(holder, lab=LAB).update(
            world.operator_a.principal, target.id, TargetUpdate(enabled=False), request_id=None
        )
        race.start()
        wait_until_waiting_for_a_lock(seed, RACER)
    race.join()

    error = _only_error(race)
    assert (error.status_code, error.code) == (409, ErrorCode.TARGET_DISABLED)
