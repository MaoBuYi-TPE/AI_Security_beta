"""工作佇列：認領、lease、心跳、prepare、轉換與對帳（docs/DECISIONS.md §13.4、§13.5）。

每個測試用自己的資料庫（queue_database）：佇列會認領任何排隊中的 run。
"""

import dataclasses
from collections.abc import Callable
from datetime import UTC, datetime
from ipaddress import IPv4Network
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine, Row
from sqlalchemy.orm import Session, sessionmaker

from secscan.auth_profiles.domain.credentials import SecretValue
from secscan.auth_profiles.domain.model import ChangeInput
from secscan.auth_profiles.service import AuthProfileService
from secscan.grants.service import ScopeGrantService
from secscan.scans import queue as queue_module
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.catalog import ScanProfile, plan_runs
from secscan.scans.domain.lifecycle import (
    InvalidRunTransitionError,
    RunErrorCode,
    RunStatus,
    ScanStatus,
)
from secscan.scans.domain.model import Lease, NewScan
from secscan.scans.progress import ScanProgress
from secscan.scans.queue import (
    LEASE_DURATION,
    Heartbeat,
    LeaseLostError,
    Progress,
    QueueOperations,
    ScanQueue,
)
from secscan.scans.repository import ScanRepository
from secscan.targets.domain import LabNetwork, TargetUpdate
from secscan.targets.service import TargetService
from tests.integration.api_support import LAB, Scannable, Seeder, World
from tests.integration.database import ProvisionedDatabase
from tests.integration.locks import Race
from tests.secret_support import shared_cipher

pytestmark = pytest.mark.integration

OWNER = "runner-test-1"
OTHER_OWNER = "runner-test-2"
FAKE_ONLY = frozenset({ScanEngine.FAKE})
EVERY_ENGINE = frozenset(ScanEngine)
RACER = "secscan-queue-racer"
R = RunStatus
S = ScanStatus


def _now() -> datetime:
    return datetime.now(UTC)


def _queue(engine: Engine, clock: Callable[[], datetime] = _now) -> ScanQueue:
    return ScanQueue(sessionmaker(engine, expire_on_commit=False), lab=LAB, clock=clock)


@pytest.fixture
def queue(queue_engine: Engine) -> ScanQueue:
    return _queue(queue_engine)


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


@pytest.fixture
def scannable(queue_seed: Seeder, world: World) -> Scannable:
    return queue_seed.scannable(world)


def _fake_scan(seed: Seeder, world: World, scannable: Scannable) -> UUID:
    return seed.scan(world.operator_a, scannable).id


def _engine_scan(
    engine: Engine, world: World, scannable: Scannable, engines: tuple[ScanEngine, ...]
) -> UUID:
    """真的引擎還不能經由 API 建立（docs/DECISIONS.md §13.11）：直接寫入，測試佇列的依序執行。"""
    with Session(engine, expire_on_commit=False) as session, session.begin():
        return ScanRepository(session).create(
            NewScan(
                project_id=world.project_a.id,
                target_id=scannable.target.id,
                target_origin=scannable.target.origin,
                scope_grant_id=scannable.grant.id,
                api_spec_id=scannable.spec.id,
                auth=None,
                profile=ScanProfile.API_ACTIVE_LAB,
                budget=scannable.grant.budget,
                runs=plan_runs(engines, available=EVERY_ENGINE),
                operations=(),
                idempotency_key=uuid4().hex,
                request_sha256=bytes(32),
                created_by_key_id=world.operator_a.principal.key_id,
            )
        )


def _run(seed: Seeder, run_id: UUID) -> Row[Any]:
    [row] = seed.query(
        "SELECT status, lease_owner, lease_expires_at, heartbeat_at, started_at, finished_at, "
        "error_code FROM scanner_runs WHERE id = :id",
        id=run_id,
    )
    return row


def _runs(seed: Seeder, scan_id: UUID) -> list[str]:
    rows = seed.query(
        "SELECT status FROM scanner_runs WHERE scan_id = :id ORDER BY sequence", id=scan_id
    )
    return [row.status for row in rows]


def _scan(seed: Seeder, scan_id: UUID) -> Row[Any]:
    [row] = seed.query("SELECT status, finished_at FROM scans WHERE id = :id", id=scan_id)
    return row


def _events(seed: Seeder, scan_id: UUID) -> list[tuple[int, str, dict[str, object]]]:
    rows = seed.query(
        "SELECT sequence, event_type, payload FROM scan_events WHERE scan_id = :id "
        "ORDER BY sequence",
        id=scan_id,
    )
    return [(row.sequence, row.event_type, row.payload) for row in rows]


def _expire(seed: Seeder, run_id: UUID) -> None:
    seed.execute(
        "UPDATE scanner_runs SET lease_expires_at = now() - interval '1 second' WHERE id = :id",
        id=run_id,
    )


def _request_cancel(seed: Seeder, scan_id: UUID) -> None:
    seed.execute("UPDATE scans SET cancel_requested_at = now() WHERE id = :id", id=scan_id)


def _claimed(
    queue: ScanQueue, owner: str = OWNER, engines: frozenset[ScanEngine] = FAKE_ONLY
) -> Lease:
    lease = queue.claim(owner, engines)
    assert lease is not None
    return lease


def _collect(queue: ScanQueue, lease: Lease) -> Lease:
    """runner 跑完並收集；worker 認領同一個 run 來解析。"""
    assert queue.prepare(lease).run_status is R.RUNNING
    queue.advance(lease, R.COLLECTING)
    queue.advance(lease, R.COLLECTED)
    parsing = queue.claim_collected(OTHER_OWNER, EVERY_ENGINE, run_id=lease.run_id)
    assert parsing is not None
    return parsing


# --- 認領 ----------------------------------------------------------------------------------


def test_claims_a_queued_run_with_a_lease(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    scan_id = _fake_scan(queue_seed, world, scannable)
    [run_id] = [
        row.id
        for row in queue_seed.query("SELECT id FROM scanner_runs WHERE scan_id = :id", id=scan_id)
    ]

    lease = queue.claim(OWNER, FAKE_ONLY)

    assert lease == Lease(run_id=run_id, scan_id=scan_id, engine=ScanEngine.FAKE, owner=OWNER)
    run = _run(queue_seed, run_id)
    assert (run.status, run.lease_owner) == ("preparing", OWNER)
    assert run.started_at is not None
    assert run.heartbeat_at == run.started_at
    assert run.lease_expires_at - run.heartbeat_at == LEASE_DURATION
    assert _scan(queue_seed, scan_id).status == "preparing"
    assert _events(queue_seed, scan_id)[1:] == [
        (
            2,
            "run.status",
            {
                "engine": "fake",
                "status": "preparing",
                "previous_status": "queued",
                "error_code": None,
            },
        ),
        (3, "scan.status", {"status": "preparing", "previous_status": "queued"}),
    ]


def test_there_is_nothing_to_claim_in_an_empty_queue(queue: ScanQueue) -> None:
    assert queue.claim(OWNER, FAKE_ONLY) is None
    assert queue.claim_collected(OWNER, EVERY_ENGINE) is None


def test_claims_only_the_requested_engines(
    queue: ScanQueue, queue_engine: Engine, world: World, scannable: Scannable
) -> None:
    scan_id = _engine_scan(queue_engine, world, scannable, (ScanEngine.ZAP,))

    assert queue.claim(OWNER, FAKE_ONLY) is None
    lease = _claimed(queue, engines=frozenset({ScanEngine.ZAP}))
    assert (lease.scan_id, lease.engine) == (scan_id, ScanEngine.ZAP)


def test_claims_in_queue_order(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    first = _fake_scan(queue_seed, world, scannable)
    second = _fake_scan(queue_seed, world, queue_seed.scannable(world))

    assert [_claimed(queue).scan_id, _claimed(queue).scan_id] == [first, second]


def test_a_scan_with_a_cancel_request_is_not_claimed(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    _request_cancel(queue_seed, _fake_scan(queue_seed, world, scannable))

    assert queue.claim(OWNER, FAKE_ONLY) is None


def test_a_later_engine_waits_until_earlier_engines_stop_sending_traffic(
    queue: ScanQueue, queue_engine: Engine, world: World, scannable: Scannable
) -> None:
    scan_id = _engine_scan(queue_engine, world, scannable, (ScanEngine.NUCLEI, ScanEngine.ZAP))
    zap = _claimed(queue, engines=EVERY_ENGINE)

    assert zap.engine is ScanEngine.ZAP
    assert queue.claim(OTHER_OWNER, EVERY_ENGINE) is None
    queue.prepare(zap)
    queue.advance(zap, R.COLLECTING)
    assert queue.claim(OTHER_OWNER, EVERY_ENGINE) is None
    queue.advance(zap, R.COLLECTED)
    nuclei = _claimed(queue, OTHER_OWNER, EVERY_ENGINE)
    assert (nuclei.scan_id, nuclei.engine) == (scan_id, ScanEngine.NUCLEI)


def test_a_failed_engine_does_not_block_later_engines(
    queue: ScanQueue, queue_seed: Seeder, queue_engine: Engine, world: World, scannable: Scannable
) -> None:
    scan_id = _engine_scan(queue_engine, world, scannable, (ScanEngine.ZAP, ScanEngine.NUCLEI))
    zap = _claimed(queue, engines=EVERY_ENGINE)

    progress = queue.advance(zap, R.FAILED, error_code=RunErrorCode.ENGINE_FAILED)

    assert progress == Progress(run_status=R.FAILED, scan_status=S.RUNNING)
    assert _claimed(queue, OTHER_OWNER, EVERY_ENGINE).engine is ScanEngine.NUCLEI
    assert _runs(queue_seed, scan_id) == ["failed", "preparing"]


def test_one_engine_succeeding_and_another_failing_is_partially_completed(
    queue: ScanQueue, queue_seed: Seeder, queue_engine: Engine, world: World, scannable: Scannable
) -> None:
    scan_id = _engine_scan(queue_engine, world, scannable, (ScanEngine.ZAP, ScanEngine.NUCLEI))
    zap = _collect(queue, _claimed(queue, engines=EVERY_ENGINE))
    queue.advance(zap, R.SUCCEEDED)
    nuclei = _claimed(queue, engines=EVERY_ENGINE)
    queue.prepare(nuclei)

    progress = queue.advance(nuclei, R.FAILED, error_code=RunErrorCode.ENGINE_FAILED)

    assert progress == Progress(run_status=R.FAILED, scan_status=S.PARTIALLY_COMPLETED)
    scan = _scan(queue_seed, scan_id)
    assert scan.status == "partially_completed"
    assert scan.finished_at is not None


# --- lease ---------------------------------------------------------------------------------


def test_a_heartbeat_extends_the_lease_and_reports_a_cancel_request(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    _fake_scan(queue_seed, world, scannable)
    lease = _claimed(queue)
    before = _run(queue_seed, lease.run_id)

    assert queue.heartbeat(lease) == Heartbeat(valid=True, cancel_requested=False)
    after = _run(queue_seed, lease.run_id)
    assert after.lease_expires_at > before.lease_expires_at
    assert after.lease_expires_at - after.heartbeat_at == LEASE_DURATION

    _request_cancel(queue_seed, lease.scan_id)
    assert queue.heartbeat(lease) == Heartbeat(valid=True, cancel_requested=True)


def test_an_expired_lease_cannot_be_extended_or_used(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    _fake_scan(queue_seed, world, scannable)
    lease = _claimed(queue)
    _expire(queue_seed, lease.run_id)
    expired = _run(queue_seed, lease.run_id)

    assert queue.heartbeat(lease) == Heartbeat(valid=False, cancel_requested=False)
    with pytest.raises(LeaseLostError):
        queue.prepare(lease)
    with pytest.raises(LeaseLostError):
        queue.advance(lease, R.FAILED, error_code=RunErrorCode.ENGINE_FAILED)
    assert _run(queue_seed, lease.run_id) == expired


def test_another_owner_cannot_use_the_lease(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    _fake_scan(queue_seed, world, scannable)
    lease = _claimed(queue)
    impostor = dataclasses.replace(lease, owner=OTHER_OWNER)

    assert queue.heartbeat(impostor) == Heartbeat(valid=False, cancel_requested=False)
    with pytest.raises(LeaseLostError):
        queue.prepare(impostor)
    with pytest.raises(LeaseLostError):
        queue.advance(impostor, R.FAILED, error_code=RunErrorCode.ENGINE_FAILED)
    assert _run(queue_seed, lease.run_id).status == "preparing"


def test_an_expired_lease_is_not_taken_over_by_another_claim(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    """lease 過期不代表工作已經停止（ARCHITECTURE.md §9）：不會被別人接手。"""
    _fake_scan(queue_seed, world, scannable)
    _expire(queue_seed, _claimed(queue).run_id)

    assert queue.claim(OTHER_OWNER, FAKE_ONLY) is None


def test_transitions_outside_the_table_are_rejected(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    _fake_scan(queue_seed, world, scannable)
    lease = _claimed(queue)

    with pytest.raises(InvalidRunTransitionError):
        queue.advance(lease, R.SUCCEEDED)
    assert _run(queue_seed, lease.run_id).status == "preparing"


def test_collected_and_finished_runs_drop_their_lease(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    scan_id = _fake_scan(queue_seed, world, scannable)
    lease = _claimed(queue)
    queue.prepare(lease)
    queue.advance(lease, R.COLLECTING)
    assert _run(queue_seed, lease.run_id).lease_owner == OWNER

    assert queue.advance(lease, R.COLLECTED) == Progress(R.COLLECTED, S.COLLECTING)
    collected = _run(queue_seed, lease.run_id)
    assert (collected.lease_owner, collected.lease_expires_at, collected.heartbeat_at) == (
        None,
        None,
        None,
    )
    parsing = queue.claim_collected(OTHER_OWNER, FAKE_ONLY)
    assert parsing == dataclasses.replace(lease, owner=OTHER_OWNER)
    assert _run(queue_seed, lease.run_id).lease_owner == OTHER_OWNER
    assert _scan(queue_seed, scan_id).status == "normalizing"

    assert queue.advance(parsing, R.SUCCEEDED) == Progress(R.SUCCEEDED, S.COMPLETED)
    finished = _run(queue_seed, lease.run_id)
    assert finished.lease_owner is None
    assert finished.finished_at is not None
    assert _scan(queue_seed, scan_id).finished_at is not None


def test_a_specific_collected_run_can_be_claimed(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    _fake_scan(queue_seed, world, scannable)
    lease = _claimed(queue)

    assert queue.claim_collected(OWNER, FAKE_ONLY, run_id=lease.run_id) is None
    _collect(queue, lease)


# --- prepare：runner 啟動前重新判斷 ----------------------------------------------------------


def test_prepare_starts_the_run_while_the_gate_still_passes(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    scan_id = _fake_scan(queue_seed, world, scannable)

    assert queue.prepare(_claimed(queue)) == Progress(R.RUNNING, S.RUNNING)
    assert _scan(queue_seed, scan_id).status == "running"


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


def _replace_profile(engine: Engine, world: World, scannable: Scannable) -> None:
    with Session(engine, expire_on_commit=False) as session, session.begin():
        AuthProfileService(session, cipher=shared_cipher()).update(
            world.operator_a.principal,
            scannable.profile.id,
            ChangeInput(secret=SecretValue("t2")),
            request_id=None,
        )


def _move_origin(engine: Engine, world: World, scannable: Scannable) -> None:
    """targets 沒有 trigger：只有直接改了 DB，origin 才會和快照不同。"""
    seed = Seeder(engine)
    seed.execute(
        "UPDATE targets SET canonical_origin = 'http://elsewhere:5000' WHERE id = :id",
        id=scannable.target.id,
    )


@pytest.mark.parametrize(
    ("change", "error_code"),
    [
        (_revoke, RunErrorCode.SCOPE_REVOKED),
        (_disable, RunErrorCode.TARGET_DISABLED),
        (_replace_profile, RunErrorCode.AUTH_PROFILE_SUPERSEDED),
        (_move_origin, RunErrorCode.SCOPE_MISMATCH),
    ],
    ids=["revoked", "disabled", "superseded", "moved"],
)
def test_prepare_fails_closed_after_the_snapshot_stops_being_valid(
    queue: ScanQueue,
    queue_seed: Seeder,
    queue_engine: Engine,
    world: World,
    scannable: Scannable,
    change: Callable[[Engine, World, Scannable], None],
    error_code: RunErrorCode,
) -> None:
    """撤銷、停用、PATCH profile 之後，排隊中的 scan 在送出流量之前就停下（T06、T08 的交接）。"""
    scan_id = _fake_scan(queue_seed, world, scannable)
    lease = _claimed(queue)
    change(queue_engine, world, scannable)

    assert queue.prepare(lease) == Progress(R.FAILED, S.FAILED)
    run = _run(queue_seed, lease.run_id)
    assert (run.status, run.error_code, run.lease_owner) == ("failed", error_code.value, None)
    assert _scan(queue_seed, scan_id).finished_at is not None


def test_prepare_fails_after_the_grant_expires(
    queue_engine: Engine, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    _fake_scan(queue_seed, world, scannable)
    late = _queue(queue_engine, clock=lambda: scannable.grant.window.valid_until)
    lease = _claimed(late)

    assert late.prepare(lease) == Progress(R.FAILED, S.FAILED)
    assert _run(queue_seed, lease.run_id).error_code == "SCOPE_EXPIRED"


def test_prepare_moves_a_cancelled_scan_to_cancelling(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    scan_id = _fake_scan(queue_seed, world, scannable)
    lease = _claimed(queue)
    _request_cancel(queue_seed, scan_id)

    assert queue.prepare(lease) == Progress(R.CANCELLING, S.CANCELLING)
    assert queue.advance(lease, R.CANCELLED) == Progress(R.CANCELLED, S.CANCELLED)


# --- 對帳 ----------------------------------------------------------------------------------


def test_reconcile_interrupts_expired_runner_stage_runs(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    scan_id = _fake_scan(queue_seed, world, scannable)
    lease = _claimed(queue)
    queue.prepare(lease)
    _expire(queue_seed, lease.run_id)

    assert queue.reconcile_expired(FAKE_ONLY) == 1
    run = _run(queue_seed, lease.run_id)
    assert (run.status, run.error_code, run.lease_owner) == ("interrupted", "LEASE_EXPIRED", None)
    assert _scan(queue_seed, scan_id).status == "interrupted"
    # 對帳之後 target 不再忙碌。
    assert queue_seed.scan(world.operator_a, scannable).status is S.QUEUED


def test_reconcile_returns_expired_parsing_to_collected(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    """只有 parser 可以重試（CLAUDE.md §8）：解析不可變的 artifact，不會送出流量。"""
    _fake_scan(queue_seed, world, scannable)
    parsing = _collect(queue, _claimed(queue))
    _expire(queue_seed, parsing.run_id)

    assert queue.reconcile_expired(FAKE_ONLY) == 1
    assert _run(queue_seed, parsing.run_id).status == "collected"
    retry = queue.claim_collected(OWNER, FAKE_ONLY)
    assert retry is not None
    assert queue.advance(retry, R.SUCCEEDED).scan_status is S.COMPLETED


def test_reconcile_only_touches_the_requested_engines_and_expired_leases(
    queue: ScanQueue, queue_seed: Seeder, queue_engine: Engine, world: World, scannable: Scannable
) -> None:
    _engine_scan(queue_engine, world, scannable, (ScanEngine.ZAP,))
    zap = _claimed(queue, engines=EVERY_ENGINE)
    _expire(queue_seed, zap.run_id)
    _fake_scan(queue_seed, world, queue_seed.scannable(world))
    fake = _claimed(queue)

    assert queue.reconcile_expired(FAKE_ONLY) == 0
    assert _run(queue_seed, zap.run_id).status == "preparing"
    assert _run(queue_seed, fake.run_id).status == "preparing"


def test_events_have_consecutive_sequences(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    scan_id = _fake_scan(queue_seed, world, scannable)
    queue.advance(_collect(queue, _claimed(queue)), R.SUCCEEDED)

    events = _events(queue_seed, scan_id)
    assert [sequence for sequence, _, _ in events] == list(range(1, len(events) + 1))
    assert [(kind, payload.get("status")) for _, kind, payload in events] == [
        ("scan.created", "queued"),
        ("run.status", "preparing"),
        ("scan.status", "preparing"),
        ("run.status", "running"),
        ("scan.status", "running"),
        ("run.status", "collecting"),
        ("scan.status", "collecting"),
        ("run.status", "collected"),
        ("run.status", "normalizing"),
        ("scan.status", "normalizing"),
        ("run.status", "succeeded"),
        ("scan.status", "completed"),
    ]


# --- 兩個 consumer 同時認領（SKIP LOCKED，[S28]）----------------------------------------------


def _claim_in(session: Session) -> Lease | None:
    return QueueOperations(session, lab=LAB).claim(OTHER_OWNER, FAKE_ONLY)


def test_two_consumers_claim_different_scans_at_once(
    queue_engine: Engine,
    queue_database: ProvisionedDatabase,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    first = _fake_scan(queue_seed, world, scannable)
    second = _fake_scan(queue_seed, world, queue_seed.scannable(world))
    race = Race(queue_database, RACER, _claim_in)

    with Session(queue_engine, expire_on_commit=False) as holder, holder.begin():
        mine = QueueOperations(holder, lab=LAB).claim(OWNER, FAKE_ONLY)
        # 對手不等待先到的鎖：在先到的 commit 之前就結束（逾時代表它在等）。
        race.start()
        race.join()

    assert race.errors == []
    [theirs] = race.results
    assert mine is not None
    assert theirs is not None
    assert (mine.scan_id, theirs.scan_id) == (first, second)


def test_a_scan_being_claimed_is_skipped_without_waiting(
    queue_engine: Engine,
    queue_database: ProvisionedDatabase,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    _fake_scan(queue_seed, world, scannable)
    race = Race(queue_database, RACER, _claim_in)

    with Session(queue_engine, expire_on_commit=False) as holder, holder.begin():
        assert QueueOperations(holder, lab=LAB).claim(OWNER, FAKE_ONLY) is not None
        race.start()
        race.join()

    assert (race.errors, race.results) == ([], [None])


# --- 鎖到之後再確認、上限與防線 -------------------------------------------------------------


def _change_before_lock(
    monkeypatch: pytest.MonkeyPatch, seed: Seeder, statement: str, run_id: UUID
) -> None:
    """在佇列選出候選、還沒鎖住 scan 之前，另一個連線改了這個 run 並 commit（READ COMMITTED 下
    候選的資料可能已經過時，[S28]）。只觸發一次。"""
    original = ScanProgress.lock_scan
    fired: list[bool] = []

    def lock_scan(self: ScanProgress, scan_id: UUID) -> object:
        if not fired:
            fired.append(True)
            seed.execute(statement, id=run_id)
        return original(self, scan_id)

    monkeypatch.setattr(ScanProgress, "lock_scan", lock_scan)


def test_a_claim_rechecks_the_run_after_locking_the_scan(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id = _fake_scan(queue_seed, world, scannable)
    [run] = queue_seed.query("SELECT id FROM scanner_runs WHERE scan_id = :id", id=scan_id)
    _change_before_lock(
        monkeypatch,
        queue_seed,
        "UPDATE scanner_runs SET status = 'cancelled', finished_at = now() WHERE id = :id",
        run.id,
    )

    assert queue.claim(OWNER, FAKE_ONLY) is None
    assert _run(queue_seed, run.id).status == "cancelled"


def test_a_claim_gives_up_after_a_few_stale_candidates(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """候選一直過時（別人一直搶先）也不會無限重試：試過上限之後回「沒有工作」。"""
    monkeypatch.setattr(queue_module, "MAX_CLAIM_ATTEMPTS", 1)
    first = _fake_scan(queue_seed, world, scannable)
    _fake_scan(queue_seed, world, queue_seed.scannable(world))
    [run] = queue_seed.query("SELECT id FROM scanner_runs WHERE scan_id = :id", id=first)
    _change_before_lock(
        monkeypatch,
        queue_seed,
        "UPDATE scanner_runs SET status = 'cancelled', finished_at = now() WHERE id = :id",
        run.id,
    )

    assert queue.claim(OWNER, FAKE_ONLY) is None
    assert queue.claim(OWNER, FAKE_ONLY) is not None


def test_reconcile_rechecks_the_lease_after_locking_the_scan(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_scan(queue_seed, world, scannable)
    lease = _claimed(queue)
    _expire(queue_seed, lease.run_id)
    _change_before_lock(
        monkeypatch,
        queue_seed,
        "UPDATE scanner_runs SET lease_expires_at = now() + interval '1 minute' WHERE id = :id",
        lease.run_id,
    )

    assert queue.reconcile_expired(FAKE_ONLY) == 0
    assert _run(queue_seed, lease.run_id).status == "preparing"


def test_reconcile_handles_a_bounded_number_of_runs_per_call(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(queue_module, "MAX_RECONCILED_PER_CALL", 1)
    for target in (scannable, queue_seed.scannable(world)):
        _fake_scan(queue_seed, world, target)
        _expire(queue_seed, _claimed(queue).run_id)

    assert queue.reconcile_expired(FAKE_ONLY) == 1
    assert queue.reconcile_expired(FAKE_ONLY) == 1
    assert queue.reconcile_expired(FAKE_ONLY) == 0


def test_prepare_fails_when_the_grant_ips_leave_the_lab(
    queue_engine: Engine, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    """LAB_CIDR 在建立 scan 之後改了：IP 不在目前的 lab 內就不啟動。"""
    _fake_scan(queue_seed, world, scannable)
    elsewhere = ScanQueue(
        sessionmaker(queue_engine, expire_on_commit=False),
        lab=LabNetwork(IPv4Network("10.99.0.0/24")),
        clock=_now,
    )
    lease = _claimed(elsewhere)

    assert elsewhere.prepare(lease) == Progress(R.FAILED, S.FAILED)
    assert _run(queue_seed, lease.run_id).error_code == "SCOPE_OUTSIDE_LAB"


def test_a_lease_of_an_unknown_scan_is_lost(queue: ScanQueue) -> None:
    lease = Lease(run_id=uuid4(), scan_id=uuid4(), engine=ScanEngine.FAKE, owner=OWNER)

    with pytest.raises(LeaseLostError):
        queue.advance(lease, R.COLLECTING)


def test_claiming_without_an_owner_is_a_programming_error(
    queue: ScanQueue, queue_engine: Engine, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    _fake_scan(queue_seed, world, scannable)
    lease = _claimed(queue)
    queue.prepare(lease)
    queue.advance(lease, R.COLLECTING)
    queue.advance(lease, R.COLLECTED)

    with Session(queue_engine) as session, session.begin():
        progress = ScanProgress(session)
        scan = progress.lock_scan(lease.scan_id)
        run = progress.run(lease.run_id)
        assert scan is not None
        assert run is not None
        with pytest.raises(ValueError, match="lease_owner"):
            progress.move(scan, run, R.NORMALIZING)


def test_a_claim_skips_a_scan_locked_by_another_worker_without_waiting(
    queue: ScanQueue,
    queue_engine: Engine,
    queue_database: ProvisionedDatabase,
    world: World,
    scannable: Scannable,
) -> None:
    """worker 正在解析前一個引擎（持有 scan 的鎖，沒有鎖下一個 run）：runner 認領下一個引擎時
    跳過這個 scan、不等待（鎖的是 scan，不是 run；突變檢查找到）。"""
    _engine_scan(queue_engine, world, scannable, (ScanEngine.ZAP, ScanEngine.NUCLEI))
    zap = _claimed(queue, engines=EVERY_ENGINE)
    queue.prepare(zap)
    queue.advance(zap, R.COLLECTING)
    queue.advance(zap, R.COLLECTED)
    race = Race(
        queue_database,
        RACER,
        lambda session: QueueOperations(session, lab=LAB).claim(OTHER_OWNER, EVERY_ENGINE),
    )

    with Session(queue_engine, expire_on_commit=False) as holder, holder.begin():
        parsing = QueueOperations(holder, lab=LAB).claim_collected(OWNER, EVERY_ENGINE)
        assert parsing is not None
        race.start()
        race.join()

    assert (race.errors, race.results) == ([], [None])
    nuclei = _claimed(queue, OTHER_OWNER, EVERY_ENGINE)
    assert nuclei.engine is ScanEngine.NUCLEI
