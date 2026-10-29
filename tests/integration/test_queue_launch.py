"""容器版 runner 的 prepare（docs/DECISIONS.md §14.5、§14.6）與分階段的對帳。

- prepare_launch：檢查通過時，在移到 running 的同一個 transaction 中記下容器與映像，並以 FOR SHARE
  讀出綁定版本的密文（T09 的交接：PATCH 清除密文要等這個 transaction 結束）。
- 有容器的 run，lease 過期不代表容器已停止：runner 階段的對帳不碰它（T13）。
每個測試用自己的資料庫（queue_database）。
"""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import Engine, Row
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from secscan.auth_profiles.domain.credentials import SecretValue
from secscan.auth_profiles.domain.model import AuthProfile, ChangeInput
from secscan.auth_profiles.service import AuthProfileService
from secscan.grants.service import ScopeGrantService
from secscan.guard.domain.budget import RunBudget
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus, ScanStatus
from secscan.scans.domain.model import Lease
from secscan.scans.queue import (
    EgressScope,
    Launch,
    LeaseLostError,
    Progress,
    QueueOperations,
    RunUsage,
    ScanQueue,
)
from tests.integration.api_support import DEFAULT_SECRET, LAB, Scannable, Seeder, World
from tests.integration.database import ProvisionedDatabase
from tests.integration.locks import Race, wait_until_waiting_for_a_lock
from tests.secret_support import shared_cipher

pytestmark = pytest.mark.integration

OWNER = "runner-launch-1"
FAKE = frozenset({ScanEngine.FAKE})
PREFLIGHT = frozenset({ScanEngine.PREFLIGHT})
IMAGE = "busybox:1.38.0@sha256:" + "ab" * 32
RACER = "secscan-launch-racer"
R = RunStatus
S = ScanStatus


def _now() -> datetime:
    return datetime.now(UTC)


@pytest.fixture
def queue(queue_engine: Engine) -> ScanQueue:
    return ScanQueue(sessionmaker(queue_engine, expire_on_commit=False), lab=LAB, clock=_now)


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


@pytest.fixture
def scannable(queue_seed: Seeder, world: World) -> Scannable:
    return queue_seed.scannable(world)


def _claimed(queue: ScanQueue, engines: frozenset[ScanEngine] = FAKE) -> Lease:
    lease = queue.claim(OWNER, engines)
    assert lease is not None
    return lease


def _preflight(queue: ScanQueue, seed: Seeder, world: World, scannable: Scannable) -> Lease:
    """綁定 auth profile 的 scan：第一個 run 是 preflight（docs/DECISIONS.md §16.5）。"""
    seed.scan(world.operator_a, scannable, auth_profile_id=scannable.profile.id)
    lease = _claimed(queue, PREFLIGHT)
    assert lease.engine is ScanEngine.PREFLIGHT
    return lease


def _run(seed: Seeder, run_id: UUID) -> Row[Any]:
    [row] = seed.query(
        "SELECT status, error_code, container_name, image_ref, lease_owner FROM scanner_runs "
        "WHERE id = :id",
        id=run_id,
    )
    return row


def _expire(seed: Seeder, run_id: UUID) -> None:
    seed.execute(
        "UPDATE scanner_runs SET lease_expires_at = now() - interval '1 second' WHERE id = :id",
        id=run_id,
    )


def test_launch_records_the_container_and_returns_the_sealed_secret(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    lease = _preflight(queue, queue_seed, world, scannable)

    launch = queue.prepare_launch(lease, image_ref=IMAGE)

    assert launch.progress == Progress(R.RUNNING, S.RUNNING)
    assert launch.preflight == scannable.profile.current.definition.preflight
    assert launch.secret is not None
    assert launch.secret.profile_id == scannable.profile.id
    assert shared_cipher().reveal(launch.secret.token, context=launch.secret.context) == (
        DEFAULT_SECRET
    )
    assert DEFAULT_SECRET not in repr(launch)
    run = _run(queue_seed, lease.run_id)
    assert (run.status, run.container_name, run.image_ref) == (
        "running",
        f"secscan-run-{lease.run_id}",
        IMAGE,
    )


def test_launch_carries_the_grant_scope_for_the_guard(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    """gate 剛以 FOR SHARE 確認過的 grant：guard 的 policy 以它產生（docs/DECISIONS.md §15.7）。"""
    lease = _preflight(queue, queue_seed, world, scannable)
    [scan] = queue_seed.query("SELECT requests_per_second, max_requests FROM scans")

    launch = queue.prepare_launch(lease, image_ref=IMAGE)

    assert launch.egress == EgressScope(
        origin=scannable.target.origin,
        scope=scannable.grant.scope,
        valid_until=scannable.grant.window.valid_until,
        budget=RunBudget(
            requests_per_second=scan.requests_per_second, burst=1, max_requests=scan.max_requests
        ),
        auth_header="authorization",  # 預設的 profile 是 bearer
    )


def test_anonymous_scans_tell_the_guard_there_is_no_auth_header(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    queue_seed.scan(world.operator_a, scannable, auth_profile_id=None)
    lease = _claimed(queue)

    launch = queue.prepare_launch(lease, image_ref=IMAGE)

    assert launch.egress is not None
    assert launch.egress.auth_header is None


def test_an_anonymous_scan_has_no_secret(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    queue_seed.scan(world.operator_a, scannable, auth_profile_id=None)
    lease = _claimed(queue)

    launch = queue.prepare_launch(lease, image_ref=IMAGE)

    assert launch.progress.run_status is R.RUNNING
    assert launch.secret is None


def test_a_cancelled_scan_gets_no_container(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    scan = queue_seed.scan(world.operator_a, scannable)
    lease = _claimed(queue)
    queue_seed.execute("UPDATE scans SET cancel_requested_at = now() WHERE id = :id", id=scan.id)

    launch = queue.prepare_launch(lease, image_ref=IMAGE)

    assert launch == Launch(Progress(R.CANCELLING, S.CANCELLING), launch.max_duration_seconds, None)
    assert launch.egress is None
    assert _run(queue_seed, lease.run_id).container_name is None


def test_a_refused_gate_gets_no_container_nor_secret(
    queue: ScanQueue, queue_engine: Engine, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    lease = _claimed(queue)
    with Session(queue_engine, expire_on_commit=False) as session, session.begin():
        ScopeGrantService(session, lab=LAB).revoke(
            world.admin.principal, scannable.grant.id, reason="停止", now=_now(), request_id=None
        )

    launch = queue.prepare_launch(lease, image_ref=IMAGE)

    assert launch.progress == Progress(R.FAILED, S.FAILED)
    assert launch.secret is None
    assert launch.egress is None
    run = _run(queue_seed, lease.run_id)
    assert (run.error_code, run.container_name, run.image_ref) == ("SCOPE_REVOKED", None, None)


def _patch(world: World, profile: AuthProfile) -> Callable[[Session], AuthProfile]:
    def work(session: Session) -> AuthProfile:
        return AuthProfileService(session, cipher=shared_cipher()).update(
            world.operator_a.principal,
            profile.id,
            ChangeInput(secret=SecretValue("second-secret-value")),
            request_id=None,
        )

    return work


def test_a_superseded_version_gets_no_secret(
    queue: ScanQueue, queue_engine: Engine, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    lease = _preflight(queue, queue_seed, world, scannable)
    with Session(queue_engine, expire_on_commit=False) as session, session.begin():
        _patch(world, scannable.profile)(session)

    launch = queue.prepare_launch(lease, image_ref=IMAGE)

    # 之後的 fake run 還在排隊（它自己的 prepare 也會因同樣的原因失敗）。
    assert launch.progress == Progress(R.FAILED, S.RUNNING)
    assert launch.secret is None
    assert launch.egress is None
    assert _run(queue_seed, lease.run_id).error_code == RunErrorCode.AUTH_PROFILE_SUPERSEDED


def test_a_patch_waits_until_the_secret_is_read(
    queue_engine: Engine,
    queue_database: ProvisionedDatabase,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    queue: ScanQueue,
) -> None:
    """prepare_launch 以 FOR SHARE 讀密文：PATCH 的清除等它 commit，讀到的一定是還沒清除的密文。"""
    lease = _preflight(queue, queue_seed, world, scannable)
    race = Race(queue_database, RACER, _patch(world, scannable.profile))
    with Session(queue_engine, expire_on_commit=False) as holder, holder.begin():
        launch = QueueOperations(holder, lab=LAB).prepare_launch(lease, clock=_now, image_ref=IMAGE)
        race.start()
        wait_until_waiting_for_a_lock(queue_seed, RACER)
    race.join()

    assert race.errors == []
    assert launch.secret is not None
    assert shared_cipher().reveal(launch.secret.token, context=launch.secret.context) == (
        DEFAULT_SECRET
    )


def test_the_in_process_prepare_records_no_container(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    lease = _claimed(queue)

    assert queue.prepare(lease) == Progress(R.RUNNING, S.RUNNING)
    assert _run(queue_seed, lease.run_id).container_name is None


def test_reconcile_leaves_runs_with_a_container_alone(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    """容器可能還在執行：只因 lease 過期就標成 interrupted，會讓第二個容器同時跑（T13 處理）。"""
    queue_seed.scan(world.operator_a, scannable)
    lease = _claimed(queue)
    queue.prepare_launch(lease, image_ref=IMAGE)
    _expire(queue_seed, lease.run_id)

    assert queue.reconcile_expired(FAKE) == 0
    run = _run(queue_seed, lease.run_id)
    assert (run.status, run.lease_owner) == ("running", OWNER)


def test_the_worker_reconciles_only_parsing(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    running = _claimed(queue)
    queue.prepare(running)
    _expire(queue_seed, running.run_id)
    queue_seed.scan(world.operator_a, queue_seed.scannable(world))
    other = _claimed(queue)
    queue.prepare_launch(other, image_ref=IMAGE)
    queue.advance(other, R.COLLECTING)
    queue.advance(other, R.COLLECTED)
    parsing = queue.claim_collected(OWNER, FAKE)
    assert parsing is not None
    _expire(queue_seed, parsing.run_id)

    assert queue.reconcile_expired_parsing(FAKE) == 1
    assert _run(queue_seed, parsing.run_id).status == "collected"
    assert _run(queue_seed, running.run_id).status == "running"


# --- 共享預算（docs/DECISIONS.md §16.4）------------------------------------------------------


def _usage(seed: Seeder, run_id: UUID) -> Row[Any]:
    [row] = seed.query(
        "SELECT requests_allotted, requests_sent, requests_denied, traffic_seconds "
        "FROM scanner_runs WHERE id = :id",
        id=run_id,
    )
    return row


def test_a_container_run_is_allotted_the_remaining_budget(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    scan = queue_seed.scan(world.operator_a, scannable)
    lease = _claimed(queue)

    launch = queue.prepare_launch(lease, image_ref=IMAGE)

    assert launch.max_duration_seconds == scan.budget.max_duration_seconds
    assert launch.egress is not None
    assert launch.egress.budget.max_requests == scan.budget.max_requests
    assert _usage(queue_seed, lease.run_id).requests_allotted == scan.budget.max_requests


def test_in_process_runs_send_nothing_and_are_allotted_nothing(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    lease = _claimed(queue)

    queue.prepare(lease)

    assert _usage(queue_seed, lease.run_id).requests_allotted is None


def test_usage_is_recorded_before_the_run_ends(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    lease = _claimed(queue)
    queue.prepare_launch(lease, image_ref=IMAGE)

    queue.record_usage(lease, RunUsage(requests_sent=7, requests_denied=2, traffic_seconds=31))
    queue.advance(lease, R.TIMED_OUT, error_code=RunErrorCode.BUDGET_EXHAUSTED)

    row = _usage(queue_seed, lease.run_id)
    assert (row.requests_sent, row.requests_denied, row.traffic_seconds) == (7, 2, 31)


def test_unknown_usage_is_left_empty(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    lease = _claimed(queue)
    queue.prepare_launch(lease, image_ref=IMAGE)

    queue.record_usage(lease, RunUsage(requests_sent=None, requests_denied=None, traffic_seconds=4))

    row = _usage(queue_seed, lease.run_id)
    assert (row.requests_sent, row.requests_denied, row.traffic_seconds) == (None, None, 4)


def test_usage_needs_the_lease(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    lease = _claimed(queue)
    queue.prepare_launch(lease, image_ref=IMAGE)
    _expire(queue_seed, lease.run_id)

    with pytest.raises(LeaseLostError):
        queue.record_usage(lease, RunUsage(requests_sent=1, requests_denied=0, traffic_seconds=1))


def test_the_database_refuses_usage_beyond_the_allotment(
    queue: ScanQueue, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    scan = queue_seed.scan(world.operator_a, scannable)
    lease = _claimed(queue)
    queue.prepare_launch(lease, image_ref=IMAGE)
    too_many = scan.budget.max_requests + 1

    with pytest.raises(IntegrityError, match="sent_within_allotment"):
        queue.record_usage(
            lease, RunUsage(requests_sent=too_many, requests_denied=0, traffic_seconds=1)
        )
