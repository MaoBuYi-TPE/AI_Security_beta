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
from sqlalchemy.orm import Session, sessionmaker

from secscan.auth_profiles.domain.credentials import SecretValue
from secscan.auth_profiles.domain.model import AuthProfile, ChangeInput
from secscan.auth_profiles.service import AuthProfileService
from secscan.grants.service import ScopeGrantService
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus, ScanStatus
from secscan.scans.domain.model import Lease
from secscan.scans.queue import Launch, Progress, QueueOperations, ScanQueue
from tests.integration.api_support import DEFAULT_SECRET, LAB, Scannable, Seeder, World
from tests.integration.database import ProvisionedDatabase
from tests.integration.locks import Race, wait_until_waiting_for_a_lock
from tests.secret_support import shared_cipher

pytestmark = pytest.mark.integration

OWNER = "runner-launch-1"
FAKE = frozenset({ScanEngine.FAKE})
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


def _claimed(queue: ScanQueue) -> Lease:
    lease = queue.claim(OWNER, FAKE)
    assert lease is not None
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
    scan = queue_seed.scan(world.operator_a, scannable)
    lease = _claimed(queue)

    launch = queue.prepare_launch(lease, image_ref=IMAGE)

    assert launch.progress == Progress(R.RUNNING, S.RUNNING)
    assert launch.max_duration_seconds == scan.budget.max_duration_seconds
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
    queue_seed.scan(world.operator_a, scannable)
    lease = _claimed(queue)
    with Session(queue_engine, expire_on_commit=False) as session, session.begin():
        _patch(world, scannable.profile)(session)

    launch = queue.prepare_launch(lease, image_ref=IMAGE)

    assert launch.progress == Progress(R.FAILED, S.FAILED)
    assert launch.secret is None
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
    queue_seed.scan(world.operator_a, scannable)
    lease = _claimed(queue)
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
