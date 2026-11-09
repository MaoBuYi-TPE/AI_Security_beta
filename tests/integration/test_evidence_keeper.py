"""keeper 對真的 DB 與檔案的行為（EVID-01、EVID-02、EVID-04、EVID-05、EVID-07、RET-01；
docs/DECISIONS.md §30.3、§30.5）。

- 每一種終止狀態都會加密（含沒有收集、沒有 manifest 的殘留）；還在執行、容器還沒確認刪除的不加密；
  從來沒有目錄的記為 none。
- 等待解析逾期：從第一次 collected 起算；collected 或 lease 過期的 normalizing → failed 並加密；
  有效 lease 的解析不受影響；worker 舊 lease 的寫入被拒。
- 保留期限到了才清除；時間由 keeper 的 clock 注入。
每個測試用自己的資料庫（queue_database）與暫存的 runs 目錄。
"""

import os
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from secscan.main import create_app
from secscan.runner.evidence import SEALED_DIR, EvidenceVault
from secscan.runner.keeper import EvidenceKeeper, KeeperSettings, PassReport
from secscan.runner.plans import ENGINE_IMAGES
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.domain.model import Lease
from secscan.scans.evidence_records import EvidenceRun, EvidenceStore
from secscan.scans.queue import LeaseLostError, RunUsage, ScanQueue
from secscan.scans.service import ScanService
from tests.integration.api_support import LAB, Scannable, Seeder, World
from tests.integration.database import ProvisionedDatabase
from tests.secret_support import shared_evidence_cipher

pytestmark = pytest.mark.integration

OWNER = "runner-evidence-test"
WORKER = "worker-evidence-test"
FAKE = frozenset({ScanEngine.FAKE})
CANARY = b"canary-evidence-keeper-7d2a"
FAKE_IMAGE = str(ENGINE_IMAGES[ScanEngine.FAKE])


@dataclass
class Moment:
    now: datetime


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


@pytest.fixture
def runs(tmp_path: Path) -> Path:
    directory = tmp_path / "runs"
    directory.mkdir()
    return directory


@pytest.fixture
def moment() -> Moment:
    return Moment(datetime.now(UTC))


@pytest.fixture
def store(queue_engine: Engine) -> EvidenceStore:
    return EvidenceStore(sessionmaker(queue_engine, expire_on_commit=False), engine=queue_engine)


@pytest.fixture
def keeper(store: EvidenceStore, runs: Path, moment: Moment) -> EvidenceKeeper:
    return EvidenceKeeper(
        store,
        EvidenceVault(runs, shared_evidence_cipher()),
        KeeperSettings(retention_days=7, plaintext_max_minutes=60),
        clock=lambda: moment.now,
    )


def _claim(queue: ScanQueue, seed: Seeder, world: World, scannable: Scannable) -> Lease:
    seed.scan(world.operator_a, scannable)
    lease = queue.claim(OWNER, FAKE)
    assert lease is not None
    return lease


def _directory(runs: Path, run_id: UUID, *, manifest: bool = True) -> Path:
    root = runs / str(run_id)
    (root / "in").mkdir(parents=True)
    (root / "out").mkdir()
    (root / "in" / "plan.json").write_bytes(b'{"plan": 1}')
    (root / "out" / "report.json").write_bytes(b'{"evidence": "' + CANARY + b'"}')
    if manifest:
        (root / "manifest.json").write_bytes(b'{"files": []}')
    return root


def _collected(queue: ScanQueue, lease: Lease) -> None:
    queue.prepare(lease)
    queue.advance(lease, RunStatus.COLLECTING)
    queue.advance(lease, RunStatus.COLLECTED)


def _evidence(seed: Seeder, run_id: UUID) -> Any:
    rows = seed.query("SELECT * FROM run_evidence WHERE scanner_run_id = :id", id=run_id)
    return rows[0] if rows else None


def _status(seed: Seeder, run_id: UUID) -> tuple[str, str | None]:
    [row] = seed.query("SELECT status, error_code FROM scanner_runs WHERE id = :id", id=run_id)
    return row.status, row.error_code


def _sealed_only(root: Path) -> None:
    assert {entry.name for entry in root.iterdir()} == {SEALED_DIR}
    for directory, _names, files in os.walk(root):
        for name in files:
            assert CANARY not in (Path(directory) / name).read_bytes()


def _cancel(engine: Engine, world: World, scan_id: UUID) -> None:
    with Session(engine, expire_on_commit=False) as session, session.begin():
        ScanService(session, lab=LAB).cancel(
            world.operator_a.principal, scan_id, request_id="req-evidence-cancel"
        )


# --- 加密的時機（EVID-01）-------------------------------------------------------------------------


def _finish_failed(queue: ScanQueue, lease: Lease) -> None:
    queue.prepare(lease)
    queue.advance(lease, RunStatus.FAILED, error_code=RunErrorCode.ENGINE_FAILED)


def _finish_timed_out(queue: ScanQueue, lease: Lease) -> None:
    queue.prepare(lease)
    queue.advance(lease, RunStatus.TIMED_OUT, error_code=RunErrorCode.TIME_LIMIT_EXCEEDED)


def _finish_interrupted(queue: ScanQueue, lease: Lease) -> None:
    queue.prepare(lease)
    queue.advance(lease, RunStatus.INTERRUPTED, error_code=RunErrorCode.RUNNER_STOPPED)


def _finish_succeeded(queue: ScanQueue, lease: Lease) -> None:
    _collected(queue, lease)
    parsing = queue.claim_collected(WORKER, FAKE, run_id=lease.run_id)
    assert parsing is not None
    queue.advance(parsing, RunStatus.SUCCEEDED)


FINISHERS: dict[str, Callable[[ScanQueue, Lease], None]] = {
    "failed": _finish_failed,
    "timed_out": _finish_timed_out,
    "interrupted": _finish_interrupted,
    "succeeded": _finish_succeeded,
}


@pytest.mark.parametrize("status", sorted(FINISHERS))
@pytest.mark.parametrize("manifest", [True, False])
def test_every_finished_run_is_sealed(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    runs: Path,
    keeper: EvidenceKeeper,
    status: str,
    manifest: bool,
) -> None:
    lease = _claim(queue, queue_seed, world, scannable)
    root = _directory(runs, lease.run_id, manifest=manifest)
    FINISHERS[status](queue, lease)

    report = keeper.run_pass()

    assert report.clean
    assert report.sealed == 1
    row = _evidence(queue_seed, lease.run_id)
    assert (row.status, row.file_count) == ("sealed", 3 if manifest else 2)
    assert row.sealed_at is not None
    assert row.purged_at is None
    _sealed_only(root)
    assert keeper.healthy


def test_a_cancelled_run_is_sealed_and_one_without_a_directory_is_none(
    queue: ScanQueue,
    queue_seed: Seeder,
    queue_engine: Engine,
    world: World,
    scannable: Scannable,
    runs: Path,
    keeper: EvidenceKeeper,
) -> None:
    started = _claim(queue, queue_seed, world, scannable)
    root = _directory(runs, started.run_id)
    queue.prepare(started)
    _cancel(queue_engine, world, started.scan_id)
    queue.advance(started, RunStatus.CANCELLING)
    queue.advance(started, RunStatus.CANCELLED)
    never = queue_seed.scan(world.operator_a, scannable)
    _cancel(queue_engine, world, never.id)
    [never_run] = queue_seed.query("SELECT id FROM scanner_runs WHERE scan_id = :id", id=never.id)

    report = keeper.run_pass()

    assert (report.sealed, report.none) == (1, 1)
    assert _evidence(queue_seed, started.run_id).status == "sealed"
    assert _evidence(queue_seed, never_run.id).status == "none"
    _sealed_only(root)


def test_unfinished_runs_are_left_alone(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    runs: Path,
    keeper: EvidenceKeeper,
) -> None:
    running = _claim(queue, queue_seed, world, scannable)
    queue.prepare(running)
    collected = _claim(queue, queue_seed, world, queue_seed.scannable(world))
    _collected(queue, collected)
    roots = [_directory(runs, lease.run_id) for lease in (running, collected)]

    keeper.run_pass()

    for lease, root in zip((running, collected), roots, strict=True):
        assert _evidence(queue_seed, lease.run_id) is None
        assert (root / "out" / "report.json").read_bytes().count(CANARY) == 1


def test_a_run_waits_until_its_container_is_confirmed_removed(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    runs: Path,
    keeper: EvidenceKeeper,
) -> None:
    lease = _claim(queue, queue_seed, world, scannable)
    queue.prepare_launch(lease, image_ref=FAKE_IMAGE)
    root = _directory(runs, lease.run_id)
    queue.advance(lease, RunStatus.FAILED, error_code=RunErrorCode.ENGINE_FAILED)

    keeper.run_pass()
    assert _evidence(queue_seed, lease.run_id) is None
    assert (root / "out" / "report.json").exists()

    assert queue.settle_container(lease.run_id)
    keeper.run_pass()

    assert _evidence(queue_seed, lease.run_id).status == "sealed"
    _sealed_only(root)


def test_a_run_whose_usage_recorded_removal_is_sealed(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    runs: Path,
    keeper: EvidenceKeeper,
) -> None:
    lease = _claim(queue, queue_seed, world, scannable)
    queue.prepare_launch(lease, image_ref=FAKE_IMAGE)
    root = _directory(runs, lease.run_id)
    queue.record_usage(lease, RunUsage(0, 0, 0), container_removed=True)
    queue.advance(lease, RunStatus.FAILED, error_code=RunErrorCode.ENGINE_FAILED)

    keeper.run_pass()

    assert _evidence(queue_seed, lease.run_id).status == "sealed"
    _sealed_only(root)


# --- 失敗時保留明文（EVID-02）---------------------------------------------------------------------


def test_a_failure_keeps_the_plaintext_records_nothing_and_recovers(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    runs: Path,
    keeper: EvidenceKeeper,
) -> None:
    lease = _claim(queue, queue_seed, world, scannable)
    root = _directory(runs, lease.run_id)
    _finish_failed(queue, lease)
    (root / "out").chmod(0o500)
    try:
        report = keeper.run_pass()
        assert report.failures == 1
        assert keeper.healthy is False
        assert _evidence(queue_seed, lease.run_id) is None
        assert CANARY in (root / "out" / "report.json").read_bytes()
    finally:
        (root / "out").chmod(0o700)

    keeper.run_pass()

    assert keeper.healthy is True
    assert _evidence(queue_seed, lease.run_id).status == "sealed"
    _sealed_only(root)


# --- 等待解析逾期（EVID-04）-----------------------------------------------------------------------


def test_a_run_waiting_too_long_fails_and_is_sealed(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    runs: Path,
    keeper: EvidenceKeeper,
    moment: Moment,
) -> None:
    lease = _claim(queue, queue_seed, world, scannable)
    root = _directory(runs, lease.run_id)
    _collected(queue, lease)
    keeper.run_pass()
    assert _status(queue_seed, lease.run_id) == ("collected", None)

    moment.now += timedelta(minutes=61)
    report = keeper.run_pass()

    assert report.expired == 1
    assert _status(queue_seed, lease.run_id) == ("failed", "PARSE_DEADLINE_EXCEEDED")
    [scan] = queue_seed.query("SELECT status FROM scans WHERE id = :id", id=lease.scan_id)
    assert scan.status == "failed"
    assert _evidence(queue_seed, lease.run_id).status == "sealed"
    _sealed_only(root)


def _parsing(queue: ScanQueue, seed: Seeder, lease: Lease, *, expired: bool) -> Lease:
    parsing = queue.claim_collected(WORKER, FAKE, run_id=lease.run_id)
    assert parsing is not None
    if expired:
        seed.execute(
            "UPDATE scanner_runs SET lease_expires_at = now() - interval '1 second' WHERE id = :id",
            id=lease.run_id,
        )
    return parsing


def test_a_live_parse_is_not_interrupted(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    keeper: EvidenceKeeper,
    moment: Moment,
) -> None:
    lease = _claim(queue, queue_seed, world, scannable)
    _collected(queue, lease)
    _parsing(queue, queue_seed, lease, expired=False)
    moment.now += timedelta(minutes=120)

    keeper.run_pass()

    assert _status(queue_seed, lease.run_id) == ("normalizing", None)


def test_an_abandoned_parse_fails_and_the_stale_worker_cannot_write(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    keeper: EvidenceKeeper,
    moment: Moment,
) -> None:
    lease = _claim(queue, queue_seed, world, scannable)
    _collected(queue, lease)
    stale = _parsing(queue, queue_seed, lease, expired=True)
    moment.now += timedelta(minutes=61)

    keeper.run_pass()

    assert _status(queue_seed, lease.run_id) == ("failed", "PARSE_DEADLINE_EXCEEDED")
    with pytest.raises(LeaseLostError):
        queue.advance(stale, RunStatus.SUCCEEDED)


def test_the_deadline_counts_from_the_first_collection(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    keeper: EvidenceKeeper,
    moment: Moment,
) -> None:
    """重試會再進入 collected；期限仍從第一次算起，否則反覆失敗的解析能無限期延長明文。"""
    lease = _claim(queue, queue_seed, world, scannable)
    _collected(queue, lease)
    _parsing(queue, queue_seed, lease, expired=True)
    assert queue.reconcile_expired_parsing(FAKE) == 1
    assert _status(queue_seed, lease.run_id) == ("collected", None)
    first, last = (
        row.created_at
        for row in queue_seed.query(
            "SELECT created_at FROM scan_events WHERE scanner_run_id = :id "
            "AND payload->>'status' = 'collected' ORDER BY sequence",
            id=lease.run_id,
        )
    )
    assert last > first
    # 期限的時間點落在兩次 collected 之間：以第一次起算才逾期。
    moment.now = first + timedelta(minutes=60) + (last - first) / 2

    keeper.run_pass()

    assert _status(queue_seed, lease.run_id) == ("failed", "PARSE_DEADLINE_EXCEEDED")


def test_expiry_rechecks_after_locking(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    store: EvidenceStore,
    moment: Moment,
) -> None:
    """選出之後 worker 搶先認領（lease 有效）：鎖住之後條件不成立，不轉換。"""
    lease = _claim(queue, queue_seed, world, scannable)
    _collected(queue, lease)
    later = moment.now + timedelta(minutes=61)
    [candidate] = store.overdue(now=later, max_minutes=60, limit=10)
    assert candidate == EvidenceRun(lease.run_id, lease.scan_id)

    _parsing(queue, queue_seed, lease, expired=False)

    assert store.expire(candidate, now=later, max_minutes=60) is False
    assert _status(queue_seed, lease.run_id) == ("normalizing", None)


# --- 保留期限（RET-01）與孤兒目錄 -----------------------------------------------------------------


def test_sealed_directories_are_purged_only_after_retention(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    runs: Path,
    keeper: EvidenceKeeper,
    moment: Moment,
) -> None:
    lease = _claim(queue, queue_seed, world, scannable)
    root = _directory(runs, lease.run_id)
    _finish_failed(queue, lease)
    keeper.run_pass()
    sealed_at = _evidence(queue_seed, lease.run_id).sealed_at

    moment.now = sealed_at + timedelta(days=7) - timedelta(minutes=1)
    keeper.run_pass()
    assert _evidence(queue_seed, lease.run_id).status == "sealed"
    assert root.exists()

    moment.now = sealed_at + timedelta(days=7, minutes=1)
    report = keeper.run_pass()

    assert report.purged == 1
    row = _evidence(queue_seed, lease.run_id)
    assert (row.status, row.file_count) == ("purged", 3)
    assert row.purged_at >= sealed_at
    assert not root.exists()


def test_orphan_directories_are_sealed_then_purged(
    runs: Path, keeper: EvidenceKeeper, moment: Moment
) -> None:
    name = str(uuid4())
    root = runs / name
    (root / "out").mkdir(parents=True)
    (root / "out" / "probe.json").write_bytes(CANARY)

    keeper.run_pass()
    assert (root / "out" / "probe.json").exists()

    moment.now += timedelta(hours=2)
    keeper.run_pass()
    _sealed_only(root)

    moment.now += timedelta(days=8)
    keeper.run_pass()
    assert not root.exists()


# --- API（EVID-07）-------------------------------------------------------------------------------


@pytest.fixture
def client(queue_database: ProvisionedDatabase) -> Iterator[TestClient]:
    with TestClient(create_app(queue_database.app_settings())) as opened:
        yield opened


def _shown(client: TestClient, world: World, scan_id: UUID) -> dict[str, Any]:
    response = client.get(f"/api/v1/scans/{scan_id}", headers=world.operator_a.headers)
    assert response.status_code == 200, response.text
    [engine] = response.json()["data"]["engines"]
    evidence: dict[str, Any] = engine["evidence"]
    return evidence


def test_the_api_shows_pending_sealed_and_purged(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    runs: Path,
    keeper: EvidenceKeeper,
    moment: Moment,
    client: TestClient,
) -> None:
    lease = _claim(queue, queue_seed, world, scannable)
    _directory(runs, lease.run_id)
    _finish_failed(queue, lease)
    assert _shown(client, world, lease.scan_id) == {
        "status": "pending",
        "sealed_at": None,
        "purged_at": None,
    }

    keeper.run_pass()
    sealed = _shown(client, world, lease.scan_id)
    assert sealed["status"] == "sealed"
    assert sealed["sealed_at"].endswith("Z")
    assert sealed["purged_at"] is None

    moment.now += timedelta(days=8)
    keeper.run_pass()
    purged = _shown(client, world, lease.scan_id)
    assert purged["status"] == "purged"
    assert purged["purged_at"].endswith("Z")


def test_a_failing_seal_stays_pending_in_the_api(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    runs: Path,
    keeper: EvidenceKeeper,
    client: TestClient,
) -> None:
    lease = _claim(queue, queue_seed, world, scannable)
    root = _directory(runs, lease.run_id)
    _finish_failed(queue, lease)
    root.chmod(0o500)
    try:
        report: PassReport = keeper.run_pass()
    finally:
        root.chmod(0o700)

    assert report.failures == 1
    assert _shown(client, world, lease.scan_id)["status"] == "pending"
