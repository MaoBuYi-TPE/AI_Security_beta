"""migration 0021：run_evidence 的 CHECK 與 trigger（RET-02；docs/DECISIONS.md §30.3）。

- 新增：只能是 none 或 sealed，run 必須已終止而且沒有容器或容器已確認刪除；每個 run 只有一列。
- 修改：只允許 sealed → purged 一次，其他欄位不變；刪除與 TRUNCATE 一律拒絕。
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from secscan.runner.plans import ENGINE_IMAGES
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.domain.model import Lease
from secscan.scans.queue import ScanQueue
from tests.integration.api_support import LAB, Seeder
from tests.integration.sql_support import (
    CHECK_VIOLATION,
    INTEGRITY_CONSTRAINT_VIOLATION,
    UNIQUE_VIOLATION,
    violation,
)

pytestmark = pytest.mark.integration

FAKE = frozenset({ScanEngine.FAKE})
INSERT = (
    "INSERT INTO run_evidence (scanner_run_id, scan_id, status, file_count, plaintext_bytes, "
    "sealed_at, purged_at) VALUES (:run, :scan, :status, :files, :bytes, :sealed, :purged)"
)
SEALED_AT = datetime(2026, 1, 1, tzinfo=UTC)
PURGED_AT = datetime(2026, 1, 8, tzinfo=UTC)


@pytest.fixture
def queue(queue_engine: Engine) -> ScanQueue:
    return ScanQueue(
        sessionmaker(queue_engine, expire_on_commit=False), lab=LAB, clock=lambda: datetime.now(UTC)
    )


def _lease(queue: ScanQueue, seed: Seeder) -> Lease:
    world = seed.world()
    seed.scan(world.operator_a, seed.scannable(world))
    lease = queue.claim("runner-schema", FAKE)
    assert lease is not None
    return lease


def _finished(queue: ScanQueue, seed: Seeder) -> Lease:
    lease = _lease(queue, seed)
    queue.prepare(lease)
    queue.advance(lease, RunStatus.FAILED, error_code=RunErrorCode.ENGINE_FAILED)
    return lease


def _params(lease: Lease, **overrides: object) -> dict[str, object]:
    params: dict[str, object] = {
        "run": lease.run_id,
        "scan": lease.scan_id,
        "status": "sealed",
        "files": 2,
        "bytes": 10,
        "sealed": SEALED_AT,
        "purged": None,
    }
    params.update(overrides)
    return params


def _code(engine: Engine, statement: str, params: dict[str, object]) -> str | None:
    with Session(engine) as session:
        return violation(session, statement, params).sqlstate


def _insert(engine: Engine, params: dict[str, object]) -> None:
    with Session(engine) as session, session.begin():
        session.execute(text(INSERT), params)


def test_only_finished_runs_without_live_containers_get_a_record(
    queue: ScanQueue, queue_seed: Seeder, queue_engine: Engine
) -> None:
    queued = _lease(queue, queue_seed)
    assert _code(queue_engine, INSERT, _params(queued)) == INTEGRITY_CONSTRAINT_VIOLATION

    launched = _lease(queue, queue_seed)
    queue.prepare_launch(launched, image_ref=str(ENGINE_IMAGES[ScanEngine.FAKE]))
    queue.advance(launched, RunStatus.FAILED, error_code=RunErrorCode.ENGINE_FAILED)
    assert _code(queue_engine, INSERT, _params(launched)) == INTEGRITY_CONSTRAINT_VIOLATION
    assert queue.settle_container(launched.run_id)
    _insert(queue_engine, _params(launched))


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"status": "purged", "purged": PURGED_AT}, INTEGRITY_CONSTRAINT_VIOLATION),
        ({"status": "pending"}, INTEGRITY_CONSTRAINT_VIOLATION),
        ({"status": "none", "sealed": None, "files": 1}, CHECK_VIOLATION),
        ({"status": "none"}, CHECK_VIOLATION),
        ({"sealed": None}, CHECK_VIOLATION),
        ({"files": -1}, CHECK_VIOLATION),
        ({"purged": PURGED_AT}, INTEGRITY_CONSTRAINT_VIOLATION),
    ],
)
def test_new_records_must_be_consistent(
    queue: ScanQueue,
    queue_seed: Seeder,
    queue_engine: Engine,
    overrides: dict[str, object],
    code: str,
) -> None:
    lease = _finished(queue, queue_seed)

    assert _code(queue_engine, INSERT, _params(lease, **overrides)) == code


def test_a_run_has_one_record(queue: ScanQueue, queue_seed: Seeder, queue_engine: Engine) -> None:
    lease = _finished(queue, queue_seed)
    _insert(queue_engine, _params(lease, status="none", sealed=None, files=0, bytes=0))

    assert _code(queue_engine, INSERT, _params(lease)) == UNIQUE_VIOLATION


PURGE = "UPDATE run_evidence SET status = 'purged', purged_at = :at WHERE scanner_run_id = :run"


def _sealed(queue: ScanQueue, seed: Seeder, engine: Engine) -> Lease:
    lease = _finished(queue, seed)
    _insert(engine, _params(lease))
    return lease


def _purge(engine: Engine, run_id: UUID, at: datetime = PURGED_AT) -> None:
    with Session(engine) as session, session.begin():
        session.execute(text(PURGE), {"run": run_id, "at": at})


def test_a_sealed_record_can_be_purged_once(
    queue: ScanQueue, queue_seed: Seeder, queue_engine: Engine
) -> None:
    lease = _sealed(queue, queue_seed, queue_engine)
    _purge(queue_engine, lease.run_id)

    params = {"run": lease.run_id, "at": datetime(2026, 2, 1, tzinfo=UTC)}
    assert _code(queue_engine, PURGE, params) == INTEGRITY_CONSTRAINT_VIOLATION
    back = "UPDATE run_evidence SET status = 'sealed', purged_at = NULL WHERE scanner_run_id = :run"
    assert _code(queue_engine, back, {"run": lease.run_id}) == INTEGRITY_CONSTRAINT_VIOLATION


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE run_evidence SET file_count = 9 WHERE scanner_run_id = :run",
        "UPDATE run_evidence SET sealed_at = now() WHERE scanner_run_id = :run",
        "UPDATE run_evidence SET status = 'purged', purged_at = now(), file_count = 0 "
        "WHERE scanner_run_id = :run",
        "DELETE FROM run_evidence WHERE scanner_run_id = :run",
    ],
)
def test_other_changes_are_refused(
    queue: ScanQueue, queue_seed: Seeder, queue_engine: Engine, statement: str
) -> None:
    lease = _sealed(queue, queue_seed, queue_engine)

    assert _code(queue_engine, statement, {"run": lease.run_id}) == INTEGRITY_CONSTRAINT_VIOLATION


def test_none_cannot_become_purged(
    queue: ScanQueue, queue_seed: Seeder, queue_engine: Engine
) -> None:
    lease = _finished(queue, queue_seed)
    _insert(queue_engine, _params(lease, status="none", sealed=None, files=0, bytes=0))

    params = {"run": lease.run_id, "at": PURGED_AT}
    assert _code(queue_engine, PURGE, params) in (INTEGRITY_CONSTRAINT_VIOLATION, CHECK_VIOLATION)


def test_purging_cannot_precede_sealing(
    queue: ScanQueue, queue_seed: Seeder, queue_engine: Engine
) -> None:
    lease = _sealed(queue, queue_seed, queue_engine)

    params = {"run": lease.run_id, "at": datetime(2025, 1, 1, tzinfo=UTC)}
    assert _code(queue_engine, PURGE, params) == CHECK_VIOLATION


def test_truncate_is_refused(queue: ScanQueue, queue_seed: Seeder, queue_engine: Engine) -> None:
    _sealed(queue, queue_seed, queue_engine)

    assert _code(queue_engine, "TRUNCATE run_evidence", {}) == INTEGRITY_CONSTRAINT_VIOLATION


def test_purging_cannot_be_dated_in_the_future(
    queue: ScanQueue, queue_seed: Seeder, queue_engine: Engine
) -> None:
    """清除的時間不能晚於現在（資料庫審查 L5）。"""
    lease = _sealed(queue, queue_seed, queue_engine)

    params = {"run": lease.run_id, "at": datetime.now(UTC) + timedelta(days=1)}
    assert _code(queue_engine, PURGE, params) == INTEGRITY_CONSTRAINT_VIOLATION
