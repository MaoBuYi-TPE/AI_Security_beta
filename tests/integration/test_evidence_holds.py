"""需要人工處理的原始證據對真的 DB 與檔案（EVID-08、EVID-09；docs/DECISIONS.md §30.12）。

- keeper 以較小的 TreeLimits 製造超過上限的目錄：連續 3 次失敗才寫入隔離紀錄與 audit；之後恢復健康、
  其他 run 照常加密，重啟的 keeper 也不再重試；明文保留原狀；API 顯示 manual_intervention_required。
- 孤兒目錄也會隔離，之後被跳過。
- trigger：新增、解除與刪除的規則；CHECK。
人工重試（retry-evidence）與 retention-status 見 test_evidence_retry.py。
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from secscan.main import create_app
from secscan.runner.backoff import MAX_BACKOFF_SECONDS
from secscan.runner.evidence import EvidenceVault
from secscan.runner.fs import TreeLimits
from secscan.runner.keeper import EvidenceKeeper, KeeperSettings, PassReport
from secscan.runner.plans import ENGINE_IMAGES
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.evidence import HOLD_AFTER_FAILURES, EvidenceHoldCode, SealedEvidence
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.evidence_holds import EvidenceHolds, HoldNotActiveError
from secscan.scans.evidence_records import EvidenceRun, EvidenceStore
from secscan.scans.queue import ScanQueue
from tests.integration.api_support import LAB, Scannable, Seeder, World
from tests.integration.database import ProvisionedDatabase
from tests.secret_support import shared_evidence_cipher

pytestmark = pytest.mark.integration

OWNER = "runner-evidence-holds-test"
FAKE = frozenset({ScanEngine.FAKE})
CANARY = b"canary-evidence-hold-3f9e"
LIMITS = TreeLimits(max_depth=4, max_entries=50)
SETTINGS = KeeperSettings(retention_days=7, plaintext_max_minutes=60)


@dataclass
class Moment:
    now: datetime


@dataclass
class Ticker:
    now: float = 0.0


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
def ticker() -> Ticker:
    return Ticker()


@pytest.fixture
def store(queue_engine: Engine) -> EvidenceStore:
    return EvidenceStore(sessionmaker(queue_engine, expire_on_commit=False), engine=queue_engine)


def _keeper(
    store: EvidenceStore,
    runs: Path,
    moment: Moment,
    ticker: Ticker,
    limits: TreeLimits = LIMITS,
) -> EvidenceKeeper:
    return EvidenceKeeper(
        store,
        EvidenceVault(runs, shared_evidence_cipher(), limits=limits),
        SETTINGS,
        clock=lambda: moment.now,
        monotonic=lambda: ticker.now,
    )


@pytest.fixture
def keeper(store: EvidenceStore, runs: Path, moment: Moment, ticker: Ticker) -> EvidenceKeeper:
    return _keeper(store, runs, moment, ticker)


@pytest.fixture
def client(queue_database: ProvisionedDatabase) -> Iterator[TestClient]:
    with TestClient(create_app(queue_database.app_settings())) as opened:
        yield opened


def _finished(queue: ScanQueue, seed: Seeder, world: World, scannable: Scannable) -> EvidenceRun:
    seed.scan(world.operator_a, scannable)
    lease = queue.claim(OWNER, FAKE)
    assert lease is not None
    queue.prepare(lease)
    queue.advance(lease, RunStatus.FAILED, error_code=RunErrorCode.ENGINE_FAILED)
    return EvidenceRun(lease.run_id, lease.scan_id)


def _deep(runs: Path, name: UUID | str, levels: int) -> Path:
    """out/ 之下再 levels 層目錄，最底下一個含 canary 的檔案（深度是 levels + 1）。"""
    leaf = runs / str(name) / "out" / Path(*(["d"] * levels))
    leaf.mkdir(parents=True)
    (leaf / "messages.txt").write_bytes(CANARY)
    return leaf / "messages.txt"


def _until_held(keeper: EvidenceKeeper, ticker: Ticker) -> list[PassReport]:
    reports = []
    for _ in range(HOLD_AFTER_FAILURES):
        reports.append(keeper.run_pass())
        ticker.now += MAX_BACKOFF_SECONDS
    return reports


def _hold_row(seed: Seeder, directory: UUID) -> Any:
    rows = seed.query("SELECT * FROM evidence_holds WHERE directory = :id", id=directory)
    return rows[0] if rows else None


def _audits(seed: Seeder, action: str) -> list[Any]:
    return list(
        seed.query(
            "SELECT redacted_changes, actor_key_id, object_type, object_id, project_id "
            "FROM audit_events WHERE action = :action ORDER BY created_at",
            action=action,
        )
    )


def _shown(client: TestClient, world: World, scan_id: UUID) -> dict[str, Any]:
    response = client.get(f"/api/v1/scans/{scan_id}", headers=world.operator_a.headers)
    assert response.status_code == 200, response.text
    [engine] = response.json()["data"]["engines"]
    evidence: dict[str, Any] = engine["evidence"]
    return evidence


# --- keeper（EVID-08）---------------------------------------------------------------------------


def test_a_run_over_the_limit_is_held_and_the_keeper_recovers(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    runs: Path,
    store: EvidenceStore,
    keeper: EvidenceKeeper,
    moment: Moment,
    ticker: Ticker,
    client: TestClient,
) -> None:
    stuck = _finished(queue, queue_seed, world, scannable)
    leaf = _deep(runs, stuck.run_id, LIMITS.max_depth)

    reports = _until_held(keeper, ticker)

    assert [report.failures for report in reports] == [1, 1, 1]
    assert [report.held for report in reports] == [0, 0, 1]
    row = _hold_row(queue_seed, stuck.run_id)
    assert (row.scanner_run_id, row.scan_id, row.error_code, row.attempts, row.resolved_at) == (
        stuck.run_id,
        stuck.scan_id,
        "EVIDENCE_TREE_TOO_DEEP",
        HOLD_AFTER_FAILURES,
        None,
    )
    [audit] = _audits(queue_seed, "evidence.hold")
    assert (audit.actor_key_id, audit.object_type, audit.object_id) == (
        None,
        "evidence_hold",
        stuck.run_id,
    )
    assert audit.project_id is not None
    assert audit.redacted_changes == {
        "kind": "run",
        "error_code": "EVIDENCE_TREE_TOO_DEEP",
        "attempts": HOLD_AFTER_FAILURES,
    }
    assert (
        queue_seed.query("SELECT 1 FROM run_evidence WHERE scanner_run_id = :id", id=stuck.run_id)
        == []
    )
    assert leaf.read_bytes() == CANARY

    shown = _shown(client, world, stuck.scan_id)
    assert shown["status"] == "manual_intervention_required"
    assert (shown["sealed_at"], shown["purged_at"]) == (None, None)
    assert shown["hold"]["error_code"] == "EVIDENCE_TREE_TOO_DEEP"
    assert shown["hold"]["attempts"] == HOLD_AFTER_FAILURES
    assert shown["hold"]["held_at"].endswith("Z")
    assert shown["hold"]["resolved_at"] is None
    summary = store.summary(now=moment.now, retention_days=7, max_minutes=60)
    assert summary.pending == 0

    fine = _finished(queue, queue_seed, world, scannable)
    (runs / str(fine.run_id) / "out").mkdir(parents=True)
    (runs / str(fine.run_id) / "out" / "report.json").write_bytes(b"{}")
    report = keeper.run_pass()
    assert report.clean
    assert report.sealed == 1
    assert keeper.healthy

    restarted = _keeper(store, runs, moment, Ticker())
    assert restarted.run_pass().clean
    assert leaf.read_bytes() == CANARY
    assert _hold_row(queue_seed, stuck.run_id).resolved_at is None


def test_two_failures_do_not_hold(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    runs: Path,
    keeper: EvidenceKeeper,
    ticker: Ticker,
) -> None:
    run = _finished(queue, queue_seed, world, scannable)
    _deep(runs, run.run_id, LIMITS.max_depth)

    for _ in range(HOLD_AFTER_FAILURES - 1):
        keeper.run_pass()
        ticker.now += MAX_BACKOFF_SECONDS

    assert _hold_row(queue_seed, run.run_id) is None
    assert keeper.healthy is False


def test_an_orphan_over_the_limit_is_held_and_skipped(
    queue_seed: Seeder, runs: Path, keeper: EvidenceKeeper, moment: Moment, ticker: Ticker
) -> None:
    name = uuid4()
    leaf = _deep(runs, name, LIMITS.max_depth)
    moment.now += timedelta(hours=2)

    reports = _until_held(keeper, ticker)

    assert reports[-1].held == 1
    row = _hold_row(queue_seed, name)
    assert (row.scanner_run_id, row.scan_id, row.error_code) == (
        None,
        None,
        "EVIDENCE_TREE_TOO_DEEP",
    )
    [audit] = _audits(queue_seed, "evidence.hold")
    assert audit.project_id is None
    assert audit.redacted_changes["kind"] == "orphan"
    assert keeper.run_pass().clean
    assert leaf.read_bytes() == CANARY


# --- trigger 與 CHECK（EVID-09）------------------------------------------------------------------


def _execute(engine: Engine, statement: str, **params: object) -> None:
    with Session(engine) as session, session.begin():
        session.execute(text(statement), params)


_INSERT_RUN = (
    "INSERT INTO evidence_holds (directory, scanner_run_id, scan_id, error_code, attempts) "
    "VALUES (:run, :run, :scan, 'EVIDENCE_TREE_TOO_DEEP', 3)"
)
_INSERT_SEALED = (
    "INSERT INTO run_evidence (scanner_run_id, scan_id, status, file_count, plaintext_bytes, "
    "sealed_at) VALUES (:run, :scan, :status, 0, 0, :sealed_at)"
)
_RESOLVE = "UPDATE evidence_holds SET resolved_at = clock_timestamp() WHERE directory = :run"


def test_a_hold_needs_a_finished_run_without_recorded_evidence(
    queue: ScanQueue,
    queue_seed: Seeder,
    queue_engine: Engine,
    world: World,
    scannable: Scannable,
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    running = queue.claim(OWNER, FAKE)
    assert running is not None
    with pytest.raises(DBAPIError, match="must be finished"):
        _execute(queue_engine, _INSERT_RUN, run=running.run_id, scan=running.scan_id)
    queue.prepare(running)
    queue.advance(running, RunStatus.FAILED, error_code=RunErrorCode.ENGINE_FAILED)
    _execute(
        queue_engine,
        _INSERT_SEALED,
        run=running.run_id,
        scan=running.scan_id,
        status="none",
        sealed_at=None,
    )

    with pytest.raises(DBAPIError, match="not yet recorded"):
        _execute(queue_engine, _INSERT_RUN, run=running.run_id, scan=running.scan_id)


def test_an_orphan_hold_cannot_name_a_known_run_and_starts_unresolved(
    queue: ScanQueue,
    queue_seed: Seeder,
    queue_engine: Engine,
    world: World,
    scannable: Scannable,
) -> None:
    run = _finished(queue, queue_seed, world, scannable)
    orphan = (
        "INSERT INTO evidence_holds (directory, error_code, attempts, resolved_at) "
        "VALUES (:directory, 'EVIDENCE_TREE_TOO_DEEP', 3, :resolved_at)"
    )

    with pytest.raises(DBAPIError, match="known run"):
        _execute(queue_engine, orphan, directory=run.run_id, resolved_at=None)
    with pytest.raises(DBAPIError, match="must be unresolved"):
        _execute(queue_engine, orphan, directory=uuid4(), resolved_at=datetime.now(UTC))
    _execute(queue_engine, orphan, directory=uuid4(), resolved_at=None)


def test_a_run_is_resolved_only_with_sealed_evidence_and_only_once(
    queue: ScanQueue,
    queue_seed: Seeder,
    queue_engine: Engine,
    world: World,
    scannable: Scannable,
) -> None:
    run = _finished(queue, queue_seed, world, scannable)
    _execute(queue_engine, _INSERT_RUN, run=run.run_id, scan=run.scan_id)

    with pytest.raises(DBAPIError, match="after its evidence is sealed"):
        _execute(queue_engine, _RESOLVE, run=run.run_id)
    with Session(queue_engine) as session, session.begin():
        session.execute(
            text(_INSERT_SEALED),
            {
                "run": run.run_id,
                "scan": run.scan_id,
                "status": "sealed",
                "sealed_at": datetime.now(UTC),
            },
        )
        session.execute(text(_RESOLVE), {"run": run.run_id})

    assert _hold_row(queue_seed, run.run_id).resolved_at is not None
    with pytest.raises(DBAPIError, match="resolved once"):
        _execute(queue_engine, _RESOLVE, run=run.run_id)
    with pytest.raises(DBAPIError, match="resolved once"):
        _execute(
            queue_engine,
            "UPDATE evidence_holds SET attempts = 9 WHERE directory = :run",
            run=run.run_id,
        )


@pytest.mark.parametrize(
    "statement",
    ["DELETE FROM evidence_holds", "TRUNCATE evidence_holds"],
)
def test_holds_cannot_be_deleted(queue_engine: Engine, queue_seed: Seeder, statement: str) -> None:
    directory = uuid4()
    _execute(
        queue_engine,
        "INSERT INTO evidence_holds (directory, error_code, attempts) "
        "VALUES (:directory, 'EVIDENCE_TREE_TOO_MANY_ENTRIES', 3)",
        directory=directory,
    )

    with pytest.raises(DBAPIError, match="blocked"):
        _execute(queue_engine, statement)

    assert _hold_row(queue_seed, directory) is not None


@pytest.mark.parametrize(
    ("columns", "constraint"),
    [
        ({"scan_id": uuid4()}, "run_columns_paired"),
        ({"error_code": "EVIDENCE_SOMETHING_ELSE"}, "error_code_valid"),
        ({"attempts": 0}, "attempts_positive"),
    ],
)
def test_checks_reject_inconsistent_rows(
    queue_engine: Engine, columns: dict[str, object], constraint: str
) -> None:
    directory = uuid4()
    values: dict[str, object] = {
        "directory": directory,
        "scanner_run_id": None,
        "scan_id": None,
        "error_code": "EVIDENCE_TREE_TOO_DEEP",
        "attempts": 3,
    }

    with pytest.raises(DBAPIError, match=constraint):
        _execute(queue_engine, _INSERT_ANY, **(values | columns))


_INSERT_ANY = (
    "INSERT INTO evidence_holds (directory, scanner_run_id, scan_id, error_code, attempts) "
    "VALUES (:directory, :scanner_run_id, :scan_id, :error_code, :attempts)"
)


def test_a_run_hold_is_named_after_the_run(
    queue: ScanQueue,
    queue_seed: Seeder,
    queue_engine: Engine,
    world: World,
    scannable: Scannable,
) -> None:
    """trigger 先確認 run 已終止、沒有紀錄；之後的 CHECK 要求目錄名稱就是 run_id。"""
    run = _finished(queue, queue_seed, world, scannable)

    with pytest.raises(DBAPIError, match="directory_is_run"):
        _execute(
            queue_engine,
            _INSERT_ANY,
            directory=uuid4(),
            scanner_run_id=run.run_id,
            scan_id=run.scan_id,
            error_code="EVIDENCE_TREE_TOO_DEEP",
            attempts=3,
        )


# --- 審查之後（資料庫審查 M1、M2、L1、L5、L6；安全審查 L3；§30.12）-------------------------------


def _transaction(engine: Engine, *statements: tuple[str, dict[str, object]]) -> None:
    """幾個敘述在同一個 transaction 中依序執行（deferred 的檢查在 commit 時進行）。"""
    with Session(engine) as session, session.begin():
        for statement, params in statements:
            session.execute(text(statement), params)


def _held_run(
    queue: ScanQueue, seed: Seeder, engine: Engine, world: World, scannable: Scannable
) -> EvidenceRun:
    run = _finished(queue, seed, world, scannable)
    _execute(engine, _INSERT_RUN, run=run.run_id, scan=run.scan_id)
    return run


@pytest.mark.parametrize("status", ["none", "sealed"])
def test_run_evidence_for_a_held_run_is_refused_at_commit(
    queue: ScanQueue,
    queue_seed: Seeder,
    queue_engine: Engine,
    world: World,
    scannable: Scannable,
    status: str,
) -> None:
    """隔離的 run 不能被記成 none 或 sealed：只有在同一個 transaction 中解除隔離才行。"""
    run = _held_run(queue, queue_seed, queue_engine, world, scannable)

    with pytest.raises(DBAPIError, match="held run"):
        _execute(
            queue_engine,
            _INSERT_SEALED,
            run=run.run_id,
            scan=run.scan_id,
            status=status,
            sealed_at=datetime.now(UTC) if status == "sealed" else None,
        )

    assert (
        queue_seed.query("SELECT 1 FROM run_evidence WHERE scanner_run_id = :id", id=run.run_id)
        == []
    )


def test_a_hold_and_run_evidence_cannot_commit_concurrently(
    queue: ScanQueue,
    queue_seed: Seeder,
    queue_engine: Engine,
    world: World,
    scannable: Scannable,
) -> None:
    """兩邊都先取得以 run 為鍵的交易鎖：一邊還沒 commit 時，另一邊等它，之後看得到對方。"""
    run = _finished(queue, queue_seed, world, scannable)
    none = {"run": run.run_id, "scan": run.scan_id, "status": "none", "sealed_at": None}
    with Session(queue_engine) as holding, holding.begin():
        holding.execute(text(_INSERT_RUN), {"run": run.run_id, "scan": run.scan_id})
        with pytest.raises(DBAPIError, match="lock timeout"):
            _transaction(
                queue_engine, ("SET LOCAL lock_timeout = '200ms'", {}), (_INSERT_SEALED, none)
            )

    with pytest.raises(DBAPIError, match="held run"):
        _execute(
            queue_engine,
            _INSERT_SEALED,
            run=run.run_id,
            scan=run.scan_id,
            status="none",
            sealed_at=None,
        )


def test_resolving_cannot_change_other_columns(
    queue: ScanQueue,
    queue_seed: Seeder,
    queue_engine: Engine,
    world: World,
    scannable: Scannable,
) -> None:
    run = _held_run(queue, queue_seed, queue_engine, world, scannable)

    sealed = {
        "run": run.run_id,
        "scan": run.scan_id,
        "status": "sealed",
        "sealed_at": datetime.now(UTC),
    }
    for resolve_and_change in (
        "UPDATE evidence_holds SET resolved_at = clock_timestamp(), attempts = 9 "
        "WHERE directory = :run",
        "UPDATE evidence_holds SET resolved_at = clock_timestamp(), "
        "error_code = 'EVIDENCE_TREE_TOO_MANY_ENTRIES' WHERE directory = :run",
    ):
        with pytest.raises(DBAPIError, match="resolved once"):
            _transaction(
                queue_engine, (_INSERT_SEALED, sealed), (resolve_and_change, {"run": run.run_id})
            )
    with pytest.raises(DBAPIError, match="resolved once"):
        _execute(
            queue_engine,
            "UPDATE evidence_holds SET held_at = held_at - interval '1 day' WHERE directory = :run",
            run=run.run_id,
        )
    assert _hold_row(queue_seed, run.run_id).attempts == 3


def test_resolving_needs_sealed_not_none_evidence(
    queue: ScanQueue,
    queue_seed: Seeder,
    queue_engine: Engine,
    world: World,
    scannable: Scannable,
) -> None:
    run = _held_run(queue, queue_seed, queue_engine, world, scannable)

    none = {"run": run.run_id, "scan": run.scan_id, "status": "none", "sealed_at": None}

    with pytest.raises(DBAPIError, match="after its evidence is sealed"):
        _transaction(queue_engine, (_INSERT_SEALED, none), (_RESOLVE, {"run": run.run_id}))


def test_times_come_from_the_database(queue_engine: Engine, queue_seed: Seeder) -> None:
    """用戶端給的 held_at、resolved_at 一律被 trigger 以 clock_timestamp() 取代。"""
    directory = uuid4()
    before = datetime.now(UTC) - timedelta(minutes=1)
    _execute(
        queue_engine,
        "INSERT INTO evidence_holds (directory, error_code, attempts, held_at) "
        "VALUES (:directory, 'EVIDENCE_TREE_TOO_DEEP', 3, '2000-01-01T00:00:00Z')",
        directory=directory,
    )
    _execute(
        queue_engine,
        "UPDATE evidence_holds SET resolved_at = '2999-01-01T00:00:00Z' WHERE directory = :id",
        id=directory,
    )

    row = _hold_row(queue_seed, directory)
    after = datetime.now(UTC) + timedelta(minutes=1)
    assert before < row.held_at <= row.resolved_at < after


def test_a_run_whose_container_is_not_confirmed_removed_cannot_be_held(
    queue: ScanQueue,
    queue_seed: Seeder,
    queue_engine: Engine,
    world: World,
    scannable: Scannable,
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    lease = queue.claim(OWNER, FAKE)
    assert lease is not None
    queue.prepare_launch(lease, image_ref=str(ENGINE_IMAGES[ScanEngine.FAKE]))
    queue.advance(lease, RunStatus.FAILED, error_code=RunErrorCode.ENGINE_FAILED)

    with pytest.raises(DBAPIError, match="container removed"):
        _execute(queue_engine, _INSERT_RUN, run=lease.run_id, scan=lease.scan_id)


def test_the_run_reference_must_match_its_scan(
    queue: ScanQueue,
    queue_seed: Seeder,
    queue_engine: Engine,
    world: World,
    scannable: Scannable,
) -> None:
    first = _finished(queue, queue_seed, world, scannable)
    second = _finished(queue, queue_seed, world, scannable)

    with pytest.raises(DBAPIError, match="fk_evidence_holds"):
        _execute(queue_engine, _INSERT_RUN, run=first.run_id, scan=second.scan_id)


def test_the_error_code_check_matches_the_domain(queue_engine: Engine) -> None:
    """CHECK 的運算式不在 autogenerate 的比對範圍：直接核對 DB 中的清單（資料庫審查 L5）。"""
    with queue_engine.connect() as connection:
        definition = connection.execute(
            text(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conname = 'ck_evidence_holds_error_code_valid'"
            )
        ).scalar_one()

    assert sorted(re.findall(r"'([A-Z_]+)'", definition)) == sorted(
        code.value for code in EvidenceHoldCode
    )


def test_a_second_resolve_finds_the_hold_already_resolved(
    queue: ScanQueue,
    queue_seed: Seeder,
    queue_engine: Engine,
    world: World,
    scannable: Scannable,
) -> None:
    run = _held_run(queue, queue_seed, queue_engine, world, scannable)
    holds = EvidenceHolds(sessionmaker(queue_engine, expire_on_commit=False))
    held = holds.active(run.run_id)
    assert held is not None

    holds.resolve(held, SealedEvidence(files=1, plaintext_bytes=1), {})

    with pytest.raises(HoldNotActiveError):
        holds.resolve(held, SealedEvidence(files=1, plaintext_bytes=1), {})
    assert len(_audits(queue_seed, "evidence.resolve")) == 1


def test_a_run_with_too_long_paths_is_held_like_the_other_limits(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    runs: Path,
    store: EvidenceStore,
    moment: Moment,
    ticker: Ticker,
) -> None:
    """路徑總長度超過上限也只隔離這個 run，不阻擋其他 run（使用者，2026-11-10；§30.12）。"""
    keeper = _keeper(store, runs, moment, ticker, TreeLimits(max_path_chars=300))
    stuck = _finished(queue, queue_seed, world, scannable)
    leaf = runs / str(stuck.run_id) / "out" / ("n" * 200)
    leaf.mkdir(parents=True)
    (leaf / "messages.txt").write_bytes(CANARY)

    reports = _until_held(keeper, ticker)

    assert reports[-1].held == 1
    assert _hold_row(queue_seed, stuck.run_id).error_code == "EVIDENCE_TREE_PATHS_TOO_LONG"
    assert (leaf / "messages.txt").read_bytes() == CANARY
    fine = _finished(queue, queue_seed, world, scannable)
    (runs / str(fine.run_id) / "out").mkdir(parents=True)
    (runs / str(fine.run_id) / "out" / "report.json").write_bytes(b"{}")
    report = keeper.run_pass()
    assert (report.clean, report.sealed) == (True, 1)
