"""隔離紀錄的 v0024 轉換與 CHECK（EVID-11；docs/DECISIONS.md §30.13）。

trigger 只允許固定的五種轉換（記錄來源 inode、記錄搬移失敗、隔離完成、開始解除、解除），其他欄位
必須完全不變；時間由 DB 寫入。HoldIsolationStore 以 WHERE 寫出前提，條件不成立時回 False。
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.evidence import (
    ISOLATION_URGENT_AFTER,
    EvidenceHoldCode,
    HoldMoveCode,
    HoldStage,
    SealedEvidence,
)
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.evidence_hold_isolation import HoldIsolationStore
from secscan.scans.evidence_holds import EvidenceHolds, HeldDirectory
from secscan.scans.queue import ScanQueue
from tests.integration.api_support import LAB, Seeder

pytestmark = pytest.mark.integration

FAKE = frozenset({ScanEngine.FAKE})
_INSERT = (
    "INSERT INTO evidence_holds (directory, error_code, attempts, source_ino) "
    "VALUES (:directory, 'EVIDENCE_TREE_TOO_DEEP', 3, :source_ino)"
)


@pytest.fixture
def isolation(queue_engine: Engine) -> HoldIsolationStore:
    return HoldIsolationStore(sessionmaker(queue_engine, expire_on_commit=False))


@pytest.fixture
def holds(queue_engine: Engine) -> EvidenceHolds:
    return EvidenceHolds(sessionmaker(queue_engine, expire_on_commit=False))


def _execute(engine: Engine, statement: str, **params: object) -> None:
    with Session(engine) as session, session.begin():
        session.execute(text(statement), params)


def _orphan(engine: Engine, source_ino: int | None = 7) -> UUID:
    directory = uuid4()
    if source_ino is None:
        # v0024 之前留下的紀錄：暫時關閉 trigger 寫入（只有測試這樣做）。
        with Session(engine) as session, session.begin():
            session.execute(text("ALTER TABLE evidence_holds DISABLE TRIGGER evidence_holds_guard"))
            session.execute(
                text(
                    "INSERT INTO evidence_holds (directory, error_code, attempts) "
                    "VALUES (:directory, 'EVIDENCE_TREE_TOO_DEEP', 3)"
                ),
                {"directory": directory},
            )
            session.execute(text("ALTER TABLE evidence_holds ENABLE TRIGGER evidence_holds_guard"))
        return directory
    _execute(engine, _INSERT, directory=directory, source_ino=source_ino)
    return directory


def _row(seed: Seeder, directory: UUID) -> Any:
    [row] = seed.query("SELECT * FROM evidence_holds WHERE directory = :id", id=directory)
    return row


def _held(holds: EvidenceHolds, directory: UUID) -> HeldDirectory:
    held = holds.active(directory)
    assert held is not None
    return held


def _audits(seed: Seeder, action: str) -> list[Any]:
    return list(
        seed.query(
            "SELECT redacted_changes, object_id FROM audit_events WHERE action = :action",
            action=action,
        )
    )


# --- 新增 ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("columns", "values"),
    [
        ("isolated_at", "clock_timestamp()"),
        ("releasing_at", "clock_timestamp()"),
        (
            "move_failures, last_move_error, last_move_failed_at",
            "1, 'EVIDENCE_HOLD_CONFLICT', clock_timestamp()",
        ),
    ],
)
def test_a_new_hold_starts_isolating_without_failures(
    queue_engine: Engine, columns: str, values: str
) -> None:
    statement = (
        f"INSERT INTO evidence_holds (directory, error_code, attempts, source_ino, {columns}) "  # noqa: S608
        f"VALUES (:directory, 'EVIDENCE_TREE_TOO_DEEP', 3, 1, {values})"
    )

    with pytest.raises(DBAPIError, match="not yet isolated"):
        _execute(queue_engine, statement, directory=uuid4())


def test_a_new_hold_must_record_the_inode(queue_engine: Engine) -> None:
    with pytest.raises(DBAPIError, match="inode"):
        _execute(
            queue_engine,
            "INSERT INTO evidence_holds (directory, error_code, attempts) "
            "VALUES (:directory, 'EVIDENCE_TREE_TOO_DEEP', 3)",
            directory=uuid4(),
        )


# --- 五種轉換 ----------------------------------------------------------------------------------


def test_the_full_lifecycle_through_the_store(
    queue_engine: Engine,
    queue_seed: Seeder,
    holds: EvidenceHolds,
    isolation: HoldIsolationStore,
) -> None:
    directory = _orphan(queue_engine)

    assert isolation.record_move_failure(directory, HoldMoveCode.CONFLICT)
    assert isolation.record_move_failure(directory, HoldMoveCode.MOVE_FAILED)
    row = _row(queue_seed, directory)
    assert (row.move_failures, row.last_move_error) == (2, "EVIDENCE_HOLD_MOVE_FAILED")
    assert row.last_move_failed_at >= row.held_at
    held = _held(holds, directory)
    assert (held.moves.count, held.moves.last_code) == (2, HoldMoveCode.MOVE_FAILED)
    assert held.hold.stage is HoldStage.ISOLATING

    assert isolation.mark_isolated(held)
    assert not isolation.mark_isolated(held)
    assert not isolation.record_move_failure(directory, HoldMoveCode.CONFLICT)
    assert _held(holds, directory).hold.stage is HoldStage.ISOLATED

    assert isolation.begin_release(_held(holds, directory), {"max_depth": 40})
    assert not isolation.begin_release(_held(holds, directory), {})
    released = _held(holds, directory)
    assert released.hold.stage is HoldStage.RELEASING

    holds.resolve(released, SealedEvidence(files=1, plaintext_bytes=1), {})
    row = _row(queue_seed, directory)
    assert row.held_at <= row.isolated_at <= row.releasing_at <= row.resolved_at
    [isolated] = _audits(queue_seed, "evidence.isolated")
    assert isolated.redacted_changes == {"kind": "orphan", "move_failures": 2}
    [release] = _audits(queue_seed, "evidence.release")
    assert release.redacted_changes == {"kind": "orphan", "max_depth": 40}


def test_the_source_inode_is_recorded_once_for_legacy_holds(
    queue_engine: Engine, queue_seed: Seeder, isolation: HoldIsolationStore
) -> None:
    legacy = _orphan(queue_engine, None)

    assert isolation.record_source(legacy, 42)
    assert not isolation.record_source(legacy, 43)
    assert _row(queue_seed, legacy).source_ino == 42
    with pytest.raises(DBAPIError, match="isolation steps"):
        _execute(
            queue_engine,
            "UPDATE evidence_holds SET source_ino = 9 WHERE directory = :id",
            id=legacy,
        )


def test_isolation_needs_an_inode(
    queue_engine: Engine, holds: EvidenceHolds, isolation: HoldIsolationStore
) -> None:
    legacy = _orphan(queue_engine, None)

    with pytest.raises(DBAPIError, match="isolation steps"):
        _execute(
            queue_engine,
            "UPDATE evidence_holds SET isolated_at = clock_timestamp() WHERE directory = :id",
            id=legacy,
        )
    assert not isolation.mark_isolated(_held(holds, legacy))


@pytest.mark.parametrize(
    "statement",
    [
        # 開始解除之前必須已隔離完成；解除之前必須已開始解除。
        "UPDATE evidence_holds SET releasing_at = clock_timestamp() WHERE directory = :id",
        "UPDATE evidence_holds SET resolved_at = clock_timestamp() WHERE directory = :id",
        # 搬移失敗：次數剛好加 1、必須帶代碼；不能同時改其他欄位。
        "UPDATE evidence_holds SET move_failures = 2, last_move_error = 'EVIDENCE_HOLD_CONFLICT' "
        "WHERE directory = :id",
        "UPDATE evidence_holds SET move_failures = 1 WHERE directory = :id",
        "UPDATE evidence_holds SET move_failures = 1, last_move_error = 'EVIDENCE_HOLD_CONFLICT', "
        "attempts = 9 WHERE directory = :id",
        # 隔離完成不能同時改其他欄位。
        "UPDATE evidence_holds SET isolated_at = clock_timestamp(), attempts = 9 "
        "WHERE directory = :id",
        "UPDATE evidence_holds SET source_ino = 8 WHERE directory = :id",
    ],
)
def test_other_changes_are_blocked(queue_engine: Engine, statement: str) -> None:
    directory = _orphan(queue_engine)

    with pytest.raises(DBAPIError, match="isolation steps"):
        _execute(queue_engine, statement, id=directory)


def test_a_move_failure_after_isolation_is_blocked(queue_engine: Engine) -> None:
    directory = _orphan(queue_engine)
    _execute(
        queue_engine,
        "UPDATE evidence_holds SET isolated_at = clock_timestamp() WHERE directory = :id",
        id=directory,
    )

    with pytest.raises(DBAPIError, match="isolation steps"):
        _execute(
            queue_engine,
            "UPDATE evidence_holds SET move_failures = 1, "
            "last_move_error = 'EVIDENCE_HOLD_CONFLICT' WHERE directory = :id",
            id=directory,
        )


@pytest.mark.parametrize(
    ("statement", "constraint"),
    [
        (
            "UPDATE evidence_holds SET move_failures = move_failures + 1, "
            "last_move_error = 'EVIDENCE_SOMETHING' WHERE directory = :id",
            "move_error_valid",
        ),
    ],
)
def test_checks_reject_unknown_move_codes(
    queue_engine: Engine, statement: str, constraint: str
) -> None:
    directory = _orphan(queue_engine)

    with pytest.raises(DBAPIError, match=constraint):
        _execute(queue_engine, statement, id=directory)


@pytest.mark.parametrize(
    ("columns", "constraint"),
    [
        ("source_ino = -1", "source_ino_valid"),
        ("isolated_at = held_at - interval '1 second'", "isolated_after_held"),
        ("isolated_at = held_at, source_ino = NULL", "isolated_has_source"),
        ("releasing_at = held_at", "releasing_after_isolated"),
        (
            "isolated_at = held_at + interval '2 seconds', "
            "releasing_at = held_at + interval '1 second'",
            "releasing_after_isolated",
        ),
        (
            "isolated_at = held_at, releasing_at = held_at + interval '2 seconds', "
            "resolved_at = held_at + interval '1 second'",
            "resolved_after_releasing",
        ),
        (
            "move_failures = -1, last_move_error = 'EVIDENCE_HOLD_CONFLICT', "
            "last_move_failed_at = held_at",
            "move_failures_valid",
        ),
        ("move_failures = 1", "move_failure_fields"),
        ("last_move_error = 'EVIDENCE_HOLD_CONFLICT'", "move_failure_fields"),
        (
            "move_failures = 1, last_move_error = 'EVIDENCE_HOLD_CONFLICT', "
            "last_move_failed_at = held_at - interval '1 second'",
            "move_failed_after_held",
        ),
    ],
)
def test_the_nine_checks_hold_even_without_the_trigger(
    queue_engine: Engine, columns: str, constraint: str
) -> None:
    """trigger 之外的第二道防線：關閉 trigger 直接改寫，CHECK 仍然擋下不一致的列。"""
    directory = _orphan(queue_engine)

    statement = f"UPDATE evidence_holds SET {columns} WHERE directory = :id"  # noqa: S608

    with (  # noqa: PT012 - 關閉 trigger 與改寫在同一個 transaction（失敗時一起回滾）
        pytest.raises(DBAPIError, match=constraint),
        Session(queue_engine) as session,
        session.begin(),
    ):
        session.execute(text("ALTER TABLE evidence_holds DISABLE TRIGGER evidence_holds_guard"))
        session.execute(text(statement), {"id": directory})


# --- 查詢與統計 --------------------------------------------------------------------------------


def test_settled_follows_the_run_and_orphans_are_always_settled(
    queue_engine: Engine, queue_seed: Seeder, holds: EvidenceHolds, isolation: HoldIsolationStore
) -> None:
    queue = ScanQueue(
        sessionmaker(queue_engine, expire_on_commit=False), lab=LAB, clock=lambda: datetime.now(UTC)
    )
    world = queue_seed.world()
    queue_seed.scan(world.operator_a, queue_seed.scannable(world))
    lease = queue.claim("runner-isolation", FAKE)
    assert lease is not None
    queue.prepare(lease)
    queue.advance(lease, RunStatus.FAILED, error_code=RunErrorCode.ENGINE_FAILED)
    holds.hold(lease.run_id, lease.scan_id, EvidenceHoldCode.TREE_TOO_DEEP, 3, 11)
    orphan = _orphan(queue_engine)

    assert isolation.settled(_held(holds, lease.run_id))
    assert isolation.settled(_held(holds, orphan))
    assert isolation.unresolved_among([lease.run_id, orphan, uuid4()]) == {lease.run_id, orphan}
    assert isolation.unresolved_among([]) == frozenset()
    assert [held.directory for held in isolation.unresolved(limit=10)] == [lease.run_id, orphan]


def test_the_summary_counts_each_stage_and_the_urgent_ones(
    queue_engine: Engine, holds: EvidenceHolds, isolation: HoldIsolationStore
) -> None:
    isolating, isolated, releasing = (_orphan(queue_engine) for _ in range(3))
    assert isolation.record_move_failure(isolating, HoldMoveCode.CONFLICT)
    assert isolation.mark_isolated(_held(holds, isolated))
    assert isolation.mark_isolated(_held(holds, releasing))
    assert isolation.begin_release(_held(holds, releasing), {})
    now = datetime.now(UTC)

    summary = isolation.summary(now=now, urgent_after=ISOLATION_URGENT_AFTER, listed=10)
    later = isolation.summary(
        now=now + ISOLATION_URGENT_AFTER + timedelta(seconds=1),
        urgent_after=ISOLATION_URGENT_AFTER,
        listed=10,
    )

    assert (summary.isolating, summary.isolated, summary.releasing) == (1, 1, 1)
    assert (summary.urgent, later.urgent) == (0, 1)
    [oldest] = summary.oldest
    assert (oldest.directory, oldest.moves.count) == (isolating, 1)
    assert oldest.moves.last_code is HoldMoveCode.CONFLICT


def test_notes_are_audited(
    queue_engine: Engine, queue_seed: Seeder, holds: EvidenceHolds, isolation: HoldIsolationStore
) -> None:
    directory = _orphan(queue_engine)

    isolation.note(_held(holds, directory), "evidence.isolation_overdue", {"minutes": 16})

    [audit] = _audits(queue_seed, "evidence.isolation_overdue")
    assert audit.redacted_changes == {"kind": "orphan", "minutes": 16}
    assert audit.object_id == directory


def test_the_move_failure_time_comes_from_the_database(
    queue_engine: Engine, queue_seed: Seeder
) -> None:
    """資料庫審查 L2：轉換 1 中用戶端給的 last_move_failed_at 也被 trigger 取代。"""
    directory = _orphan(queue_engine)
    before = datetime.now(UTC) - timedelta(minutes=1)

    _execute(
        queue_engine,
        "UPDATE evidence_holds SET move_failures = move_failures + 1, "
        "last_move_error = 'EVIDENCE_HOLD_CONFLICT', "
        "last_move_failed_at = '2999-01-01T00:00:00Z' WHERE directory = :id",
        id=directory,
    )

    row = _row(queue_seed, directory)
    assert before < row.last_move_failed_at < datetime.now(UTC) + timedelta(minutes=1)


def test_a_no_op_update_is_blocked(queue_engine: Engine) -> None:
    directory = _orphan(queue_engine)

    with pytest.raises(DBAPIError, match="isolation steps"):
        _execute(
            queue_engine,
            "UPDATE evidence_holds SET attempts = attempts WHERE directory = :id",
            id=directory,
        )


def test_pages_split_the_stages_and_overdue_lists_only_isolating(
    queue_engine: Engine, holds: EvidenceHolds, isolation: HoldIsolationStore
) -> None:
    isolating = [_orphan(queue_engine) for _ in range(3)]
    isolated = _orphan(queue_engine)
    assert isolation.mark_isolated(_held(holds, isolated))

    first = isolation.unresolved_page(isolating=True, after=None, limit=2)
    second = isolation.unresolved_page(isolating=True, after=first[-1], limit=2)
    others = isolation.unresolved_page(isolating=False, after=None, limit=10)

    assert [held.directory for held in (*first, *second)] == isolating
    assert [held.directory for held in others] == [isolated]
    later = datetime.now(UTC) + ISOLATION_URGENT_AFTER + timedelta(seconds=1)
    overdue = isolation.overdue(now=later, urgent_after=ISOLATION_URGENT_AFTER, limit=10)
    assert [held.directory for held in overdue] == isolating
    assert (
        isolation.overdue(now=datetime.now(UTC), urgent_after=ISOLATION_URGENT_AFTER, limit=10)
        == ()
    )
