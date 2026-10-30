"""migration 0009：容器確認刪除的時間（docs/DECISIONS.md §17.3）。

- container_removed_at 只能寫入一次（不能改、不能清除），只有記下容器的 run 才能寫，而且不早於
  run 開始的時間。
- 已終止的 run 只允許補寫 container_removed_at（由 NULL 變成有值），其他欄位一律不能動。
- 待處理的容器以部分索引查詢；downgrade 還原 0005 的 trigger。
"""

from collections.abc import Mapping
from datetime import UTC, datetime
from uuid import UUID

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from tests.integration.conftest import app_engine
from tests.integration.database import ProvisionedDatabase
from tests.integration.scan_support import create_scan, scan_world
from tests.integration.sql_support import (
    CHECK_VIOLATION,
    INTEGRITY_CONSTRAINT_VIOLATION,
    violation,
)
from tests.integration.test_migrations import _migrate

pytestmark = pytest.mark.integration

STARTED = datetime(2030, 1, 1, tzinfo=UTC)
REMOVED = datetime(2030, 1, 1, 0, 5, tzinfo=UTC)
LATER = datetime(2030, 1, 1, 0, 9, tzinfo=UTC)
BEFORE_START = datetime(2029, 12, 31, tzinfo=UTC)
IMAGE = "busybox:1.38.0@sha256:" + "ab" * 32

MOVE = (
    "UPDATE scanner_runs SET status = :status, lease_owner = :owner, lease_expires_at = :expires, "
    "heartbeat_at = :heartbeat, started_at = :started, finished_at = :finished, "
    "error_code = :error_code, container_name = :container, image_ref = :image WHERE id = :id"
)
REMOVE = "UPDATE scanner_runs SET container_removed_at = :at WHERE id = :id"
FINISH = (
    "UPDATE scanner_runs SET status = 'failed', error_code = 'ENGINE_FAILED', lease_owner = NULL, "
    "lease_expires_at = NULL, heartbeat_at = NULL, finished_at = :at WHERE id = :id"
)


def _move(run_id: UUID, **overrides: object) -> dict[str, object]:
    params: dict[str, object] = {
        "id": run_id,
        "status": "running",
        "owner": "runner-1",
        "expires": LATER,
        "heartbeat": STARTED,
        "started": STARTED,
        "finished": None,
        "error_code": None,
        "container": f"secscan-run-{run_id}",
        "image": IMAGE,
    }
    params.update(overrides)
    return params


def _run(session: Session, *, container: bool = True) -> UUID:
    """一個 running 的 fake run（有容器，或像 in-process 的 fake 一樣沒有容器）。"""
    scan = create_scan(session, scan_world(session))
    run_id: UUID = session.execute(
        text("SELECT id FROM scanner_runs WHERE scan_id = :scan"), {"scan": scan.id}
    ).scalar_one()
    session.execute(text(MOVE), _move(run_id, status="preparing", container=None, image=None))
    if container:
        session.execute(text(MOVE), _move(run_id))
    else:
        session.execute(text(MOVE), _move(run_id, container=None, image=None))
    return run_id


def _removed_at(session: Session, run_id: UUID) -> datetime | None:
    value: datetime | None = session.execute(
        text("SELECT container_removed_at FROM scanner_runs WHERE id = :id"), {"id": run_id}
    ).scalar_one()
    return value


def _blocked(session: Session, statement: str, params: Mapping[str, object]) -> None:
    error = violation(session, statement, params)
    assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION
    assert str(error).startswith("scanner_runs:")


def test_the_removal_is_recorded_while_the_run_is_in_progress(db_session: Session) -> None:
    run_id = _run(db_session)

    db_session.execute(text(REMOVE), {"id": run_id, "at": REMOVED})

    assert _removed_at(db_session, run_id) == REMOVED


@pytest.mark.parametrize("change", [LATER, None])
def test_the_removal_is_recorded_only_once(db_session: Session, change: datetime | None) -> None:
    run_id = _run(db_session)
    db_session.execute(text(REMOVE), {"id": run_id, "at": REMOVED})

    _blocked(db_session, REMOVE, {"id": run_id, "at": change})


def test_a_run_without_a_container_has_nothing_to_remove(db_session: Session) -> None:
    run_id = _run(db_session, container=False)

    error = violation(db_session, REMOVE, {"id": run_id, "at": REMOVED})

    assert (error.sqlstate, error.diag.constraint_name) == (
        CHECK_VIOLATION,
        "ck_scanner_runs_container_removed_after_start",
    )


def test_the_removal_cannot_precede_the_start(db_session: Session) -> None:
    run_id = _run(db_session)

    error = violation(db_session, REMOVE, {"id": run_id, "at": BEFORE_START})

    assert error.diag.constraint_name == "ck_scanner_runs_container_removed_after_start"


def test_a_finished_run_may_record_the_removal_afterwards(db_session: Session) -> None:
    run_id = _run(db_session)
    db_session.execute(text(FINISH), {"id": run_id, "at": REMOVED})

    db_session.execute(text(REMOVE), {"id": run_id, "at": LATER})

    assert _removed_at(db_session, run_id) == LATER


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE scanner_runs SET container_removed_at = :at, requests_sent = 1 WHERE id = :id",
        "UPDATE scanner_runs SET container_removed_at = :at, error_code = 'LEASE_EXPIRED' "
        "WHERE id = :id",
        "UPDATE scanner_runs SET container_removed_at = :at, finished_at = :at WHERE id = :id",
        "UPDATE scanner_runs SET container_removed_at = :at, coverage_recorded = true "
        "WHERE id = :id",
        "UPDATE scanner_runs SET requests_sent = 1 WHERE id = :id",
    ],
)
def test_nothing_else_changes_on_a_finished_run(db_session: Session, statement: str) -> None:
    run_id = _run(db_session)
    db_session.execute(
        text("UPDATE scanner_runs SET requests_allotted = 5 WHERE id = :id"), {"id": run_id}
    )
    db_session.execute(text(FINISH), {"id": run_id, "at": REMOVED})

    _blocked(db_session, statement, {"id": run_id, "at": LATER})


def test_a_finished_run_keeps_its_recorded_removal(db_session: Session) -> None:
    run_id = _run(db_session)
    db_session.execute(text(REMOVE), {"id": run_id, "at": REMOVED})
    db_session.execute(text(FINISH), {"id": run_id, "at": LATER})

    _blocked(db_session, REMOVE, {"id": run_id, "at": LATER})
    _blocked(db_session, REMOVE, {"id": run_id, "at": None})


def test_pending_containers_have_a_partial_index(db_session: Session) -> None:
    indexdef = db_session.execute(
        text(
            "SELECT indexdef FROM pg_indexes WHERE indexname = 'ix_scanner_runs_pending_containers'"
        )
    ).scalar_one()

    assert "(created_at)" in indexdef
    assert "container_name IS NOT NULL" in indexdef
    assert "container_removed_at IS NULL" in indexdef


def test_downgrade_restores_the_previous_guard(fresh_database: ProvisionedDatabase) -> None:
    engine: Engine = app_engine(fresh_database)
    try:
        _migrate(engine, "up", "head")
        _migrate(engine, "down", "0008")
        with engine.connect() as connection:
            columns = connection.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name = 'scanner_runs' AND column_name = 'container_removed_at'"
                )
            ).all()
            body = connection.execute(
                text("SELECT prosrc FROM pg_proc WHERE proname = 'scanner_runs_guard'")
            ).scalar_one()
        assert columns == []
        assert "container_removed_at" not in body
        assert "OLD.status NOT IN" in body
        _migrate(engine, "up", "head")
    finally:
        engine.dispose()
