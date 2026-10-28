"""migration 0006 的 DB 約束與 trigger（docs/DECISIONS.md §14.6、§14.7）。

- scanner_runs 的 container_name 與 image_ref：只能在 preparing → running 的那一次寫入，之後不可改；
  名稱一定是 secscan-run-<run 的 id>，映像一定有 tag 與 digest。
- runner_instances：runner 與 worker 的心跳列。
"""

from collections.abc import Mapping
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from tests.integration.scan_support import create_scan, scan_world
from tests.integration.sql_support import (
    CHECK_VIOLATION,
    INTEGRITY_CONSTRAINT_VIOLATION,
    UNIQUE_VIOLATION,
    violation,
)

pytestmark = pytest.mark.integration

LATER = datetime(2030, 1, 1, tzinfo=UTC)
LONG_AGO = datetime(2020, 1, 1, tzinfo=UTC)
IMAGE = "busybox:1.38.0@sha256:" + "ab" * 32
LEASE = {"lease_owner": "runner-1", "lease_expires_at": LATER, "heartbeat_at": LATER}

MOVE = (
    "UPDATE scanner_runs SET status = :status, lease_owner = :lease_owner, "
    "lease_expires_at = :lease_expires_at, heartbeat_at = :heartbeat_at, started_at = :started_at, "
    "finished_at = :finished_at, error_code = :error_code, container_name = :container_name, "
    "image_ref = :image_ref WHERE id = :id"
)
INSERT_RUN = (
    "INSERT INTO scanner_runs (scan_id, engine, sequence, status, container_name, image_ref) "
    "VALUES (:scan_id, 'zap', 2, 'queued', :container_name, :image_ref)"
)
INSERT_INSTANCE = (
    "INSERT INTO runner_instances (role, owner, software_version, capabilities, heartbeat_at) "
    "VALUES (:role, :owner, :software_version, CAST(:capabilities AS jsonb), :heartbeat_at)"
)


def _params(run_id: UUID, **overrides: object) -> dict[str, object]:
    params: dict[str, object] = {
        "id": run_id,
        "status": "running",
        "started_at": LATER,
        "finished_at": None,
        "error_code": None,
        "container_name": f"secscan-run-{run_id}",
        "image_ref": IMAGE,
        **LEASE,
    }
    params.update(overrides)
    return params


@pytest.fixture
def run_id(db_session: Session) -> UUID:
    """一個 preparing 的 fake run（還沒有容器）。"""
    scan = create_scan(db_session, scan_world(db_session))
    run_id: UUID = db_session.execute(
        text("SELECT id FROM scanner_runs WHERE scan_id = :scan"), {"scan": scan.id}
    ).scalar_one()
    db_session.execute(
        text(MOVE), _params(run_id, status="preparing", container_name=None, image_ref=None)
    )
    return run_id


def _container(session: Session, run_id: UUID) -> tuple[str | None, str | None]:
    row = session.execute(
        text("SELECT container_name, image_ref FROM scanner_runs WHERE id = :id"), {"id": run_id}
    ).one()
    return row.container_name, row.image_ref


def test_the_container_is_recorded_when_the_run_starts(db_session: Session, run_id: UUID) -> None:
    db_session.execute(text(MOVE), _params(run_id))
    db_session.execute(
        text(MOVE),
        _params(
            run_id, status="collected", lease_owner=None, lease_expires_at=None, heartbeat_at=None
        ),
    )
    db_session.execute(
        text(MOVE),
        _params(
            run_id,
            status="succeeded",
            lease_owner=None,
            lease_expires_at=None,
            heartbeat_at=None,
            finished_at=LATER,
        ),
    )

    assert _container(db_session, run_id) == (f"secscan-run-{run_id}", IMAGE)


def test_a_run_may_start_without_a_container(db_session: Session, run_id: UUID) -> None:
    """in-process 的 fake runner 不建立容器。"""
    db_session.execute(text(MOVE), _params(run_id, container_name=None, image_ref=None))

    assert _container(db_session, run_id) == (None, None)


@pytest.mark.parametrize(
    ("overrides", "constraint"),
    [
        (
            {"container_name": "secscan-run-00000000-0000-4000-8000-000000000000"},
            "ck_scanner_runs_container_matches_run",
        ),
        ({"container_name": "secscan-api-1"}, "ck_scanner_runs_container_matches_run"),
        ({"image_ref": "busybox:1.38.0"}, "ck_scanner_runs_image_ref_valid"),
        ({"image_ref": "busybox@sha256:" + "ab" * 32}, "ck_scanner_runs_image_ref_valid"),
        ({"image_ref": "busybox:1@sha256:" + "AB" * 32}, "ck_scanner_runs_image_ref_valid"),
        ({"image_ref": None}, "ck_scanner_runs_container_with_image"),
        ({"container_name": None}, "ck_scanner_runs_container_with_image"),
    ],
)
def test_container_checks(
    db_session: Session, run_id: UUID, overrides: dict[str, object], constraint: str
) -> None:
    error = violation(db_session, MOVE, _params(run_id, **overrides))

    assert (error.sqlstate, error.diag.constraint_name) == (CHECK_VIOLATION, constraint)


def test_a_queued_run_has_no_container(db_session: Session, run_id: UUID) -> None:
    scan_id = db_session.execute(
        text("SELECT scan_id FROM scanner_runs WHERE id = :id"), {"id": run_id}
    ).scalar_one()
    error = violation(
        db_session,
        INSERT_RUN,
        {"scan_id": scan_id, "container_name": None, "image_ref": IMAGE},
    )

    assert error.sqlstate in {CHECK_VIOLATION, INTEGRITY_CONSTRAINT_VIOLATION}


def _blocked(session: Session, statement: str, params: Mapping[str, object]) -> None:
    error = violation(session, statement, params)
    assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION
    assert str(error).startswith("scanner_runs: container")


def test_the_container_cannot_be_set_later(db_session: Session, run_id: UUID) -> None:
    db_session.execute(text(MOVE), _params(run_id, container_name=None, image_ref=None))

    _blocked(db_session, MOVE, _params(run_id))


def test_the_container_cannot_be_set_while_preparing(db_session: Session, run_id: UUID) -> None:
    _blocked(db_session, MOVE, _params(run_id, status="preparing"))


@pytest.mark.parametrize(
    "change",
    [
        {"container_name": None, "image_ref": None},
        {"image_ref": "busybox:1.37.0@sha256:" + "cd" * 32},
    ],
)
def test_the_container_cannot_change_once_recorded(
    db_session: Session, run_id: UUID, change: dict[str, object]
) -> None:
    db_session.execute(text(MOVE), _params(run_id))

    _blocked(db_session, MOVE, _params(run_id, status="collecting", **change))


# --- runner_instances ----------------------------------------------------------------------


def _instance(**overrides: object) -> dict[str, object]:
    params: dict[str, object] = {
        "role": "runner",
        "owner": f"runner:{uuid4().hex}",
        "software_version": "0.1.0",
        "capabilities": '{"engines": {}}',
        "heartbeat_at": LATER,
    }
    params.update(overrides)
    return params


def test_a_heartbeat_row_is_stored(db_session: Session) -> None:
    for role in ("runner", "worker"):
        db_session.execute(text(INSERT_INSTANCE), _instance(role=role))


@pytest.mark.parametrize(
    ("overrides", "constraint"),
    [
        ({"role": "admin"}, "ck_runner_instances_role_valid"),
        ({"owner": " "}, "ck_runner_instances_owner_not_blank"),
        ({"software_version": ""}, "ck_runner_instances_software_version_not_blank"),
        ({"capabilities": "[]"}, "ck_runner_instances_capabilities_valid"),
        ({"capabilities": '"x"'}, "ck_runner_instances_capabilities_valid"),
        (
            {"capabilities": '{"x": "' + "a" * 5000 + '"}'},
            "ck_runner_instances_capabilities_valid",
        ),
        ({"heartbeat_at": LONG_AGO}, "ck_runner_instances_times"),
    ],
)
def test_instance_checks(
    db_session: Session, overrides: dict[str, object], constraint: str
) -> None:
    error = violation(db_session, INSERT_INSTANCE, _instance(**overrides))

    assert (error.sqlstate, error.diag.constraint_name) == (CHECK_VIOLATION, constraint)


def test_an_owner_has_one_row(db_session: Session) -> None:
    params = _instance()
    db_session.execute(text(INSERT_INSTANCE), params)

    error = violation(db_session, INSERT_INSTANCE, params)

    assert (error.sqlstate, error.diag.constraint_name) == (
        UNIQUE_VIOLATION,
        "uq_runner_instances_owner",
    )
