"""scans、scanner_runs、scan_events、scan_operations 的 DB 約束與 trigger（docs/DECISIONS.md §13）。

直接用 SQL 驗證 schema 本身：即使程式有 bug，DB 也保證快照引用的資料屬於同一個 target、
一個 target 同時只有一個進行中的 scan、lease 與狀態一致、終止的 scan 與 run 不可再改、
事件與凍結的 operation 不可修改。
"""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from secscan.api_keys.domain import Principal
from secscan.auth_profiles.domain.credentials import AuthType, SecretValue
from secscan.auth_profiles.domain.model import ProfileInput
from secscan.auth_profiles.service import AuthProfileService
from secscan.grants.service import ScopeGrantService
from secscan.specs.domain.documents import SpecFormat
from secscan.specs.domain.model import SpecUpload
from secscan.specs.service import ApiSpecService
from secscan.targets.domain import TargetKind
from secscan.targets.service import TargetService
from tests.integration.api_support import MINIMAL_SPEC, VAMPI_ME
from tests.integration.scope_support import LAB, grant_request, members
from tests.integration.sql_support import (
    CHECK_VIOLATION,
    FOREIGN_KEY_VIOLATION,
    INTEGRITY_CONSTRAINT_VIOLATION,
    UNIQUE_VIOLATION,
    returning_id,
    violation,
)
from tests.secret_support import shared_cipher

pytestmark = pytest.mark.integration

NOW = datetime(2026, 10, 26, 8, 0, tzinfo=UTC)
# 一定晚於、早於資料列的 created_at（DB 的 now()）。
LATER = datetime(2030, 1, 1, tzinfo=UTC)
LONG_AGO = datetime(2020, 1, 1, tzinfo=UTC)
HASH = bytes(range(32))

INSERT_SCAN = (
    "INSERT INTO scans (project_id, target_id, target_origin, scope_grant_id, api_spec_id, "
    "auth_profile_id, auth_profile_version, auth_role, scan_profile, requests_per_second, "
    "max_requests, max_duration_seconds, status, idempotency_key, request_sha256, "
    "cancel_requested_at, created_by_key_id, finished_at) "
    "VALUES (:project_id, :target_id, :target_origin, :scope_grant_id, :api_spec_id, "
    ":auth_profile_id, :auth_profile_version, :auth_role, :scan_profile, :requests_per_second, "
    ":max_requests, :max_duration_seconds, :status, :idempotency_key, :request_sha256, "
    ":cancel_requested_at, :created_by_key_id, :finished_at) RETURNING id"
)
INSERT_RUN = (
    "INSERT INTO scanner_runs (scan_id, engine, sequence, status, lease_owner, lease_expires_at, "
    "heartbeat_at, started_at, finished_at, error_code) "
    "VALUES (:scan_id, :engine, :sequence, :status, :lease_owner, :lease_expires_at, "
    ":heartbeat_at, :started_at, :finished_at, :error_code) RETURNING id"
)
INSERT_EVENT = (
    "INSERT INTO scan_events (scan_id, sequence, event_type, scanner_run_id, payload) "
    "VALUES (:scan_id, :sequence, :event_type, :scanner_run_id, CAST(:payload AS jsonb))"
)
INSERT_OPERATION = (
    "INSERT INTO scan_operations (scan_id, ordinal, method, path, operation_id, "
    "ineligible_reason) VALUES (:scan_id, :ordinal, :method, :path, :operation_id, :reason)"
)


@dataclass(frozen=True)
class Snapshot:
    """project A 的兩個 target（各有 grant、規格與 profile），以及 project B 的一個 target。"""

    key_id: UUID
    project_a: UUID
    project_b: UUID
    target: UUID
    sibling: UUID
    other_project_target: UUID
    grant: UUID
    sibling_grant: UUID
    spec: UUID
    sibling_spec: UUID
    profile: UUID
    sibling_profile: UUID


def _target(session: Session, principal: Principal, project_id: UUID, host: str) -> UUID:
    return (
        TargetService(session, lab=LAB)
        .create(
            principal,
            project_id,
            name=host,
            kind=TargetKind.API,
            base_url=f"http://{host}:5000",
            request_id=None,
        )
        .id
    )


def _grant(session: Session, principal: Principal, target_id: UUID, host: str) -> UUID:
    request = grant_request(NOW, origins=(f"http://{host}:5000",))
    return (
        ScopeGrantService(session, lab=LAB)
        .request(principal, target_id, request, now=NOW, request_id=None)
        .id
    )


def _spec(session: Session, principal: Principal, target_id: UUID) -> UUID:
    upload = SpecUpload(spec_format=SpecFormat.JSON, content=MINIMAL_SPEC)
    return ApiSpecService(session).upload(principal, target_id, upload, request_id=None).id


def _profile(session: Session, principal: Principal, target_id: UUID) -> UUID:
    request = ProfileInput(
        name="profile",
        role_label="standard_user",
        type=AuthType.BEARER,
        header_name=None,
        secret=SecretValue("t1"),
        preflight=VAMPI_ME,
    )
    service = AuthProfileService(session, cipher=shared_cipher())
    return service.create(principal, target_id, request, request_id=None).id


@pytest.fixture
def snap(db_session: Session) -> Snapshot:
    team = members(db_session, NOW)
    admin = team.admin
    target = _target(db_session, admin, team.project_a, "vampi-a")
    sibling = _target(db_session, admin, team.project_a, "vampi-b")
    return Snapshot(
        key_id=admin.key_id,
        project_a=team.project_a,
        project_b=team.project_b,
        target=target,
        sibling=sibling,
        other_project_target=_target(db_session, admin, team.project_b, "vampi-c"),
        grant=_grant(db_session, admin, target, "vampi-a"),
        sibling_grant=_grant(db_session, admin, sibling, "vampi-b"),
        spec=_spec(db_session, admin, target),
        sibling_spec=_spec(db_session, admin, sibling),
        profile=_profile(db_session, admin, target),
        sibling_profile=_profile(db_session, admin, sibling),
    )


def _scan_params(snap: Snapshot, **overrides: object) -> dict[str, object]:
    params: dict[str, object] = {
        "project_id": snap.project_a,
        "target_id": snap.target,
        "target_origin": "http://vampi-a:5000",
        "scope_grant_id": snap.grant,
        "api_spec_id": snap.spec,
        "auth_profile_id": snap.profile,
        "auth_profile_version": 1,
        "auth_role": "standard_user",
        "scan_profile": "api_active_lab",
        "requests_per_second": 2,
        "max_requests": 1_000,
        "max_duration_seconds": 1_500,
        "status": "queued",
        "idempotency_key": uuid4().hex,
        "request_sha256": HASH,
        "cancel_requested_at": None,
        "created_by_key_id": snap.key_id,
        "finished_at": None,
    }
    params.update(overrides)
    return params


def _insert_scan(session: Session, snap: Snapshot, **overrides: object) -> UUID:
    scan_id = returning_id(session, INSERT_SCAN, _scan_params(snap, **overrides))
    assert scan_id is not None
    return scan_id


def _run_params(scan_id: UUID, **overrides: object) -> dict[str, object]:
    params: dict[str, object] = {
        "scan_id": scan_id,
        "engine": "fake",
        "sequence": 1,
        "status": "queued",
        "lease_owner": None,
        "lease_expires_at": None,
        "heartbeat_at": None,
        "started_at": None,
        "finished_at": None,
        "error_code": None,
    }
    params.update(overrides)
    return params


def _insert_run(session: Session, scan_id: UUID, **overrides: object) -> UUID:
    run_id = returning_id(session, INSERT_RUN, _run_params(scan_id, **overrides))
    assert run_id is not None
    return run_id


def _rejected(session: Session, statement: str, params: Mapping[str, object]) -> tuple[str, str]:
    error = violation(session, statement, params)
    return error.sqlstate or "", error.diag.constraint_name or ""


def _blocked(session: Session, statement: str, params: Mapping[str, object], table: str) -> None:
    error = violation(session, statement, params)
    assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION
    assert str(error).startswith(table)


# --- scans ---------------------------------------------------------------------------------


def test_a_valid_snapshot_is_stored_with_a_queue_position(
    db_session: Session, snap: Snapshot
) -> None:
    first = _insert_scan(db_session, snap)
    second = _insert_scan(db_session, snap, target_id=snap.sibling, **_sibling(snap))

    positions = db_session.execute(
        text("SELECT queue_position FROM scans WHERE id IN (:a, :b) ORDER BY queue_position"),
        {"a": first, "b": second},
    ).scalars()
    assert len(list(positions)) == 2


def _sibling(snap: Snapshot) -> dict[str, object]:
    return {
        "target_origin": "http://vampi-b:5000",
        "scope_grant_id": snap.sibling_grant,
        "api_spec_id": snap.sibling_spec,
        "auth_profile_id": snap.sibling_profile,
    }


def test_the_queue_position_is_generated_by_the_database(
    db_session: Session, snap: Snapshot
) -> None:
    """identity（GENERATED ALWAYS）：client 不能指定佇列的位置插隊 [S82]。"""
    statement = INSERT_SCAN.replace("(project_id,", "(queue_position, project_id,").replace(
        "VALUES (:project_id,", "VALUES (1, :project_id,"
    )
    with pytest.raises(DBAPIError) as caught, db_session.begin_nested():
        db_session.execute(text(statement), _scan_params(snap))
    assert getattr(caught.value.orig, "sqlstate", None) == "428C9"


@pytest.mark.parametrize(
    ("overrides", "constraint"),
    [
        ({"status": "paused"}, "ck_scans_status_valid"),
        ({"scan_profile": "full_scan"}, "ck_scans_scan_profile_valid"),
        ({"max_requests": 0}, "ck_scans_budget_positive"),
        ({"requests_per_second": -1}, "ck_scans_budget_positive"),
        ({"idempotency_key": "short"}, "ck_scans_idempotency_key_valid"),
        ({"idempotency_key": "x" * 15 + " "}, "ck_scans_idempotency_key_valid"),
        ({"request_sha256": b"\x00" * 31}, "ck_scans_request_sha256_length"),
        ({"auth_profile_version": None}, "ck_scans_auth_consistent"),
        ({"auth_role": "anonymous"}, "ck_scans_auth_consistent"),
        (
            {"auth_profile_id": None, "auth_profile_version": None},
            "ck_scans_auth_consistent",
        ),
        (
            {"auth_role": "Standard_User"},
            "ck_scans_auth_role_valid",
        ),
        ({"api_spec_id": None}, "ck_scans_spec_matches_profile"),
        ({"scan_profile": "web_active_lab"}, "ck_scans_spec_matches_profile"),
        ({"target_origin": "http://VAMPI-A:5000"}, "ck_scans_origin_canonical"),
        ({"status": "completed"}, "ck_scans_finished_matches_status"),
        ({"finished_at": LATER}, "ck_scans_finished_matches_status"),
        ({"status": "cancelling"}, "ck_scans_cancel_matches_status"),
        ({"cancel_requested_at": LONG_AGO}, "ck_scans_times"),
        ({"status": "failed", "finished_at": LONG_AGO}, "ck_scans_times"),
    ],
)
def test_scan_checks(
    db_session: Session, snap: Snapshot, overrides: dict[str, object], constraint: str
) -> None:
    assert _rejected(db_session, INSERT_SCAN, _scan_params(snap, **overrides)) == (
        CHECK_VIOLATION,
        constraint,
    )


def test_an_anonymous_web_scan_is_valid(db_session: Session, snap: Snapshot) -> None:
    _insert_scan(
        db_session,
        snap,
        auth_profile_id=None,
        auth_profile_version=None,
        auth_role="anonymous",
        scan_profile="web_active_lab",
        api_spec_id=None,
    )


@pytest.mark.parametrize(
    ("overrides", "constraint"),
    [
        ({"project_id": "B"}, "fk_scans_target_project"),
        ({"scope_grant_id": "sibling_grant"}, "fk_scans_grant_target"),
        ({"api_spec_id": "sibling_spec"}, "fk_scans_spec_target"),
        ({"auth_profile_id": "sibling_profile"}, "fk_scans_profile_target_role"),
        ({"auth_role": "admin_user"}, "fk_scans_profile_target_role"),
        ({"auth_profile_version": 2}, "fk_scans_profile_version"),
        ({"created_by_key_id": "missing"}, "fk_scans_created_by_key_id_api_keys"),
    ],
)
def test_the_snapshot_references_belong_to_the_same_target(
    db_session: Session, snap: Snapshot, overrides: dict[str, object], constraint: str
) -> None:
    """快照引用的 grant、規格、profile 都屬於 scan 的 target；target 屬於 scan 的 project。"""
    resolved = {
        "B": snap.project_b,
        "sibling_grant": snap.sibling_grant,
        "sibling_spec": snap.sibling_spec,
        "sibling_profile": snap.sibling_profile,
        "missing": uuid4(),
    }
    params = {key: resolved.get(str(value), value) for key, value in overrides.items()}

    assert _rejected(db_session, INSERT_SCAN, _scan_params(snap, **params)) == (
        FOREIGN_KEY_VIOLATION,
        constraint,
    )


def test_an_idempotency_key_is_unique_within_a_project(db_session: Session, snap: Snapshot) -> None:
    key = uuid4().hex
    _insert_scan(db_session, snap, idempotency_key=key, status="failed", finished_at=LATER)

    sibling = _scan_params(snap, idempotency_key=key, target_id=snap.sibling, **_sibling(snap))
    assert _rejected(db_session, INSERT_SCAN, sibling) == (
        UNIQUE_VIOLATION,
        "uq_scans_project_id_idempotency_key",
    )


def test_only_one_active_scan_per_target(db_session: Session, snap: Snapshot) -> None:
    first = _insert_scan(db_session, snap)

    assert _rejected(db_session, INSERT_SCAN, _scan_params(snap)) == (
        UNIQUE_VIOLATION,
        "uq_scans_active_target",
    )

    db_session.execute(
        text("UPDATE scans SET status = 'failed', finished_at = now() WHERE id = :id"),
        {"id": first},
    )
    _insert_scan(db_session, snap)


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE scans SET target_origin = 'http://other:5000', status = 'running' WHERE id = :id",
        "UPDATE scans SET max_requests = 1, status = 'running' WHERE id = :id",
        "UPDATE scans SET idempotency_key = 'another-key-0123456789' WHERE id = :id",
        "UPDATE scans SET created_at = now() - interval '1 day' WHERE id = :id",
    ],
)
def test_the_snapshot_cannot_change(db_session: Session, snap: Snapshot, statement: str) -> None:
    scan_id = _insert_scan(db_session, snap)

    _blocked(db_session, statement, {"id": scan_id}, "scans")


def test_the_status_of_an_unfinished_scan_can_change(db_session: Session, snap: Snapshot) -> None:
    scan_id = _insert_scan(db_session, snap)

    db_session.execute(text("UPDATE scans SET status = 'running' WHERE id = :id"), {"id": scan_id})
    db_session.execute(
        text("UPDATE scans SET status = 'cancelling', cancel_requested_at = now() WHERE id = :id"),
        {"id": scan_id},
    )
    db_session.execute(
        text("UPDATE scans SET status = 'cancelled', finished_at = now() WHERE id = :id"),
        {"id": scan_id},
    )


def test_a_cancel_request_cannot_be_changed(db_session: Session, snap: Snapshot) -> None:
    scan_id = _insert_scan(db_session, snap)
    db_session.execute(
        text("UPDATE scans SET cancel_requested_at = now() WHERE id = :id"), {"id": scan_id}
    )

    for statement in (
        "UPDATE scans SET cancel_requested_at = NULL WHERE id = :id",
        "UPDATE scans SET cancel_requested_at = now() + interval '1s' WHERE id = :id",
    ):
        _blocked(db_session, statement, {"id": scan_id}, "scans")


def test_a_finished_scan_cannot_change(db_session: Session, snap: Snapshot) -> None:
    scan_id = _insert_scan(db_session, snap, status="completed", finished_at=LATER)

    _blocked(
        db_session, "UPDATE scans SET status = 'completed' WHERE id = :id", {"id": scan_id}, "scans"
    )


@pytest.mark.parametrize(
    ("statement", "table"),
    # TRUNCATE 要 CASCADE 才會走到 trigger（否則 FK 先拒絕）；被一併清除的資料表也都擋下。
    [("DELETE FROM scans WHERE id = :id", "scans"), ("TRUNCATE scans CASCADE", "scan")],
)
def test_scans_cannot_be_deleted(
    db_session: Session, snap: Snapshot, statement: str, table: str
) -> None:
    scan_id = _insert_scan(db_session, snap)

    _blocked(db_session, statement, {"id": scan_id}, table)


# --- scanner_runs --------------------------------------------------------------------------

LEASE = {"lease_owner": "runner-1", "lease_expires_at": LATER, "heartbeat_at": LATER}


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"status": "preparing", "started_at": LATER, **LEASE}, "queued"),
        ({**LEASE}, "queued"),
        ({"status": "cancelled", "finished_at": LATER}, "queued"),
    ],
)
def test_a_new_run_is_queued_without_a_lease(
    db_session: Session, snap: Snapshot, overrides: dict[str, object], message: str
) -> None:
    scan_id = _insert_scan(db_session, snap)

    error = violation(db_session, INSERT_RUN, _run_params(scan_id, **overrides))

    assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION
    assert message in str(error)


RUN_UPDATE = (
    "UPDATE scanner_runs SET status = :status, lease_owner = :lease_owner, "
    "lease_expires_at = :lease_expires_at, heartbeat_at = :heartbeat_at, "
    "started_at = :started_at, finished_at = :finished_at, error_code = :error_code "
    "WHERE id = :id"
)


def _run_update(run_id: UUID, **overrides: object) -> dict[str, object]:
    params = _run_params(run_id, **overrides)
    params["id"] = run_id
    return params


@pytest.mark.parametrize(
    ("overrides", "constraint"),
    [
        ({"status": "paused", "started_at": LATER}, "ck_scanner_runs_status_valid"),
        ({"status": "preparing", "started_at": LATER}, "ck_scanner_runs_lease_matches_status"),
        (
            {"status": "collected", "started_at": LATER, **LEASE},
            "ck_scanner_runs_lease_matches_status",
        ),
        (
            {"status": "running", "started_at": LATER, **LEASE, "heartbeat_at": None},
            "ck_scanner_runs_lease_matches_status",
        ),
        (
            {"status": "running", "started_at": LATER, **LEASE, "lease_owner": " "},
            "ck_scanner_runs_lease_owner_not_blank",
        ),
        ({"status": "succeeded", "started_at": LATER}, "ck_scanner_runs_finished_matches_status"),
        (
            {"status": "failed", "started_at": LATER, "finished_at": LATER},
            "ck_scanner_runs_error_code_matches_status",
        ),
        (
            {
                "status": "succeeded",
                "started_at": LATER,
                "finished_at": LATER,
                "error_code": "ENGINE_FAILED",
            },
            "ck_scanner_runs_error_code_matches_status",
        ),
        (
            {
                "status": "failed",
                "started_at": LATER,
                "finished_at": LATER,
                "error_code": "engine failed",
            },
            "ck_scanner_runs_error_code_valid",
        ),
        ({"status": "running", **LEASE}, "ck_scanner_runs_started_matches_status"),
        ({"started_at": LATER}, "ck_scanner_runs_started_matches_status"),
        ({"status": "running", "started_at": LONG_AGO, **LEASE}, "ck_scanner_runs_times"),
        (
            {"status": "running", "started_at": LATER, **LEASE, "heartbeat_at": LONG_AGO},
            "ck_scanner_runs_times",
        ),
    ],
)
def test_run_checks(
    db_session: Session, snap: Snapshot, overrides: dict[str, object], constraint: str
) -> None:
    run_id = _insert_run(db_session, _insert_scan(db_session, snap))

    assert _rejected(db_session, RUN_UPDATE, _run_update(run_id, **overrides)) == (
        CHECK_VIOLATION,
        constraint,
    )


@pytest.mark.parametrize(
    ("overrides", "constraint"),
    [
        ({"engine": "burp"}, "ck_scanner_runs_engine_valid"),
        ({"sequence": 0}, "ck_scanner_runs_sequence_valid"),
        ({"sequence": 5}, "ck_scanner_runs_sequence_valid"),
    ],
)
def test_run_identity_checks(
    db_session: Session, snap: Snapshot, overrides: dict[str, object], constraint: str
) -> None:
    scan_id = _insert_scan(db_session, snap)

    assert _rejected(db_session, INSERT_RUN, _run_params(scan_id, **overrides)) == (
        CHECK_VIOLATION,
        constraint,
    )


def test_a_scan_has_one_run_per_engine_and_sequence(db_session: Session, snap: Snapshot) -> None:
    scan_id = _insert_scan(db_session, snap)
    _insert_run(db_session, scan_id, engine="zap", sequence=1)

    assert _rejected(db_session, INSERT_RUN, _run_params(scan_id, engine="nuclei", sequence=1)) == (
        UNIQUE_VIOLATION,
        "uq_scanner_runs_scan_id_sequence",
    )
    assert _rejected(db_session, INSERT_RUN, _run_params(scan_id, engine="zap", sequence=2)) == (
        UNIQUE_VIOLATION,
        "uq_scanner_runs_scan_id_engine",
    )


def test_a_run_goes_through_its_lifecycle(db_session: Session, snap: Snapshot) -> None:
    run_id = _insert_run(db_session, _insert_scan(db_session, snap))
    lease = {"lease_owner": "runner-1", "lease_expires_at": LATER, "heartbeat_at": LATER}

    for overrides in (
        {"status": "preparing", "started_at": LATER, **lease},
        {"status": "running", "started_at": LATER, **lease},
        {"status": "collected", "started_at": LATER},
        {"status": "normalizing", "started_at": LATER, **lease},
        {"status": "succeeded", "started_at": LATER, "finished_at": LATER},
    ):
        db_session.execute(text(RUN_UPDATE), _run_update(run_id, **overrides))


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE scanner_runs SET engine = 'zap' WHERE id = :id",
        "UPDATE scanner_runs SET sequence = 2 WHERE id = :id",
        "UPDATE scanner_runs SET scan_id = :other WHERE id = :id",
    ],
)
def test_the_identity_of_a_run_cannot_change(
    db_session: Session, snap: Snapshot, statement: str
) -> None:
    run_id = _insert_run(db_session, _insert_scan(db_session, snap))
    other_scan = _insert_scan(db_session, snap, target_id=snap.sibling, **_sibling(snap))

    _blocked(db_session, statement, {"id": run_id, "other": other_scan}, "scanner_runs")


def test_a_finished_run_cannot_change(db_session: Session, snap: Snapshot) -> None:
    run_id = _insert_run(db_session, _insert_scan(db_session, snap))
    db_session.execute(text(RUN_UPDATE), _run_update(run_id, status="cancelled", finished_at=LATER))

    _blocked(
        db_session,
        "UPDATE scanner_runs SET status = 'cancelled' WHERE id = :id",
        {"id": run_id},
        "scanner_runs",
    )


@pytest.mark.parametrize(
    ("statement", "table"),
    [
        ("DELETE FROM scanner_runs WHERE id = :id", "scanner_runs"),
        ("TRUNCATE scanner_runs CASCADE", "scan"),
    ],
)
def test_runs_cannot_be_deleted(
    db_session: Session, snap: Snapshot, statement: str, table: str
) -> None:
    run_id = _insert_run(db_session, _insert_scan(db_session, snap))

    _blocked(db_session, statement, {"id": run_id}, table)


# --- scan_events ---------------------------------------------------------------------------


def _event_params(scan_id: UUID, **overrides: object) -> dict[str, object]:
    params: dict[str, object] = {
        "scan_id": scan_id,
        "sequence": 1,
        "event_type": "scan.created",
        "scanner_run_id": None,
        "payload": '{"status": "queued"}',
    }
    params.update(overrides)
    return params


@pytest.mark.parametrize(
    ("overrides", "constraint"),
    [
        ({"sequence": 0}, "ck_scan_events_sequence_positive"),
        ({"event_type": "scan.deleted"}, "ck_scan_events_event_type_valid"),
        ({"event_type": "run.status"}, "ck_scan_events_run_matches_type"),
        ({"payload": "[]"}, "ck_scan_events_payload_valid"),
        ({"payload": '{"x": "' + "a" * 1_024 + '"}'}, "ck_scan_events_payload_valid"),
    ],
)
def test_event_checks(
    db_session: Session, snap: Snapshot, overrides: dict[str, object], constraint: str
) -> None:
    scan_id = _insert_scan(db_session, snap)

    assert _rejected(db_session, INSERT_EVENT, _event_params(scan_id, **overrides)) == (
        CHECK_VIOLATION,
        constraint,
    )


def test_an_event_names_a_run_of_the_same_scan(db_session: Session, snap: Snapshot) -> None:
    scan_id = _insert_scan(db_session, snap)
    other_scan = _insert_scan(db_session, snap, target_id=snap.sibling, **_sibling(snap))
    other_run = _insert_run(db_session, other_scan)
    params = _event_params(scan_id, event_type="run.status", scanner_run_id=other_run)

    assert _rejected(db_session, INSERT_EVENT, params) == (
        FOREIGN_KEY_VIOLATION,
        "fk_scan_events_run_scan",
    )


def test_event_sequences_are_unique_per_scan(db_session: Session, snap: Snapshot) -> None:
    scan_id = _insert_scan(db_session, snap)
    db_session.execute(text(INSERT_EVENT), _event_params(scan_id))

    assert _rejected(db_session, INSERT_EVENT, _event_params(scan_id)) == (
        UNIQUE_VIOLATION,
        "pk_scan_events",
    )


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE scan_events SET payload = '{}'::jsonb WHERE scan_id = :id",
        "DELETE FROM scan_events WHERE scan_id = :id",
        "TRUNCATE scan_events",
    ],
)
def test_events_are_append_only(db_session: Session, snap: Snapshot, statement: str) -> None:
    scan_id = _insert_scan(db_session, snap)
    db_session.execute(text(INSERT_EVENT), _event_params(scan_id))

    _blocked(db_session, statement, {"id": scan_id}, "scan_events")


# --- scan_operations -----------------------------------------------------------------------


def _operation_params(scan_id: UUID, **overrides: object) -> dict[str, object]:
    params: dict[str, object] = {
        "scan_id": scan_id,
        "ordinal": 0,
        "method": "GET",
        "path": "/users/v1",
        "operation_id": "listUsers",
        "reason": None,
    }
    params.update(overrides)
    return params


@pytest.mark.parametrize(
    ("overrides", "constraint"),
    [
        ({"method": "get"}, "ck_scan_operations_method_valid"),
        ({"method": "CONNECT"}, "ck_scan_operations_method_valid"),
        ({"path": "users"}, "ck_scan_operations_path_valid"),
        ({"ordinal": -1}, "ck_scan_operations_ordinal_valid"),
        ({"ordinal": 1_000}, "ck_scan_operations_ordinal_valid"),
        ({"operation_id": "  "}, "ck_scan_operations_operation_id_not_blank"),
        ({"reason": "NOT_IN_SPEC"}, "ck_scan_operations_reason_valid"),
    ],
)
def test_operation_checks(
    db_session: Session, snap: Snapshot, overrides: dict[str, object], constraint: str
) -> None:
    scan_id = _insert_scan(db_session, snap)

    assert _rejected(db_session, INSERT_OPERATION, _operation_params(scan_id, **overrides)) == (
        CHECK_VIOLATION,
        constraint,
    )


def test_operations_are_unique_per_scan(db_session: Session, snap: Snapshot) -> None:
    scan_id = _insert_scan(db_session, snap)
    db_session.execute(text(INSERT_OPERATION), _operation_params(scan_id, reason="PATH_EXCLUDED"))

    assert _rejected(db_session, INSERT_OPERATION, _operation_params(scan_id, ordinal=1)) == (
        UNIQUE_VIOLATION,
        "uq_scan_operations_scan_id_method_path",
    )


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE scan_operations SET ineligible_reason = NULL WHERE scan_id = :id",
        "DELETE FROM scan_operations WHERE scan_id = :id",
        "TRUNCATE scan_operations",
    ],
)
def test_operations_are_append_only(db_session: Session, snap: Snapshot, statement: str) -> None:
    scan_id = _insert_scan(db_session, snap)
    db_session.execute(text(INSERT_OPERATION), _operation_params(scan_id, reason="PATH_EXCLUDED"))

    _blocked(db_session, statement, {"id": scan_id}, "scan_operations")
