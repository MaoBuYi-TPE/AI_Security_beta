"""targets 與 scope_grants 的 DB 約束與 trigger（docs/DECISIONS.md §10.4）。

直接用 SQL 驗證 schema 本身：即使程式有 bug，DB 也會擋下不合規則的資料、狀態轉換與範圍修改。
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DataError
from sqlalchemy.orm import Session

from tests.integration.sql_support import (
    CHECK_VIOLATION,
    FOREIGN_KEY_VIOLATION,
    INTEGRITY_CONSTRAINT_VIOLATION,
    RESTRICT_VIOLATION,
    UNIQUE_VIOLATION,
    insert_key,
    insert_project,
    returning_id,
    violation,
)

pytestmark = pytest.mark.integration

ORIGIN = "http://vampi-vuln:5000"
INSERT_TARGET = (
    "INSERT INTO targets (project_id, name, kind, canonical_origin, environment) "
    "VALUES (:project_id, :name, :kind, :canonical_origin, :environment) RETURNING id"
)
INSERT_GRANT = (
    "INSERT INTO scope_grants (target_id, version, status, allowed_origins, allowed_ips, "
    "allowed_paths, allow_all_paths, excluded_paths, allowed_methods, requests_per_second, "
    "max_requests, max_duration_seconds, authorization_reference, valid_from, valid_until, "
    "requested_by_key_id, approved_by_key_id, approved_at, approval_note, "
    "revoked_by_key_id, revoked_at, revocation_reason) "
    "VALUES (:target_id, :version, :status, :allowed_origins, CAST(:allowed_ips AS inet[]), "
    ":allowed_paths, :allow_all_paths, :excluded_paths, :allowed_methods, :requests_per_second, "
    ":max_requests, :max_duration_seconds, :authorization_reference, :valid_from, :valid_until, "
    ":requested_by_key_id, :approved_by_key_id, :approved_at, :approval_note, "
    ":revoked_by_key_id, :revoked_at, :revocation_reason) RETURNING id"
)
APPROVE = (
    "UPDATE scope_grants SET status = 'approved', approved_by_key_id = :key, "
    "approved_at = now(), approval_note = 'checked' WHERE id = :id"
)
REVOKE = (
    "UPDATE scope_grants SET status = 'revoked', revoked_by_key_id = :key, "
    "revoked_at = now(), revocation_reason = 'done' WHERE id = :id"
)


@dataclass(frozen=True)
class Lab:
    project_id: UUID
    key_id: UUID
    target_id: UUID
    now: datetime


def _target_params(project_id: UUID, **overrides: object) -> dict[str, object]:
    params: dict[str, object] = {
        "project_id": project_id,
        "name": "vampi",
        "kind": "api",
        "canonical_origin": ORIGIN,
        "environment": "lab",
    }
    params.update(overrides)
    return params


def _insert_target(session: Session, project_id: UUID, **overrides: object) -> UUID:
    target_id = returning_id(session, INSERT_TARGET, _target_params(project_id, **overrides))
    assert target_id is not None
    return target_id


@pytest.fixture
def lab(db_session: Session) -> Lab:
    project_id = insert_project(db_session)
    now = db_session.execute(text("SELECT now()")).scalar()
    assert isinstance(now, datetime)
    return Lab(
        project_id=project_id,
        key_id=insert_key(db_session),
        target_id=_insert_target(db_session, project_id),
        now=now,
    )


def _grant_params(lab: Lab, **overrides: object) -> dict[str, object]:
    params: dict[str, object] = {
        "target_id": lab.target_id,
        "version": 1,
        "status": "pending",
        "allowed_origins": [ORIGIN],
        "allowed_ips": ["10.89.7.20"],
        "allowed_paths": ["/users/v1"],
        "allow_all_paths": False,
        "excluded_paths": [],
        "allowed_methods": ["GET"],
        "requests_per_second": 2,
        "max_requests": 5000,
        "max_duration_seconds": 1500,
        "authorization_reference": "LAB-ASSET-001",
        "valid_from": lab.now - timedelta(hours=1),
        "valid_until": lab.now + timedelta(days=1),
        "requested_by_key_id": lab.key_id,
        "approved_by_key_id": None,
        "approved_at": None,
        "approval_note": None,
        "revoked_by_key_id": None,
        "revoked_at": None,
        "revocation_reason": None,
    }
    params.update(overrides)
    return params


def _approval(lab: Lab, **overrides: object) -> dict[str, object]:
    fields: dict[str, object] = {
        "status": "approved",
        "approved_by_key_id": lab.key_id,
        "approved_at": lab.now,
        "approval_note": "checked",
    }
    fields.update(overrides)
    return fields


def _revocation(lab: Lab, **overrides: object) -> dict[str, object]:
    fields: dict[str, object] = {
        "status": "revoked",
        "revoked_by_key_id": lab.key_id,
        "revoked_at": lab.now,
        "revocation_reason": "done",
    }
    fields.update(overrides)
    return fields


def _approved_then_revoked(lab: Lab, **revocation: object) -> dict[str, object]:
    """先核准、後撤銷的 grant（status 以撤銷為準）。"""
    return {**_approval(lab), **_revocation(lab, **revocation)}


def _insert_grant(session: Session, lab: Lab, **overrides: object) -> UUID:
    grant_id = returning_id(session, INSERT_GRANT, _grant_params(lab, **overrides))
    assert grant_id is not None
    return grant_id


# --- targets --------------------------------------------------------------------------------


def test_target_is_enabled_by_default(db_session: Session, lab: Lab) -> None:
    row = db_session.execute(
        text("SELECT enabled, created_at FROM targets WHERE id = :id"), {"id": lab.target_id}
    ).one()

    assert row.enabled is True
    assert row.created_at.utcoffset() == timedelta(0)


def test_target_project_must_exist(db_session: Session) -> None:
    error = violation(db_session, INSERT_TARGET, _target_params(uuid4()))

    assert (error.sqlstate, error.diag.constraint_name) == (
        FOREIGN_KEY_VIOLATION,
        "fk_targets_project_id_projects",
    )


def test_target_origin_is_unique_within_a_project(db_session: Session, lab: Lab) -> None:
    error = violation(db_session, INSERT_TARGET, _target_params(lab.project_id, name="again"))

    assert (error.sqlstate, error.diag.constraint_name) == (
        UNIQUE_VIOLATION,
        "uq_targets_project_id_canonical_origin",
    )
    assert _insert_target(db_session, insert_project(db_session, "other"))


@pytest.mark.parametrize(
    ("column", "value", "constraint"),
    [
        ("name", "   ", "ck_targets_name_not_blank"),
        ("kind", "graphql", "ck_targets_kind_valid"),
        ("environment", "prod", "ck_targets_environment_valid"),
        ("canonical_origin", "https://vampi-vuln:5000", "ck_targets_origin_canonical"),
        ("canonical_origin", "http://VAMPI-VULN:5000", "ck_targets_origin_canonical"),
        ("canonical_origin", "http://vampi-vuln:05000", "ck_targets_origin_canonical"),
        ("canonical_origin", "http://vampi-vuln:5000/", "ck_targets_origin_canonical"),
        ("canonical_origin", "http://user@vampi-vuln", "ck_targets_origin_canonical"),
        ("canonical_origin", "", "ck_targets_origin_canonical"),
    ],
)
def test_target_checks(db_session: Session, column: str, value: str, constraint: str) -> None:
    project_id = insert_project(db_session)

    error = violation(db_session, INSERT_TARGET, _target_params(project_id, **{column: value}))

    assert (error.sqlstate, error.diag.constraint_name) == (CHECK_VIOLATION, constraint)


def test_project_with_targets_cannot_be_deleted(db_session: Session, lab: Lab) -> None:
    error = violation(db_session, "DELETE FROM projects WHERE id = :id", {"id": lab.project_id})

    assert (error.sqlstate, error.diag.constraint_name) == (
        RESTRICT_VIOLATION,
        "fk_targets_project_id_projects",
    )


# --- scope_grants：資料 ---------------------------------------------------------------------


def test_consistent_grants_are_accepted(db_session: Session, lab: Lab) -> None:
    later = lab.now + timedelta(seconds=1)

    assert _insert_grant(db_session, lab)
    assert _insert_grant(
        db_session, lab, version=2, allowed_paths=[], allow_all_paths=True, **_approval(lab)
    )
    assert _insert_grant(db_session, lab, version=3, **_revocation(lab))
    assert _insert_grant(db_session, lab, version=4, **_approved_then_revoked(lab))
    assert _insert_grant(
        db_session, lab, version=5, **_approved_then_revoked(lab, revoked_at=later)
    )


def test_ips_are_stored_as_inet(db_session: Session, lab: Lab) -> None:
    grant_id = _insert_grant(db_session, lab, allowed_ips=["10.89.7.20", "10.89.7.21"])

    row = db_session.execute(
        text(
            "SELECT pg_typeof(allowed_ips)::text AS type, "
            "allowed_ips = CAST(:expected AS inet[]) AS same FROM scope_grants WHERE id = :id"
        ),
        {"id": grant_id, "expected": ["10.89.7.20", "10.89.7.21"]},
    ).one()

    assert (row.type, row.same) == ("inet[]", True)
    with pytest.raises(DataError), db_session.begin_nested():
        _insert_grant(db_session, lab, version=2, allowed_ips=["vampi-vuln"])


@pytest.mark.parametrize(
    ("column", "constraint"),
    [
        ("target_id", "fk_scope_grants_target_id_targets"),
        ("requested_by_key_id", "fk_scope_grants_requested_by_key_id_api_keys"),
        ("approved_by_key_id", "fk_scope_grants_approved_by_key_id_api_keys"),
        ("revoked_by_key_id", "fk_scope_grants_revoked_by_key_id_api_keys"),
    ],
)
def test_grant_references_must_exist(
    db_session: Session, lab: Lab, column: str, constraint: str
) -> None:
    params = _grant_params(lab, **{**_approved_then_revoked(lab), column: uuid4()})

    error = violation(db_session, INSERT_GRANT, params)

    assert (error.sqlstate, error.diag.constraint_name) == (FOREIGN_KEY_VIOLATION, constraint)


def test_version_is_unique_per_target(db_session: Session, lab: Lab) -> None:
    _insert_grant(db_session, lab)

    error = violation(db_session, INSERT_GRANT, _grant_params(lab))

    assert (error.sqlstate, error.diag.constraint_name) == (
        UNIQUE_VIOLATION,
        "uq_scope_grants_target_id_version",
    )


type Overrides = Callable[[Lab], dict[str, Any]]

SECOND = timedelta(seconds=1)
# 每一個 CHECK 都至少有一筆會違反它的資料（CHECK 的總數在 test_schema_constraints.py 檢查）。
BAD_ROWS: list[tuple[str, Overrides, str]] = [
    ("version-0", lambda lab: {"version": 0}, "version_positive"),
    # CHECK 依名稱的字母順序檢查：帶上撤銷紀錄讓 status_matches_decisions 成立，
    # 只剩 status_valid 會失敗。
    (
        "expired-is-not-stored",
        lambda lab: {**_revocation(lab), "status": "expired"},
        "status_valid",
    ),
    ("no-origins", lambda lab: {"allowed_origins": []}, "origins_count"),
    (
        "five-origins",
        lambda lab: {"allowed_origins": [f"http://lab-{n}" for n in range(5)]},
        "origins_count",
    ),
    ("no-ips", lambda lab: {"allowed_ips": []}, "ips_count"),
    (
        "seventeen-ips",
        lambda lab: {"allowed_ips": [f"10.89.7.{n + 1}" for n in range(17)]},
        "ips_count",
    ),
    ("no-methods", lambda lab: {"allowed_methods": []}, "methods_valid"),
    ("trace", lambda lab: {"allowed_methods": ["TRACE"]}, "methods_valid"),
    ("lowercase-method", lambda lab: {"allowed_methods": ["get"]}, "methods_valid"),
    ("all-paths-with-list", lambda lab: {"allow_all_paths": True}, "paths_valid"),
    ("no-paths", lambda lab: {"allowed_paths": []}, "paths_valid"),
    (
        "too-many-paths",
        lambda lab: {"allowed_paths": [f"/p{n}" for n in range(257)]},
        "paths_valid",
    ),
    (
        "too-many-excluded",
        lambda lab: {"excluded_paths": [f"/x{n}" for n in range(65)]},
        "paths_valid",
    ),
    ("zero-rate", lambda lab: {"requests_per_second": 0}, "budget_positive"),
    ("zero-requests", lambda lab: {"max_requests": 0}, "budget_positive"),
    ("zero-duration", lambda lab: {"max_duration_seconds": 0}, "budget_positive"),
    (
        "window-reversed",
        lambda lab: {"valid_until": lab.now - timedelta(hours=1)},
        "window_order",
    ),
    ("blank-reference", lambda lab: {"authorization_reference": "  "}, "reference_not_blank"),
    (
        "approval-without-key",
        lambda lab: _approval(lab, approved_by_key_id=None),
        "decisions_complete",
    ),
    (
        "approval-without-note",
        lambda lab: _approval(lab, approval_note=None),
        "decisions_complete",
    ),
    ("blank-approval-note", lambda lab: _approval(lab, approval_note="  "), "decisions_complete"),
    (
        "revocation-without-reason",
        lambda lab: _revocation(lab, revocation_reason=None),
        "decisions_complete",
    ),
    (
        "blank-revocation-reason",
        lambda lab: _revocation(lab, revocation_reason="  "),
        "decisions_complete",
    ),
    ("approved-without-approval", lambda lab: {"status": "approved"}, "status_matches_decisions"),
    (
        "pending-with-approval",
        lambda lab: {**_approval(lab), "status": "pending"},
        "status_matches_decisions",
    ),
    (
        "pending-with-revocation",
        lambda lab: {**_revocation(lab), "status": "pending"},
        "status_matches_decisions",
    ),
    (
        "approved-with-revocation",
        lambda lab: {**_approval(lab), **_revocation(lab), "status": "approved"},
        "status_matches_decisions",
    ),
    ("revoked-without-revocation", lambda lab: {"status": "revoked"}, "status_matches_decisions"),
    (
        "approved-after-expiry",
        lambda lab: _approval(lab, approved_at=lab.now + timedelta(days=1)),
        "decision_times",
    ),
    (
        "approved-before-request",
        lambda lab: _approval(lab, approved_at=lab.now - SECOND),
        "decision_times",
    ),
    (
        "revoked-before-request",
        lambda lab: _revocation(lab, revoked_at=lab.now - SECOND),
        "decision_times",
    ),
    (
        "revoked-before-approval",
        lambda lab: {
            **_approval(lab, approved_at=lab.now + 2 * SECOND),
            **_revocation(lab, revoked_at=lab.now + SECOND),
        },
        "decision_times",
    ),
]


@pytest.mark.parametrize(
    ("overrides", "check"),
    [(overrides, check) for _, overrides, check in BAD_ROWS],
    ids=[case_id for case_id, _, _ in BAD_ROWS],
)
def test_grant_checks(db_session: Session, lab: Lab, overrides: Overrides, check: str) -> None:
    error = violation(db_session, INSERT_GRANT, _grant_params(lab, **overrides(lab)))

    assert (error.sqlstate, error.diag.constraint_name) == (
        CHECK_VIOLATION,
        f"ck_scope_grants_{check}",
    )


def test_target_with_grants_cannot_be_deleted(db_session: Session, lab: Lab) -> None:
    _insert_grant(db_session, lab)

    error = violation(db_session, "DELETE FROM targets WHERE id = :id", {"id": lab.target_id})

    assert (error.sqlstate, error.diag.constraint_name) == (
        RESTRICT_VIOLATION,
        "fk_scope_grants_target_id_targets",
    )


# --- scope_grants：trigger ------------------------------------------------------------------


def _status(session: Session, grant_id: UUID) -> str:
    value = session.execute(
        text("SELECT status FROM scope_grants WHERE id = :id"), {"id": grant_id}
    ).scalar()
    assert isinstance(value, str)
    return value


def test_allowed_transitions(db_session: Session, lab: Lab) -> None:
    approved_then_revoked = _insert_grant(db_session, lab, version=1)
    revoked_while_pending = _insert_grant(db_session, lab, version=2)

    db_session.execute(text(APPROVE), {"id": approved_then_revoked, "key": lab.key_id})
    assert _status(db_session, approved_then_revoked) == "approved"
    db_session.execute(text(REVOKE), {"id": approved_then_revoked, "key": lab.key_id})
    db_session.execute(text(REVOKE), {"id": revoked_while_pending, "key": lab.key_id})

    assert _status(db_session, approved_then_revoked) == "revoked"
    assert _status(db_session, revoked_while_pending) == "revoked"


def _rejected_update(session: Session, statement: str, params: dict[str, object]) -> str:
    error = violation(session, statement, params)
    assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION
    return str(error)


@pytest.mark.parametrize(
    ("state", "statement"),
    [
        (
            "approved",
            "UPDATE scope_grants SET status = 'pending', approved_by_key_id = NULL, "
            "approved_at = NULL, approval_note = NULL WHERE id = :id",
        ),
        ("approved", "UPDATE scope_grants SET approval_note = 'again' WHERE id = :id"),
        ("revoked", APPROVE),
        ("revoked", "UPDATE scope_grants SET revocation_reason = 'edited' WHERE id = :id"),
        ("pending", "UPDATE scope_grants SET authorization_reference = 'edited' WHERE id = :id"),
    ],
    ids=["approved-to-pending", "re-approve", "approve-revoked", "edit-revoked", "edit-pending"],
)
def test_other_status_changes_are_rejected(
    db_session: Session, lab: Lab, state: str, statement: str
) -> None:
    extra = {"pending": {}, "approved": _approval(lab), "revoked": _revocation(lab)}[state]
    grant_id = _insert_grant(db_session, lab, **extra)

    message = _rejected_update(db_session, statement, {"id": grant_id, "key": lab.key_id})

    assert "status change" in message
    assert _status(db_session, grant_id) == state


@pytest.mark.parametrize(
    "assignment",
    [
        "target_id = :other_target",
        "version = version + 1",
        "allowed_origins = ARRAY['http://juice-shop:3000']",
        "allowed_ips = ARRAY['10.89.7.99']::inet[]",
        "allowed_paths = ARRAY['/admin']",
        "allow_all_paths = true",
        "excluded_paths = ARRAY['/logout']",
        "allowed_methods = ARRAY['DELETE']",
        "requests_per_second = 1",
        "max_requests = 1",
        "max_duration_seconds = 1",
        "authorization_reference = 'edited'",
        "valid_from = valid_from - interval '1 day'",
        "valid_until = valid_until + interval '1 day'",
        "requested_by_key_id = :other_key",
        "created_at = created_at - interval '1 day'",
        "id = gen_random_uuid()",
    ],
)
def test_scope_cannot_change_even_during_a_valid_transition(
    db_session: Session, lab: Lab, assignment: str
) -> None:
    grant_id = _insert_grant(db_session, lab)
    other_target = _insert_target(
        db_session, lab.project_id, canonical_origin="http://juice-shop:3000"
    )
    statement = REVOKE.replace(" WHERE", f", {assignment} WHERE")

    message = _rejected_update(
        db_session,
        statement,
        {
            "id": grant_id,
            "key": lab.key_id,
            "other_target": other_target,
            "other_key": insert_key(db_session),
        },
    )

    assert "immutable" in message


def test_approval_is_fixed_once_recorded(db_session: Session, lab: Lab) -> None:
    grant_id = _insert_grant(db_session, lab, **_approval(lab))
    statement = REVOKE.replace(" WHERE", ", approval_note = 'rewritten' WHERE")

    message = _rejected_update(db_session, statement, {"id": grant_id, "key": lab.key_id})

    assert "approval" in message


def test_revoking_a_pending_grant_cannot_record_an_approval(db_session: Session, lab: Lab) -> None:
    grant_id = _insert_grant(db_session, lab)
    statement = REVOKE.replace(
        " WHERE",
        ", approved_by_key_id = :key, approved_at = now(), approval_note = 'sneaky' WHERE",
    )

    message = _rejected_update(db_session, statement, {"id": grant_id, "key": lab.key_id})

    assert "approval" in message


def test_approving_cannot_record_a_revocation(db_session: Session, lab: Lab) -> None:
    grant_id = _insert_grant(db_session, lab)
    statement = APPROVE.replace(
        " WHERE",
        ", revoked_by_key_id = :key, revoked_at = now(), revocation_reason = 'odd' WHERE",
    )

    message = _rejected_update(db_session, statement, {"id": grant_id, "key": lab.key_id})

    assert "revocation" in message


@pytest.mark.parametrize(
    "statement",
    # scans 以 FK 引用 grant（T09）：不加 CASCADE 的 TRUNCATE 先被 FK 擋下，測不到 trigger。
    ["DELETE FROM scope_grants WHERE id = :id", "TRUNCATE scope_grants CASCADE"],
    ids=["delete", "truncate"],
)
def test_grants_cannot_be_removed(db_session: Session, lab: Lab, statement: str) -> None:
    grant_id = _insert_grant(db_session, lab)

    message = _rejected_update(db_session, statement, {"id": grant_id, "key": lab.key_id})

    assert "blocked" in message
    assert _status(db_session, grant_id) == "pending"


def test_scope_grant_triggers_exist(db_session: Session) -> None:
    triggers = set(
        db_session.execute(
            text(
                "SELECT tgname FROM pg_trigger "
                "WHERE tgrelid = 'scope_grants'::regclass AND NOT tgisinternal"
            )
        ).scalars()
    )

    assert triggers == {"scope_grants_guard_rows", "scope_grants_no_truncate"}
