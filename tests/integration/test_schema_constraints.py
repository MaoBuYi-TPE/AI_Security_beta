"""資料庫層的約束：FK、unique、check、index 與 audit_events 的 append-only（T04 DoD）。

直接用 SQL 驗證 schema 本身，不經過 repository，確認即使程式有 bug，DB 也會擋下錯誤資料。
"""

from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import CheckConstraint, text
from sqlalchemy.orm import Session

from secscan.api_keys.domain import KEY_HASH_BYTES, Role
from secscan.migrations.metadata import target_metadata
from tests.integration.sql_support import (
    CHECK_VIOLATION,
    FOREIGN_KEY_VIOLATION,
    INSERT_KEY,
    INSERT_PROJECT,
    INTEGRITY_CONSTRAINT_VIOLATION,
    NOT_NULL_VIOLATION,
    RESTRICT_VIOLATION,
    UNIQUE_VIOLATION,
)
from tests.integration.sql_support import insert_key as _key
from tests.integration.sql_support import insert_project as _project
from tests.integration.sql_support import key_params as _key_params
from tests.integration.sql_support import returning_id as _execute
from tests.integration.sql_support import violation as _violation

pytestmark = pytest.mark.integration

# projects 1、api_keys 7、audit_events 3、targets 4、scope_grants 12；
# 每一個都有對應的行為測試（targets 與 scope_grants 的在 test_scope_schema.py）。
EXPECTED_CHECK_COUNT = 27

INSERT_AUDIT = (
    "INSERT INTO audit_events (actor_key_id, project_id, action, object_type, redacted_changes) "
    "VALUES (:actor_key_id, :project_id, :action, :object_type, "
    "CAST(:changes AS jsonb)) RETURNING id"
)


def _audit_params(**overrides: object) -> dict[str, object]:
    params: dict[str, object] = {
        "actor_key_id": None,
        "project_id": None,
        "action": "project.create",
        "object_type": "project",
        "changes": "{}",
    }
    params.update(overrides)
    return params


def test_server_generates_ids_and_utc_timestamps(db_session: Session) -> None:
    row = db_session.execute(
        text("INSERT INTO projects (name) VALUES ('lab') RETURNING id, created_at")
    ).one()

    assert isinstance(row.id, UUID)
    assert row.created_at.utcoffset() == timedelta(0)


def test_project_name_is_unique(db_session: Session) -> None:
    _project(db_session, "lab")

    error = _violation(db_session, INSERT_PROJECT, {"name": "lab"})

    assert (error.sqlstate, error.diag.constraint_name) == (UNIQUE_VIOLATION, "uq_projects_name")


@pytest.mark.parametrize("name", ["", "   "])
def test_project_name_must_not_be_blank(db_session: Session, name: str) -> None:
    error = _violation(db_session, INSERT_PROJECT, {"name": name})

    assert (error.sqlstate, error.diag.constraint_name) == (
        CHECK_VIOLATION,
        "ck_projects_name_not_blank",
    )


def test_api_key_project_must_exist(db_session: Session) -> None:
    params = _key_params(role=Role.OPERATOR.value, project_id=uuid4())

    error = _violation(db_session, INSERT_KEY, params)

    assert (error.sqlstate, error.diag.constraint_name) == (
        FOREIGN_KEY_VIOLATION,
        "fk_api_keys_project_id_projects",
    )


@pytest.mark.parametrize(
    ("column", "constraint"),
    [("prefix", "uq_api_keys_prefix"), ("key_hash", "uq_api_keys_key_hash")],
)
def test_api_key_prefix_and_hash_are_unique(
    db_session: Session, column: str, constraint: str
) -> None:
    first = _key_params()
    _key(db_session, **first)

    error = _violation(db_session, INSERT_KEY, _key_params(**{column: first[column]}))

    assert (error.sqlstate, error.diag.constraint_name) == (UNIQUE_VIOLATION, constraint)


def test_every_role_is_accepted_with_the_right_scope(db_session: Session) -> None:
    project_id = _project(db_session)

    for role in Role:
        scope = None if role is Role.PLATFORM_ADMIN else project_id
        assert _key(db_session, role=role.value, project_id=scope)


def test_unknown_role_is_rejected(db_session: Session) -> None:
    # 帶 project，讓 role_project_scope 成立，只剩 role_valid 會失敗。
    params = _key_params(role="superadmin", project_id=_project(db_session))

    error = _violation(db_session, INSERT_KEY, params)

    assert (error.sqlstate, error.diag.constraint_name) == (
        CHECK_VIOLATION,
        "ck_api_keys_role_valid",
    )


def test_platform_admin_key_cannot_belong_to_a_project(db_session: Session) -> None:
    params = _key_params(role=Role.PLATFORM_ADMIN.value, project_id=_project(db_session))

    error = _violation(db_session, INSERT_KEY, params)

    assert error.diag.constraint_name == "ck_api_keys_role_project_scope"


@pytest.mark.parametrize("role", [Role.OPERATOR, Role.VIEWER])
def test_project_roles_must_belong_to_a_project(db_session: Session, role: Role) -> None:
    error = _violation(db_session, INSERT_KEY, _key_params(role=role.value, project_id=None))

    assert error.diag.constraint_name == "ck_api_keys_role_project_scope"


@pytest.mark.parametrize("length", [0, KEY_HASH_BYTES - 1, KEY_HASH_BYTES + 1])
def test_key_hash_must_be_32_bytes(db_session: Session, length: int) -> None:
    error = _violation(db_session, INSERT_KEY, _key_params(key_hash=b"x" * length))

    assert error.diag.constraint_name == "ck_api_keys_key_hash_length"


def test_key_cannot_expire_before_it_is_created(db_session: Session) -> None:
    yesterday = db_session.execute(text("SELECT now() - interval '1 day'")).scalar()

    error = _violation(db_session, INSERT_KEY, _key_params(expires_at=yesterday))

    assert error.diag.constraint_name == "ck_api_keys_expires_after_created"


def test_key_cannot_be_revoked_before_it_is_created(db_session: Session) -> None:
    key_id = _key(db_session)

    error = _violation(
        db_session,
        "UPDATE api_keys SET revoked_at = created_at - interval '1 second' WHERE id = :id",
        {"id": key_id},
    )

    assert error.diag.constraint_name == "ck_api_keys_revoked_after_created"


@pytest.mark.parametrize(
    ("column", "constraint"),
    [("name", "ck_api_keys_name_not_blank"), ("prefix", "ck_api_keys_prefix_not_blank")],
)
def test_api_key_text_must_not_be_blank(db_session: Session, column: str, constraint: str) -> None:
    error = _violation(db_session, INSERT_KEY, _key_params(**{column: "   "}))

    assert (error.sqlstate, error.diag.constraint_name) == (CHECK_VIOLATION, constraint)


@pytest.mark.parametrize(
    ("column", "constraint"),
    [
        ("action", "ck_audit_events_action_not_blank"),
        ("object_type", "ck_audit_events_object_type_not_blank"),
    ],
)
def test_audit_labels_must_not_be_blank(db_session: Session, column: str, constraint: str) -> None:
    error = _violation(db_session, INSERT_AUDIT, _audit_params(**{column: "  "}))

    assert (error.sqlstate, error.diag.constraint_name) == (CHECK_VIOLATION, constraint)


def test_every_model_check_constraint_exists_in_the_database(db_session: Session) -> None:
    """autogenerate 的漂移檢查看不到 CHECK：model 宣告了、migration 卻漏寫時由這裡抓。"""
    declared = {
        constraint.name
        for table in target_metadata.tables.values()
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
    }
    in_database = set(
        db_session.execute(
            text(
                "SELECT conname FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid "
                "JOIN pg_namespace n ON n.oid = t.relnamespace "
                "WHERE c.contype = 'c' AND n.nspname = 'public'"
            )
        ).scalars()
    )

    assert declared == in_database
    assert len(declared) == EXPECTED_CHECK_COUNT


def test_append_only_triggers_exist(db_session: Session) -> None:
    triggers = set(
        db_session.execute(
            text(
                "SELECT tgname FROM pg_trigger "
                "WHERE tgrelid = 'audit_events'::regclass AND NOT tgisinternal"
            )
        ).scalars()
    )

    assert triggers == {"audit_events_append_only", "audit_events_no_truncate"}


def test_project_with_keys_cannot_be_deleted(db_session: Session) -> None:
    project_id = _project(db_session)
    _key(db_session, role=Role.VIEWER.value, project_id=project_id)

    error = _violation(db_session, "DELETE FROM projects WHERE id = :id", {"id": project_id})

    assert (error.sqlstate, error.diag.constraint_name) == (
        RESTRICT_VIOLATION,
        "fk_api_keys_project_id_projects",
    )


@pytest.mark.parametrize(
    ("column", "constraint"),
    [
        ("project_id", "fk_audit_events_project_id_projects"),
        ("actor_key_id", "fk_audit_events_actor_key_id_api_keys"),
    ],
)
def test_audit_references_must_exist(db_session: Session, column: str, constraint: str) -> None:
    error = _violation(db_session, INSERT_AUDIT, _audit_params(**{column: uuid4()}))

    assert (error.sqlstate, error.diag.constraint_name) == (FOREIGN_KEY_VIOLATION, constraint)


@pytest.mark.parametrize("changes", ["[]", '"text"', "1", "null"])
def test_audit_changes_must_be_a_json_object(db_session: Session, changes: str) -> None:
    error = _violation(db_session, INSERT_AUDIT, _audit_params(changes=changes))

    assert (error.sqlstate, error.diag.constraint_name) == (
        CHECK_VIOLATION,
        "ck_audit_events_changes_is_object",
    )


def test_audit_changes_are_required(db_session: Session) -> None:
    error = _violation(db_session, INSERT_AUDIT, _audit_params(changes=None))

    assert (error.sqlstate, error.diag.column_name) == (NOT_NULL_VIOLATION, "redacted_changes")


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_events SET action = 'tampered' WHERE id = :id",
        "DELETE FROM audit_events WHERE id = :id",
        "TRUNCATE audit_events",
    ],
    ids=["update", "delete", "truncate"],
)
def test_audit_events_are_append_only(db_session: Session, statement: str) -> None:
    event_id = _execute(db_session, INSERT_AUDIT, _audit_params())

    error = _violation(db_session, statement, {"id": event_id})

    assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION
    assert "append-only" in str(error)
    remaining = db_session.execute(text("SELECT count(*) FROM audit_events")).scalar()
    assert remaining == 1


@pytest.mark.parametrize(
    ("index_name", "definition"),
    [
        ("ix_api_keys_project_id", "(project_id)"),
        ("ix_audit_events_project_id_created_at", "(project_id, created_at)"),
        ("uq_api_keys_prefix", "UNIQUE INDEX"),
        ("uq_api_keys_key_hash", "UNIQUE INDEX"),
        ("uq_projects_name", "UNIQUE INDEX"),
        ("uq_targets_project_id_canonical_origin", "(project_id, canonical_origin)"),
        ("uq_scope_grants_target_id_version", "(target_id, version)"),
    ],
)
def test_expected_indexes_exist(db_session: Session, index_name: str, definition: str) -> None:
    indexdef = db_session.execute(
        text("SELECT indexdef FROM pg_indexes WHERE schemaname = 'public' AND indexname = :n"),
        {"n": index_name},
    ).scalar()

    assert isinstance(indexdef, str)
    assert definition in indexdef
