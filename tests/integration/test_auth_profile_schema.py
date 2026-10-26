"""auth_profiles 與 auth_profile_versions 的 DB 約束與 trigger（docs/DECISIONS.md §12.3）。

直接用 SQL 驗證 schema 本身：即使程式有 bug，DB 也只收 Fernet token 形式的密文，每個 profile
最多一份密文，版本列只允許「清除密文」與「重新加密」兩種修改。
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from secscan.auth_profiles.domain.credentials import AuthType, Credential
from secscan.auth_profiles.domain.model import (
    EXPECTED_JSON_MAX_BYTES,
    MAX_ENCRYPTED_SECRET_BYTES,
    secret_context,
)
from tests.integration.sql_support import (
    CHECK_VIOLATION,
    FOREIGN_KEY_VIOLATION,
    INTEGRITY_CONSTRAINT_VIOLATION,
    UNIQUE_VIOLATION,
    insert_key,
    insert_project,
    returning_id,
    violation,
)
from tests.secret_support import bearer_context, shared_cipher

pytestmark = pytest.mark.integration

INSERT_TARGET = (
    "INSERT INTO targets (project_id, name, kind, canonical_origin, environment) "
    "VALUES (:project_id, 'vampi', 'api', 'http://vampi-vuln:5000', 'lab') RETURNING id"
)
INSERT_PROFILE = (
    "INSERT INTO auth_profiles (target_id, name, role_label, created_by_key_id) "
    "VALUES (:target_id, :name, :role_label, :created_by_key_id) RETURNING id"
)
INSERT_VERSION = (
    "INSERT INTO auth_profile_versions (profile_id, version, type, header_name, "
    "preflight_method, preflight_path, preflight_expected_status, preflight_expected_json, "
    "encrypted_secret, secret_erased_at, created_by_key_id) "
    "VALUES (:profile_id, :version, :type, :header_name, :preflight_method, :preflight_path, "
    ":preflight_expected_status, CAST(:preflight_expected_json AS jsonb), :encrypted_secret, "
    ":secret_erased_at, :created_by_key_id)"
)
ERASED_AT = datetime(2026, 10, 25, tzinfo=UTC)
ERASE = (
    "UPDATE auth_profile_versions SET encrypted_secret = NULL, secret_erased_at = now() "
    "WHERE profile_id = :id AND version = :version"
)


@dataclass(frozen=True)
class Lab:
    key_id: UUID
    target_id: UUID


@pytest.fixture
def lab(db_session: Session) -> Lab:
    project_id = insert_project(db_session)
    target_id = returning_id(db_session, INSERT_TARGET, {"project_id": project_id})
    assert target_id is not None
    return Lab(key_id=insert_key(db_session), target_id=target_id)


def _profile_params(lab: Lab, **overrides: object) -> dict[str, object]:
    params: dict[str, object] = {
        "target_id": lab.target_id,
        "name": "VAmPI 一般使用者",
        "role_label": "standard_user",
        "created_by_key_id": lab.key_id,
    }
    params.update(overrides)
    return params


def _insert_profile(session: Session, lab: Lab, **overrides: object) -> UUID:
    profile_id = returning_id(session, INSERT_PROFILE, _profile_params(lab, **overrides))
    assert profile_id is not None
    return profile_id


def _token(profile_id: UUID) -> bytes:
    return shared_cipher().seal("token-for-the-schema-test", context=bearer_context(profile_id))


def _version_params(profile_id: UUID, lab: Lab, **overrides: object) -> dict[str, object]:
    params: dict[str, object] = {
        "profile_id": profile_id,
        "version": 1,
        "type": "bearer",
        "header_name": None,
        "preflight_method": "GET",
        "preflight_path": "/me",
        "preflight_expected_status": 200,
        "preflight_expected_json": json.dumps({"/status": "success"}),
        "encrypted_secret": _token(profile_id),
        "secret_erased_at": None,
        "created_by_key_id": lab.key_id,
    }
    params.update(overrides)
    return params


def _rejected(session: Session, statement: str, params: Mapping[str, object]) -> tuple[str, str]:
    error = violation(session, statement, params)
    return error.sqlstate or "", error.diag.constraint_name or ""


def test_valid_profile_and_version_are_stored(db_session: Session, lab: Lab) -> None:
    profile_id = _insert_profile(db_session, lab)
    db_session.execute(text(INSERT_VERSION), _version_params(profile_id, lab))
    admin_id = _insert_profile(db_session, lab, role_label="admin")
    db_session.execute(
        text(INSERT_VERSION),
        _version_params(
            admin_id,
            lab,
            type="api_key_header",
            header_name="X-API-Key",
            encrypted_secret=_token(admin_id),
        ),
    )

    row = db_session.execute(
        text(
            "SELECT created_at, preflight_expected_json FROM auth_profile_versions "
            "WHERE profile_id = :id"
        ),
        {"id": profile_id},
    ).one()
    assert row.created_at is not None
    assert row.preflight_expected_json == {"/status": "success"}


# --- auth_profiles --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("overrides", "constraint"),
    [
        ({"name": "  "}, "ck_auth_profiles_name_not_blank"),
        ({"role_label": "Admin"}, "ck_auth_profiles_role_label_valid"),
        ({"role_label": "1user"}, "ck_auth_profiles_role_label_valid"),
        ({"role_label": "user-a"}, "ck_auth_profiles_role_label_valid"),
        ({"role_label": "user\n"}, "ck_auth_profiles_role_label_valid"),
        ({"role_label": "anonymous"}, "ck_auth_profiles_role_label_valid"),
    ],
    ids=["blank-name", "uppercase", "digit-first", "hyphen", "newline", "anonymous"],
)
def test_profile_checks(
    db_session: Session, lab: Lab, overrides: dict[str, object], constraint: str
) -> None:
    params = _profile_params(lab, **overrides)

    assert _rejected(db_session, INSERT_PROFILE, params) == (CHECK_VIOLATION, constraint)


def test_role_label_is_unique_per_target(db_session: Session, lab: Lab) -> None:
    _insert_profile(db_session, lab)

    assert _rejected(db_session, INSERT_PROFILE, _profile_params(lab)) == (
        UNIQUE_VIOLATION,
        "uq_auth_profiles_target_id_role_label",
    )


@pytest.mark.parametrize(
    ("field", "constraint"),
    [
        ("target_id", "fk_auth_profiles_target_id_targets"),
        ("created_by_key_id", "fk_auth_profiles_created_by_key_id_api_keys"),
    ],
)
def test_profile_references_must_exist(
    db_session: Session, lab: Lab, field: str, constraint: str
) -> None:
    params = _profile_params(lab, **{field: uuid4()})

    assert _rejected(db_session, INSERT_PROFILE, params) == (FOREIGN_KEY_VIOLATION, constraint)


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE auth_profiles SET name = 'renamed' WHERE id = :id",
        "UPDATE auth_profiles SET role_label = role_label WHERE id = :id",
        "DELETE FROM auth_profiles WHERE id = :id",
        # scans 以 FK 引用 profile 與版本（T09）：不加 CASCADE 時先被 FK 擋下，測不到 trigger。
        "TRUNCATE auth_profiles, auth_profile_versions CASCADE",
    ],
    ids=["rename", "same-value", "delete", "truncate"],
)
def test_profiles_are_immutable(db_session: Session, lab: Lab, statement: str) -> None:
    profile_id = _insert_profile(db_session, lab)

    error = violation(db_session, statement, {"id": profile_id})

    assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION
    assert "immutable" in str(error)


# --- auth_profile_versions：CHECK -----------------------------------------------------------


def _version_checks() -> list[tuple[dict[str, object], str]]:
    huge = {f"/k{index}": "x" * 4000 for index in range(17)}
    return [
        ({"version": 0}, "ck_auth_profile_versions_version_positive"),
        ({"type": "basic"}, "ck_auth_profile_versions_type_valid"),
        ({"header_name": "X-API-Key"}, "ck_auth_profile_versions_header_name_matches_type"),
        ({"type": "api_key_header"}, "ck_auth_profile_versions_header_name_matches_type"),
        (
            {"type": "api_key_header", "header_name": "X_API_Key"},
            "ck_auth_profile_versions_header_name_valid",
        ),
        (
            {"type": "api_key_header", "header_name": "X-Key\r\nX-Injected"},
            "ck_auth_profile_versions_header_name_valid",
        ),
        ({"preflight_method": "POST"}, "ck_auth_profile_versions_preflight_method_valid"),
        ({"preflight_path": "me"}, "ck_auth_profile_versions_preflight_path_valid"),
        ({"preflight_path": "/users/{id}"}, "ck_auth_profile_versions_preflight_path_valid"),
        ({"preflight_expected_status": 199}, "ck_auth_profile_versions_preflight_status_valid"),
        ({"preflight_expected_status": 300}, "ck_auth_profile_versions_preflight_status_valid"),
        (
            {"preflight_expected_json": "{}"},
            "ck_auth_profile_versions_preflight_expected_json_valid",
        ),
        (
            {"preflight_expected_json": '[{"/a": 1}]'},
            "ck_auth_profile_versions_preflight_expected_json_valid",
        ),
        (
            {"preflight_expected_json": json.dumps(huge)},
            "ck_auth_profile_versions_preflight_expected_json_valid",
        ),
        # 密文與清除時間要成對；「兩者都是 NULL」在 INSERT 時先被 trigger 擋下（下面另有測試）。
        ({"secret_erased_at": ERASED_AT}, "ck_auth_profile_versions_secret_erasure_consistent"),
        (
            {"encrypted_secret": b"plaintext-token"},
            "ck_auth_profile_versions_encrypted_secret_valid",
        ),
        (
            {"encrypted_secret": b"gAAAAA" + b"x" * MAX_ENCRYPTED_SECRET_BYTES},
            "ck_auth_profile_versions_encrypted_secret_valid",
        ),
    ]


@pytest.mark.parametrize(("overrides", "constraint"), _version_checks())
def test_version_checks(
    db_session: Session, lab: Lab, overrides: dict[str, object], constraint: str
) -> None:
    profile_id = _insert_profile(db_session, lab)
    params = _version_params(profile_id, lab, **overrides)

    assert _rejected(db_session, INSERT_VERSION, params) == (CHECK_VIOLATION, constraint)


def test_the_largest_token_fits(db_session: Session, lab: Lab) -> None:
    profile_id = _insert_profile(db_session, lab)
    longest = Credential(AuthType.API_KEY_HEADER, header_name="x" * 64)
    token = shared_cipher().seal('"' * 4096, context=secret_context(profile_id, longest))
    assert len(token) == MAX_ENCRYPTED_SECRET_BYTES

    db_session.execute(
        text(INSERT_VERSION), _version_params(profile_id, lab, encrypted_secret=token)
    )


@pytest.mark.parametrize(
    ("field", "constraint"),
    [
        ("profile_id", "fk_auth_profile_versions_profile_id_auth_profiles"),
        ("created_by_key_id", "fk_auth_profile_versions_created_by_key_id_api_keys"),
    ],
)
def test_version_references_must_exist(
    db_session: Session, lab: Lab, field: str, constraint: str
) -> None:
    profile_id = _insert_profile(db_session, lab)
    params = {**_version_params(profile_id, lab), field: uuid4()}

    assert _rejected(db_session, INSERT_VERSION, params) == (FOREIGN_KEY_VIOLATION, constraint)


def test_version_is_unique_per_profile(db_session: Session, lab: Lab) -> None:
    profile_id = _insert_profile(db_session, lab)
    db_session.execute(text(INSERT_VERSION), _version_params(profile_id, lab))
    db_session.execute(text(ERASE), {"id": profile_id, "version": 1})

    assert _rejected(db_session, INSERT_VERSION, _version_params(profile_id, lab)) == (
        UNIQUE_VIOLATION,
        "pk_auth_profile_versions",
    )


def test_a_profile_holds_at_most_one_secret(db_session: Session, lab: Lab) -> None:
    """部分唯一索引：上一版的密文沒有清除，就不能寫入下一版。"""
    profile_id = _insert_profile(db_session, lab)
    db_session.execute(text(INSERT_VERSION), _version_params(profile_id, lab))

    assert _rejected(db_session, INSERT_VERSION, _version_params(profile_id, lab, version=2)) == (
        UNIQUE_VIOLATION,
        "uq_auth_profile_versions_live_secret",
    )
    db_session.execute(text(ERASE), {"id": profile_id, "version": 1})
    db_session.execute(text(INSERT_VERSION), _version_params(profile_id, lab, version=2))


# --- auth_profile_versions：trigger ---------------------------------------------------------


def _stored_version(session: Session, lab: Lab) -> UUID:
    profile_id = _insert_profile(session, lab)
    session.execute(text(INSERT_VERSION), _version_params(profile_id, lab))
    return profile_id


def test_erasing_the_secret_is_allowed(db_session: Session, lab: Lab) -> None:
    profile_id = _stored_version(db_session, lab)

    db_session.execute(text(ERASE), {"id": profile_id, "version": 1})

    row = db_session.execute(
        text(
            "SELECT encrypted_secret, secret_erased_at FROM auth_profile_versions "
            "WHERE profile_id = :id"
        ),
        {"id": profile_id},
    ).one()
    assert row.encrypted_secret is None
    assert row.secret_erased_at is not None


def test_reencrypting_the_secret_is_allowed(db_session: Session, lab: Lab) -> None:
    profile_id = _stored_version(db_session, lab)
    new_token = _token(profile_id)

    db_session.execute(
        text(
            "UPDATE auth_profile_versions SET encrypted_secret = :token "
            "WHERE profile_id = :id AND version = 1"
        ),
        {"token": new_token, "id": profile_id},
    )

    stored = db_session.execute(
        text("SELECT encrypted_secret FROM auth_profile_versions WHERE profile_id = :id"),
        {"id": profile_id},
    ).scalar()
    assert stored == new_token


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE auth_profile_versions SET preflight_path = '/other' WHERE profile_id = :id",
        "UPDATE auth_profile_versions SET type = 'cookie' WHERE profile_id = :id",
        "UPDATE auth_profile_versions SET encrypted_secret = encrypted_secret "
        "WHERE profile_id = :id",
        "UPDATE auth_profile_versions SET secret_erased_at = now() WHERE profile_id = :id",
        "UPDATE auth_profile_versions SET encrypted_secret = NULL, secret_erased_at = now(), "
        "preflight_expected_status = 201 WHERE profile_id = :id",
        "UPDATE auth_profile_versions SET version = 2 WHERE profile_id = :id",
        "DELETE FROM auth_profile_versions WHERE profile_id = :id",
        "TRUNCATE auth_profile_versions CASCADE",
    ],
    ids=[
        "change-preflight",
        "change-type",
        "same-secret",
        "erased-at-only",
        "erase-and-change",
        "renumber",
        "delete",
        "truncate",
    ],
)
def test_other_changes_to_versions_are_blocked(
    db_session: Session, lab: Lab, statement: str
) -> None:
    profile_id = _stored_version(db_session, lab)

    error = violation(db_session, statement, {"id": profile_id})

    assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION
    remaining = db_session.execute(
        text(
            "SELECT count(*) FROM auth_profile_versions "
            "WHERE profile_id = :id AND encrypted_secret IS NOT NULL AND preflight_path = '/me'"
        ),
        {"id": profile_id},
    ).scalar()
    assert remaining == 1


def test_an_erased_secret_cannot_be_restored(db_session: Session, lab: Lab) -> None:
    profile_id = _stored_version(db_session, lab)
    db_session.execute(text(ERASE), {"id": profile_id, "version": 1})

    error = violation(
        db_session,
        "UPDATE auth_profile_versions SET encrypted_secret = :token, secret_erased_at = NULL "
        "WHERE profile_id = :id",
        {"token": _token(profile_id), "id": profile_id},
    )

    assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION


def test_a_new_version_must_carry_a_secret(db_session: Session, lab: Lab) -> None:
    """清除過的狀態只能由 UPDATE 而來：INSERT 一個已清除的版本，也被 trigger 擋下。

    BEFORE trigger 先於 CHECK 執行，所以「密文是 NULL」的 INSERT 都由 trigger 擋下。
    """
    profile_id = _insert_profile(db_session, lab)
    params = _version_params(profile_id, lab, encrypted_secret=None, secret_erased_at=ERASED_AT)

    error = violation(db_session, INSERT_VERSION, params)

    assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION
    assert "secret" in str(error)


@pytest.mark.parametrize(
    ("constraint", "value"),
    [
        ("ck_auth_profile_versions_encrypted_secret_valid", MAX_ENCRYPTED_SECRET_BYTES),
        ("ck_auth_profile_versions_preflight_expected_json_valid", EXPECTED_JSON_MAX_BYTES),
    ],
)
def test_size_checks_match_the_domain_limits(
    db_session: Session, constraint: str, value: int
) -> None:
    """migration 寫死的上限要和 domain 的常數相同：只比對 CHECK 名稱的測試看不出內容的漂移。"""
    definition = db_session.execute(
        text("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = :name"),
        {"name": constraint},
    ).scalar_one()

    assert f"<= {value}" in definition


def test_guard_triggers_exist(db_session: Session) -> None:
    triggers = set(
        db_session.execute(
            text(
                "SELECT tgrelid::regclass || '.' || tgname FROM pg_trigger "
                "WHERE tgrelid IN ('auth_profiles'::regclass, 'auth_profile_versions'::regclass) "
                "AND NOT tgisinternal"
            )
        ).scalars()
    )

    assert triggers == {
        "auth_profiles.auth_profiles_immutable",
        "auth_profiles.auth_profiles_no_truncate",
        "auth_profile_versions.auth_profile_versions_guard_rows",
        "auth_profile_versions.auth_profile_versions_no_truncate",
    }
