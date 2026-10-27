"""api_specs 與 api_spec_operations 的 DB 約束與 trigger（docs/DECISIONS.md §11.5）。

直接用 SQL 驗證 schema 本身：即使程式有 bug，DB 也會擋下不合規則的資料與任何修改、刪除。
"""

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

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

pytestmark = pytest.mark.integration

MiB = 1024 * 1024
DOCUMENT = b'{"openapi":"3.0.3"}'
INSERT_TARGET = (
    "INSERT INTO targets (project_id, name, kind, canonical_origin, environment) "
    "VALUES (:project_id, 'vampi', 'api', 'http://vampi-vuln:5000', 'lab') RETURNING id"
)
INSERT_SPEC = (
    "INSERT INTO api_specs (target_id, version, source_format, source_size_bytes, source_sha256, "
    "document, document_sha256, openapi_version, base_path, operation_count, uploaded_by_key_id) "
    "VALUES (:target_id, :version, :source_format, :source_size_bytes, :source_sha256, "
    ":document, :document_sha256, :openapi_version, :base_path, :operation_count, "
    ":uploaded_by_key_id) RETURNING id"
)
INSERT_OPERATION = (
    "INSERT INTO api_spec_operations (spec_id, ordinal, method, path, operation_id) "
    "VALUES (:spec_id, :ordinal, :method, :path, :operation_id)"
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


def _spec_params(lab: Lab, **overrides: object) -> dict[str, object]:
    document = overrides.pop("document", DOCUMENT)
    assert isinstance(document, bytes)
    params: dict[str, object] = {
        "target_id": lab.target_id,
        "version": 1,
        "source_format": "yaml",
        "source_size_bytes": 10,
        "source_sha256": bytes(32),
        "document": document,
        "document_sha256": hashlib.sha256(document).digest(),
        "openapi_version": "3.0.3",
        "base_path": "",
        "operation_count": 0,
        "uploaded_by_key_id": lab.key_id,
    }
    params.update(overrides)
    return params


def _insert_spec(session: Session, lab: Lab, **overrides: object) -> UUID:
    spec_id = returning_id(session, INSERT_SPEC, _spec_params(lab, **overrides))
    assert spec_id is not None
    return spec_id


def _operation_params(spec_id: UUID, **overrides: object) -> dict[str, object]:
    params: dict[str, object] = {
        "spec_id": spec_id,
        "ordinal": 0,
        "method": "GET",
        "path": "/users/{id}",
        "operation_id": "getUser",
    }
    params.update(overrides)
    return params


def _rejected(session: Session, statement: str, params: Mapping[str, object]) -> tuple[str, str]:
    error = violation(session, statement, params)
    return error.sqlstate or "", error.diag.constraint_name or ""


def test_valid_spec_and_operations_are_stored(db_session: Session, lab: Lab) -> None:
    spec_id = _insert_spec(db_session, lab, base_path="/b2b/v2", operation_count=2)
    db_session.execute(text(INSERT_OPERATION), _operation_params(spec_id))
    db_session.execute(
        text(INSERT_OPERATION),
        _operation_params(spec_id, ordinal=1, method="TRACE", path="/", operation_id=None),
    )

    row = db_session.execute(
        text("SELECT created_at, document FROM api_specs WHERE id = :id"), {"id": spec_id}
    ).one()
    assert row.document == DOCUMENT
    assert row.created_at is not None


@pytest.mark.parametrize(
    ("overrides", "constraint"),
    [
        ({"version": 0}, "ck_api_specs_version_positive"),
        ({"source_format": "xml"}, "ck_api_specs_format_valid"),
        ({"source_size_bytes": 0}, "ck_api_specs_source_size_valid"),
        ({"source_size_bytes": MiB + 1}, "ck_api_specs_source_size_valid"),
        ({"source_sha256": bytes(31)}, "ck_api_specs_source_sha256_length"),
        ({"document": b""}, "ck_api_specs_document_size_valid"),
        ({"document": b" " * (2 * MiB + 1)}, "ck_api_specs_document_size_valid"),
        ({"document_sha256": bytes(32)}, "ck_api_specs_document_sha256_matches"),
        ({"openapi_version": "3.1.0"}, "ck_api_specs_openapi_version_valid"),
        ({"openapi_version": "3.0.03"}, "ck_api_specs_openapi_version_valid"),
        ({"base_path": "api"}, "ck_api_specs_base_path_valid"),
        ({"base_path": "/api/"}, "ck_api_specs_base_path_valid"),
        ({"operation_count": -1}, "ck_api_specs_operation_count_valid"),
        ({"operation_count": 1001}, "ck_api_specs_operation_count_valid"),
    ],
    ids=[
        "version",
        "format",
        "empty-source",
        "source-too-large",
        "source-hash-length",
        "empty-document",
        "document-too-large",
        "document-hash-mismatch",
        "openapi-3-1",
        "openapi-leading-zero",
        "relative-base-path",
        "trailing-slash-base-path",
        "negative-count",
        "too-many-operations",
    ],
)
def test_spec_checks(
    db_session: Session, lab: Lab, overrides: dict[str, object], constraint: str
) -> None:
    params = _spec_params(lab, **overrides)

    assert _rejected(db_session, INSERT_SPEC, params) == (CHECK_VIOLATION, constraint)


@pytest.mark.parametrize("size", [1, MiB])
def test_source_size_bounds_are_inclusive(db_session: Session, lab: Lab, size: int) -> None:
    _insert_spec(db_session, lab, source_size_bytes=size)


def test_version_is_unique_per_target(db_session: Session, lab: Lab) -> None:
    _insert_spec(db_session, lab)

    assert _rejected(db_session, INSERT_SPEC, _spec_params(lab)) == (
        UNIQUE_VIOLATION,
        "uq_api_specs_target_id_version",
    )


@pytest.mark.parametrize(
    ("field", "constraint"),
    [
        ("target_id", "fk_api_specs_target_id_targets"),
        ("uploaded_by_key_id", "fk_api_specs_uploaded_by_key_id_api_keys"),
    ],
)
def test_spec_references_must_exist(
    db_session: Session, lab: Lab, field: str, constraint: str
) -> None:
    params = _spec_params(lab, **{field: uuid4()})

    assert _rejected(db_session, INSERT_SPEC, params) == (FOREIGN_KEY_VIOLATION, constraint)


@pytest.mark.parametrize(
    ("overrides", "constraint"),
    [
        ({"method": "get"}, "ck_api_spec_operations_method_valid"),
        ({"method": "CONNECT"}, "ck_api_spec_operations_method_valid"),
        ({"path": "users"}, "ck_api_spec_operations_path_valid"),
        ({"operation_id": "  "}, "ck_api_spec_operations_operation_id_not_blank"),
        ({"ordinal": -1}, "ck_api_spec_operations_ordinal_valid"),
        ({"ordinal": 1000}, "ck_api_spec_operations_ordinal_valid"),
    ],
)
def test_operation_checks(
    db_session: Session, lab: Lab, overrides: dict[str, object], constraint: str
) -> None:
    spec_id = _insert_spec(db_session, lab)
    params = _operation_params(spec_id, **overrides)

    assert _rejected(db_session, INSERT_OPERATION, params) == (CHECK_VIOLATION, constraint)


def test_operations_are_unique_per_spec(db_session: Session, lab: Lab) -> None:
    spec_id = _insert_spec(db_session, lab)
    db_session.execute(text(INSERT_OPERATION), _operation_params(spec_id, operation_id=None))
    db_session.execute(
        text(INSERT_OPERATION),
        _operation_params(spec_id, ordinal=1, method="PUT", operation_id=None),
    )
    db_session.execute(
        text(INSERT_OPERATION), _operation_params(spec_id, ordinal=2, path="/a", operation_id="op")
    )

    same_route = _operation_params(spec_id, ordinal=3, operation_id="other")
    same_id = _operation_params(spec_id, ordinal=3, path="/b", operation_id="op")
    same_ordinal = _operation_params(spec_id, path="/c", operation_id=None)
    assert _rejected(db_session, INSERT_OPERATION, same_route) == (
        UNIQUE_VIOLATION,
        "uq_api_spec_operations_spec_id_method_path",
    )
    assert _rejected(db_session, INSERT_OPERATION, same_id) == (
        UNIQUE_VIOLATION,
        "uq_api_spec_operations_spec_id_operation_id",
    )
    assert _rejected(db_session, INSERT_OPERATION, same_ordinal) == (
        UNIQUE_VIOLATION,
        "pk_api_spec_operations",
    )


def test_operation_spec_must_exist(db_session: Session) -> None:
    params = _operation_params(uuid4())

    assert _rejected(db_session, INSERT_OPERATION, params) == (
        FOREIGN_KEY_VIOLATION,
        "fk_api_spec_operations_spec_id_api_specs",
    )


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE api_specs SET base_path = '/x' WHERE id = :id",
        "UPDATE api_specs SET document = document WHERE id = :id",
        "DELETE FROM api_specs WHERE id = :id",
        "UPDATE api_spec_operations SET path = '/x' WHERE spec_id = :id",
        "DELETE FROM api_spec_operations WHERE spec_id = :id",
        "TRUNCATE api_spec_operations",
        # scans 以 FK 引用規格（T09）：不加 CASCADE 時先被 FK 擋下，測不到 trigger。
        "TRUNCATE api_specs, api_spec_operations CASCADE",
    ],
    ids=[
        "update-spec",
        "update-same-value",
        "delete-spec",
        "update-operation",
        "delete-operation",
        "truncate-operations",
        "truncate-both",
    ],
)
def test_specs_are_immutable(db_session: Session, lab: Lab, statement: str) -> None:
    spec_id = _insert_spec(db_session, lab, operation_count=1)
    db_session.execute(text(INSERT_OPERATION), _operation_params(spec_id))

    error = violation(db_session, statement, {"id": spec_id})

    assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION
    assert "immutable" in str(error)
    counts = db_session.execute(
        text("SELECT (SELECT count(*) FROM api_specs), (SELECT count(*) FROM api_spec_operations)")
    ).one()
    assert tuple(counts) == (1, 1)


def test_immutability_triggers_exist(db_session: Session) -> None:
    triggers = set(
        db_session.execute(
            text(
                "SELECT tgrelid::regclass || '.' || tgname FROM pg_trigger "
                "WHERE tgrelid IN ('api_specs'::regclass, 'api_spec_operations'::regclass) "
                "AND NOT tgisinternal"
            )
        ).scalars()
    )

    assert triggers == {
        "api_specs.api_specs_immutable",
        "api_specs.api_specs_no_truncate",
        "api_spec_operations.api_spec_operations_immutable",
        "api_spec_operations.api_spec_operations_no_truncate",
    }
