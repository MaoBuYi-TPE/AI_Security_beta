"""直接以 SQL 驗證 schema 的共用工具：插入最少的測試資料，以及執行應該被 DB 拒絕的語句。"""

from collections.abc import Mapping
from uuid import UUID, uuid4

import psycopg
import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from secscan.api_keys.domain import Role

INTEGRITY_CONSTRAINT_VIOLATION = "23000"
RESTRICT_VIOLATION = "23001"
NOT_NULL_VIOLATION = "23502"
FOREIGN_KEY_VIOLATION = "23503"
UNIQUE_VIOLATION = "23505"
CHECK_VIOLATION = "23514"

INSERT_PROJECT = "INSERT INTO projects (name) VALUES (:name) RETURNING id"
INSERT_KEY = (
    "INSERT INTO api_keys (project_id, role, name, prefix, key_hash, expires_at) "
    "VALUES (:project_id, :role, :name, :prefix, :key_hash, :expires_at) RETURNING id"
)


def returning_id(session: Session, statement: str, params: Mapping[str, object]) -> UUID | None:
    value = session.execute(text(statement), params).scalar()
    return value if isinstance(value, UUID) else None


def violation(session: Session, statement: str, params: Mapping[str, object]) -> psycopg.Error:
    """執行應該被 DB 拒絕的 SQL；以 savepoint 隔離，後續步驟仍可使用同一個 session。"""
    with pytest.raises(IntegrityError) as caught, session.begin_nested():
        session.execute(text(statement), params)
    error = caught.value.orig
    assert isinstance(error, psycopg.Error)
    return error


def insert_project(session: Session, name: str = "lab") -> UUID:
    project_id = returning_id(session, INSERT_PROJECT, {"name": name})
    assert project_id is not None
    return project_id


def key_params(**overrides: object) -> dict[str, object]:
    params: dict[str, object] = {
        "project_id": None,
        "role": Role.PLATFORM_ADMIN.value,
        "name": "admin",
        "prefix": uuid4().hex[:12],
        "key_hash": uuid4().bytes + uuid4().bytes,
        "expires_at": None,
    }
    params.update(overrides)
    return params


def insert_key(session: Session, **overrides: object) -> UUID:
    key_id = returning_id(session, INSERT_KEY, key_params(**overrides))
    assert key_id is not None
    return key_id
