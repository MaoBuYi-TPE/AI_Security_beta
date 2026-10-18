"""repository：寫入與查詢都回傳 frozen domain model，約束錯誤轉成 ConstraintViolationError。"""

import traceback
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import StatementError
from sqlalchemy.orm import Session

from secscan.api_keys.domain import KEY_HASH_BYTES, ApiKey, NewApiKey, Role
from secscan.api_keys.models import ApiKeyModel
from secscan.api_keys.repository import ApiKeyRepository
from secscan.audit.domain import NewAuditEvent
from secscan.audit.repository import AuditEventRepository
from secscan.core.db import ConstraintViolationError
from secscan.core.json_types import JsonObject
from secscan.core.pagination import PageRequest
from secscan.projects.domain import NewProject, Project
from secscan.projects.repository import ProjectRepository

pytestmark = pytest.mark.integration


def _hash() -> bytes:
    return (uuid4().bytes * 2)[:KEY_HASH_BYTES]


def _new_key(**overrides: object) -> NewApiKey:
    fields: dict[str, object] = {
        "role": Role.PLATFORM_ADMIN,
        "name": "admin",
        "prefix": uuid4().hex[:12],
        "key_hash": _hash(),
    }
    fields.update(overrides)
    return NewApiKey(**fields)  # type: ignore[arg-type]


# --- projects -----------------------------------------------------------------------------


def test_create_project_returns_domain_model(db_session: Session) -> None:
    project = ProjectRepository(db_session).create(NewProject(name="API 教學靶場"))

    assert isinstance(project, Project)
    assert isinstance(project.id, UUID)
    assert project.name == "API 教學靶場"
    assert project.created_at.tzinfo is not None
    assert project.created_at.utcoffset() == timedelta(0)


def test_duplicate_project_name_is_a_constraint_violation(db_session: Session) -> None:
    repository = ProjectRepository(db_session)
    repository.create(NewProject(name="lab"))

    with pytest.raises(ConstraintViolationError) as caught:
        repository.create(NewProject(name="lab"))

    assert caught.value.constraint == "uq_projects_name"


def test_get_project_returns_none_when_missing(db_session: Session) -> None:
    repository = ProjectRepository(db_session)
    created = repository.create(NewProject(name="lab"))

    assert repository.get(created.id) == created
    assert repository.get(uuid4()) is None


def test_list_projects_oldest_first_and_paginated(db_session: Session) -> None:
    repository = ProjectRepository(db_session)
    created = [repository.create(NewProject(name=f"lab-{n}")) for n in range(3)]
    # 同一個 transaction 內 now() 相同；改成不同的建立時間（最後建立的最舊），才驗得到主排序鍵。
    for minutes_ago, project in zip((10, 20, 30), created, strict=True):
        db_session.execute(
            text(
                "UPDATE projects SET created_at = now() - make_interval(mins => :m) WHERE id = :id"
            ),
            {"m": minutes_ago, "id": project.id},
        )
    db_session.expire_all()

    first = repository.list_page(PageRequest(page=1, limit=2))
    second = repository.list_page(PageRequest(page=2, limit=2))

    names = [project.name for project in first.items + second.items]
    assert names == ["lab-2", "lab-1", "lab-0"]
    assert first.total == second.total == 3


def test_list_projects_breaks_ties_by_id(db_session: Session) -> None:
    repository = ProjectRepository(db_session)
    created = [repository.create(NewProject(name=f"tie-{n}")) for n in range(3)]

    listed = repository.list_page(PageRequest(limit=10)).items

    assert [project.id for project in listed] == sorted(project.id for project in created)


# --- api_keys -----------------------------------------------------------------------------


def test_create_admin_and_project_keys(db_session: Session) -> None:
    project = ProjectRepository(db_session).create(NewProject(name="lab"))
    repository = ApiKeyRepository(db_session)
    expires_at = datetime(2027, 6, 30, tzinfo=UTC)

    admin = repository.create(_new_key())
    viewer = repository.create(
        _new_key(role=Role.VIEWER, name="ro", project_id=project.id, expires_at=expires_at)
    )

    assert isinstance(admin, ApiKey)
    assert (admin.role, admin.project_id, admin.revoked_at) == (Role.PLATFORM_ADMIN, None, None)
    assert (viewer.role, viewer.project_id, viewer.expires_at) == (
        Role.VIEWER,
        project.id,
        expires_at,
    )


def test_duplicate_key_prefix_is_a_constraint_violation(db_session: Session) -> None:
    repository = ApiKeyRepository(db_session)
    repository.create(_new_key(prefix="dupprefix001"))

    with pytest.raises(ConstraintViolationError) as caught:
        repository.create(_new_key(prefix="dupprefix001"))

    assert caught.value.constraint == "uq_api_keys_prefix"


def test_constraint_violation_does_not_leak_sql_values(db_session: Session) -> None:
    """重複的 key_hash：DB 的 DETAIL 與 SQL 參數都含 hash 值，不能出現在例外或 traceback 中。"""
    canary = b"CANARY-KEY-HASH-".ljust(KEY_HASH_BYTES, b"!")
    repository = ApiKeyRepository(db_session)
    repository.create(_new_key(key_hash=canary))

    with pytest.raises(ConstraintViolationError) as caught:
        repository.create(_new_key(key_hash=canary))

    assert (caught.value.constraint, caught.value.sqlstate) == ("uq_api_keys_key_hash", "23505")
    logged = "".join(traceback.format_exception(caught.value))
    for leaked in (canary.decode(), canary.hex(), "CANARY"):
        assert leaked not in logged
    assert "SQL parameters hidden" in str(caught.value.__context__)


def test_orm_rejects_naive_datetimes(db_session: Session) -> None:
    """繞過 domain 直接用 ORM 寫入，沒有時區的時間仍會在送進 DB 前被擋下（UtcDateTime）。"""
    db_session.add(
        ApiKeyModel(
            role=Role.PLATFORM_ADMIN.value,
            name="naive",
            prefix="naive0000001",
            key_hash=_hash(),
            expires_at=datetime(2027, 6, 30),
        )
    )

    with pytest.raises(StatementError, match="時區"), db_session.begin_nested():
        db_session.flush()


def test_find_key_by_id_and_prefix(db_session: Session) -> None:
    repository = ApiKeyRepository(db_session)
    created = repository.create(_new_key(prefix="lookup000001"))

    assert repository.get(created.id) == created
    assert repository.get_by_prefix("lookup000001") == created
    assert repository.get(uuid4()) is None
    assert repository.get_by_prefix("missing00001") is None


def test_revoke_marks_key_without_deleting_it(db_session: Session) -> None:
    repository = ApiKeyRepository(db_session)
    created = repository.create(_new_key())

    revoked = repository.revoke(created.id)

    assert revoked is not None
    assert revoked.revoked_at is not None
    assert revoked.revoked_at >= revoked.created_at
    assert repository.get(created.id) == revoked


def test_revoking_twice_keeps_the_first_revocation_time(db_session: Session) -> None:
    repository = ApiKeyRepository(db_session)
    created = repository.create(_new_key())
    # 模擬「一小時前已撤銷」：同一個 transaction 內 now() 不會變，只能直接設定較早的時間。
    db_session.execute(
        text(
            "UPDATE api_keys SET created_at = now() - interval '1 day', "
            "revoked_at = now() - interval '1 hour' WHERE id = :id"
        ),
        {"id": created.id},
    )
    db_session.expire_all()
    first_revoked_at = db_session.execute(
        text("SELECT revoked_at FROM api_keys WHERE id = :id"), {"id": created.id}
    ).scalar()

    again = repository.revoke(created.id)

    assert again is not None
    assert again.revoked_at == first_revoked_at


def test_revoke_returns_none_for_missing_key(db_session: Session) -> None:
    assert ApiKeyRepository(db_session).revoke(uuid4()) is None


# --- audit_events -------------------------------------------------------------------------


def test_append_audit_event_keeps_redacted_changes(db_session: Session) -> None:
    project = ProjectRepository(db_session).create(NewProject(name="lab"))
    actor = ApiKeyRepository(db_session).create(_new_key())
    changes: JsonObject = {
        "role": {"old": None, "new": "viewer"},
        "fields": ["name", "role"],
        "count": 2,
    }

    event = AuditEventRepository(db_session).append(
        NewAuditEvent(
            action="api_key.create",
            object_type="api_key",
            actor_key_id=actor.id,
            project_id=project.id,
            object_id=uuid4(),
            request_id="0" * 32,
            redacted_changes=changes,
        )
    )

    assert isinstance(event.id, UUID)
    assert event.created_at.utcoffset() == timedelta(0)
    assert (event.actor_key_id, event.project_id, event.request_id) == (
        actor.id,
        project.id,
        "0" * 32,
    )
    assert event.redacted_changes == changes


def test_audit_event_with_unknown_project_is_a_constraint_violation(db_session: Session) -> None:
    with pytest.raises(ConstraintViolationError) as caught:
        AuditEventRepository(db_session).append(
            NewAuditEvent(action="target.create", object_type="target", project_id=uuid4())
        )

    assert caught.value.constraint == "fk_audit_events_project_id_projects"


def test_list_audit_events_only_returns_the_project_newest_first(db_session: Session) -> None:
    projects = ProjectRepository(db_session)
    mine, other = (
        projects.create(NewProject(name="mine")),
        projects.create(NewProject(name="other")),
    )
    repository = AuditEventRepository(db_session)
    appended = [
        repository.append(NewAuditEvent(action=f"step.{n}", object_type="x", project_id=mine.id))
        for n in range(3)
    ]
    repository.append(NewAuditEvent(action="elsewhere", object_type="x", project_id=other.id))

    first = repository.list_by_project(mine.id, PageRequest(page=1, limit=2))
    second = repository.list_by_project(mine.id, PageRequest(page=2, limit=2))

    assert [event.action for event in first.items + second.items] == ["step.2", "step.1", "step.0"]
    assert first.total == second.total == 3
    assert {event.id for event in first.items + second.items} == {event.id for event in appended}
