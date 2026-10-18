"""ProjectService：建立、清單、單一 project 與稽核查詢都經過權限規則（docs/DECISIONS.md §9.2）。

在交易內執行，結束時回滾。
"""

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy.orm import Session

from secscan.api_keys.domain import Principal, Role
from secscan.api_keys.service import ApiKeyService
from secscan.core.db import ConstraintViolationError
from secscan.core.errors import AppError, ErrorCode
from secscan.core.pagination import PageRequest
from secscan.projects.domain import Project
from secscan.projects.repository import ProjectRepository
from secscan.projects.service import ProjectService

pytestmark = pytest.mark.integration

NOW = datetime.now(UTC)
ALL = PageRequest(limit=100)


def _admin(session: Session) -> Principal:
    issued = ApiKeyService(session).issue_admin_key(name="admin", expires_at=None, now=NOW)
    return Principal.of(issued.key)


def _member(session: Session, admin: Principal, project_id: UUID, role: Role) -> Principal:
    issued = ApiKeyService(session).issue_project_key(
        admin, project_id, name="member", role=role, expires_at=None, now=NOW, request_id=None
    )
    return Principal.of(issued.key)


def _create(session: Session, admin: Principal) -> Project:
    return ProjectService(session).create(admin, name=f"lab-{uuid4().hex[:8]}", request_id=None)


def _app_error(call: object) -> AppError:
    assert callable(call)
    with pytest.raises(AppError) as caught:
        call()
    return caught.value


def test_admin_creates_a_project_and_it_is_audited(db_session: Session) -> None:
    admin = _admin(db_session)
    service = ProjectService(db_session)

    project = service.create(admin, name="API 教學靶場", request_id="a" * 32)

    [event] = service.list_audit_events(admin, project.id, ALL).items
    assert (event.action, event.object_type, event.object_id) == (
        "project.create",
        "project",
        project.id,
    )
    assert (event.actor_key_id, event.request_id) == (admin.key_id, "a" * 32)
    assert event.redacted_changes == {"name": "API 教學靶場"}


def test_duplicate_name_is_a_conflict_without_constraint_details(db_session: Session) -> None:
    admin = _admin(db_session)
    service = ProjectService(db_session)
    service.create(admin, name="duplicate", request_id=None)

    error = _app_error(lambda: service.create(admin, name="duplicate", request_id=None))

    assert (error.status_code, error.code) == (409, ErrorCode.PROJECT_NAME_CONFLICT)
    assert "uq_" not in error.message


def test_unknown_constraint_violation_is_not_mapped(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    admin = _admin(db_session)

    def violate(_self: ProjectRepository, _new_project: object) -> None:
        raise ConstraintViolationError("ck_projects_future_rule", "23514")

    monkeypatch.setattr(ProjectRepository, "create", violate)

    with pytest.raises(ConstraintViolationError):
        ProjectService(db_session).create(admin, name="lab", request_id=None)


@pytest.mark.parametrize("role", [Role.OPERATOR, Role.VIEWER])
def test_only_platform_admin_creates_projects(db_session: Session, role: Role) -> None:
    admin = _admin(db_session)
    member = _member(db_session, admin, _create(db_session, admin).id, role)

    error = _app_error(
        lambda: ProjectService(db_session).create(member, name="mine", request_id=None)
    )

    assert (error.status_code, error.code) == (403, ErrorCode.ROLE_NOT_ALLOWED)


@pytest.mark.parametrize("role", [Role.OPERATOR, Role.VIEWER])
def test_members_only_list_their_own_project(db_session: Session, role: Role) -> None:
    admin = _admin(db_session)
    mine, other = _create(db_session, admin), _create(db_session, admin)
    member = _member(db_session, admin, mine.id, role)
    service = ProjectService(db_session)

    visible = service.list_visible(member, ALL)
    everything = service.list_visible(admin, ALL)

    assert (visible.items, visible.total) == ((mine,), 1)
    assert {mine, other} <= set(everything.items)


@pytest.mark.parametrize("role", [Role.OPERATOR, Role.VIEWER])
def test_other_projects_look_exactly_like_missing_ones(db_session: Session, role: Role) -> None:
    admin = _admin(db_session)
    mine, other = _create(db_session, admin), _create(db_session, admin)
    member = _member(db_session, admin, mine.id, role)
    service = ProjectService(db_session)

    hidden = _app_error(lambda: service.get(member, other.id))
    missing = _app_error(lambda: service.get(member, uuid4()))

    assert service.get(member, mine.id) == mine
    assert (hidden.status_code, hidden.code, hidden.message) == (
        missing.status_code,
        missing.code,
        missing.message,
    )
    assert hidden.status_code == 404


def test_admin_gets_any_project_but_not_missing_ones(db_session: Session) -> None:
    admin = _admin(db_session)
    project = _create(db_session, admin)
    service = ProjectService(db_session)

    assert service.get(admin, project.id) == project
    assert _app_error(lambda: service.get(admin, uuid4())).status_code == 404


@pytest.mark.parametrize("role", [Role.OPERATOR, Role.VIEWER])
def test_audit_events_are_for_platform_admin_only(db_session: Session, role: Role) -> None:
    admin = _admin(db_session)
    mine, other = _create(db_session, admin), _create(db_session, admin)
    member = _member(db_session, admin, mine.id, role)
    service = ProjectService(db_session)

    own = _app_error(lambda: service.list_audit_events(member, mine.id, ALL))
    foreign = _app_error(lambda: service.list_audit_events(member, other.id, ALL))
    missing = _app_error(lambda: service.list_audit_events(admin, uuid4(), ALL))

    assert (own.status_code, own.code) == (403, ErrorCode.ROLE_NOT_ALLOWED)
    assert foreign.status_code == missing.status_code == 404
    assert [event.action for event in service.list_audit_events(admin, mine.id, ALL).items] == [
        "api_key.create",
        "project.create",
    ]
