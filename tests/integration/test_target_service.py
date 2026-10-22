"""TargetService：建立、清單、查詢與修改都經過權限規則，變更寫入 audit（docs/DECISIONS.md §10）。

在交易內執行，結束時回滾。
"""

from datetime import UTC, datetime
from ipaddress import IPv4Network
from uuid import UUID, uuid4

import pytest
from sqlalchemy.orm import Session

from secscan.api_keys.domain import Principal
from secscan.audit.domain import AuditEvent
from secscan.core.db import ConstraintViolationError
from secscan.core.errors import ErrorCode
from secscan.core.pagination import PageRequest
from secscan.projects.service import ProjectService
from secscan.targets import service as target_service
from secscan.targets.domain import LabNetwork, NewTarget, Target, TargetKind, TargetUpdate
from secscan.targets.repository import TargetRepository
from secscan.targets.service import TargetService
from tests.integration.scope_support import LAB, VAMPI, Members, app_error, members, same_response

pytestmark = pytest.mark.integration

NOW = datetime.now(UTC)
ALL = PageRequest(limit=100)
REQUEST_ID = "r" * 32


@pytest.fixture
def team(db_session: Session) -> Members:
    return members(db_session, NOW)


def _create(
    session: Session,
    principal: Principal,
    project_id: UUID,
    *,
    base_url: str = VAMPI,
    lab: LabNetwork = LAB,
) -> Target:
    return TargetService(session, lab=lab).create(
        principal,
        project_id,
        name="VAmPI",
        kind=TargetKind.API,
        base_url=base_url,
        request_id=REQUEST_ID,
    )


def _events(session: Session, team: Members, project_id: UUID, action: str) -> list[AuditEvent]:
    events = ProjectService(session).list_audit_events(team.admin, project_id, ALL).items
    return [event for event in events if event.action == action]


# --- 建立 -----------------------------------------------------------------------------------


def test_operator_creates_a_target_and_it_is_audited(db_session: Session, team: Members) -> None:
    target = _create(
        db_session, team.operator_a, team.project_a, base_url="HTTP://VAMPI-VULN:5000/"
    )

    assert str(target.origin) == VAMPI
    assert (target.project_id, target.kind, target.enabled) == (
        team.project_a,
        TargetKind.API,
        True,
    )
    [event] = _events(db_session, team, team.project_a, "target.create")
    assert (event.object_type, event.object_id, event.actor_key_id, event.request_id) == (
        "target",
        target.id,
        team.operator_a.key_id,
        REQUEST_ID,
    )
    assert event.redacted_changes == {"name": "VAmPI", "kind": "api", "origin": VAMPI}


def test_admin_creates_targets_only_in_existing_projects(
    db_session: Session, team: Members
) -> None:
    assert _create(db_session, team.admin, team.project_b).project_id == team.project_b

    error = app_error(lambda: _create(db_session, team.admin, uuid4()))

    assert (error.status_code, error.code) == (404, ErrorCode.RESOURCE_NOT_FOUND)


def test_viewer_cannot_create_and_other_projects_look_missing(
    db_session: Session, team: Members
) -> None:
    forbidden = app_error(lambda: _create(db_session, team.viewer_a, team.project_a))
    other = app_error(lambda: _create(db_session, team.operator_a, team.project_b))
    missing = app_error(lambda: _create(db_session, team.operator_a, uuid4()))

    assert (forbidden.status_code, forbidden.code) == (403, ErrorCode.ROLE_NOT_ALLOWED)
    assert (other.status_code, other.code) == (404, ErrorCode.RESOURCE_NOT_FOUND)
    assert same_response(other, missing)


def test_invalid_base_url_is_rejected_without_echoing_it(
    db_session: Session, team: Members
) -> None:
    base_url = "http://admin:hunter2-secret@vampi-vuln:5000"

    error = app_error(
        lambda: _create(db_session, team.operator_a, team.project_a, base_url=base_url)
    )

    assert (error.status_code, error.code) == (422, ErrorCode.INVALID_TARGET)
    assert "userinfo" in error.message
    assert "hunter2-secret" not in error.message
    assert (
        TargetService(db_session, lab=LAB).list_in_project(team.admin, team.project_a, ALL).total
        == 0
    )
    assert _events(db_session, team, team.project_a, "target.create") == []


def test_ip_hosts_must_be_lab_hosts(db_session: Session, team: Members) -> None:
    assert _create(db_session, team.operator_a, team.project_a, base_url="http://10.89.7.20:5000")

    outside = app_error(
        lambda: _create(db_session, team.operator_a, team.project_a, base_url="http://192.168.1.9")
    )
    narrowed = app_error(
        lambda: _create(
            db_session,
            team.operator_a,
            team.project_a,
            base_url="http://10.89.7.200",
            lab=LabNetwork(IPv4Network("10.89.7.0/25")),
        )
    )

    assert (outside.status_code, outside.code) == (422, ErrorCode.SCOPE_OUTSIDE_LAB)
    assert "10.89.7.0/24" in outside.message
    assert narrowed.code is ErrorCode.SCOPE_OUTSIDE_LAB


def test_duplicate_origin_in_a_project_is_a_conflict(db_session: Session, team: Members) -> None:
    _create(db_session, team.operator_a, team.project_a)

    # 實際的請求遇到錯誤會整個 rollback；這裡以 savepoint 隔離，之後還要用同一個 session。
    with db_session.begin_nested():
        error = app_error(lambda: _create(db_session, team.operator_a, team.project_a))

    assert (error.status_code, error.code) == (409, ErrorCode.TARGET_ORIGIN_CONFLICT)
    assert "uq_" not in error.message
    assert _create(db_session, team.operator_b, team.project_b)


def test_targets_per_project_are_capped(
    db_session: Session, team: Members, monkeypatch: pytest.MonkeyPatch
) -> None:
    """每個 target 最多有固定數量的待核准申請；target 的數量也要有上限，總量才有上界。"""
    monkeypatch.setattr(target_service, "MAX_TARGETS_PER_PROJECT", 2)
    _create(db_session, team.operator_a, team.project_a, base_url="http://lab-1")
    _create(db_session, team.operator_a, team.project_a, base_url="http://lab-2")

    error = app_error(
        lambda: _create(db_session, team.operator_a, team.project_a, base_url="http://lab-3")
    )

    assert (error.status_code, error.code) == (409, ErrorCode.QUOTA_EXCEEDED)
    assert _create(db_session, team.operator_b, team.project_b, base_url="http://lab-3")


def test_unknown_constraint_violation_is_not_mapped(
    db_session: Session, team: Members, monkeypatch: pytest.MonkeyPatch
) -> None:
    def violate(_self: TargetRepository, _target: NewTarget) -> Target:
        raise ConstraintViolationError("ck_targets_something_new", "23514")

    monkeypatch.setattr(TargetRepository, "create", violate)

    with pytest.raises(ConstraintViolationError):
        _create(db_session, team.operator_a, team.project_a)


# --- 查詢 -----------------------------------------------------------------------------------


def test_targets_are_listed_per_project(db_session: Session, team: Members) -> None:
    service = TargetService(db_session, lab=LAB)
    first = _create(db_session, team.operator_a, team.project_a)
    second = _create(db_session, team.operator_a, team.project_a, base_url="http://juice-shop:3000")
    _create(db_session, team.operator_b, team.project_b)

    page = service.list_in_project(team.viewer_a, team.project_a, ALL)
    other = app_error(lambda: service.list_in_project(team.viewer_a, team.project_b, ALL))
    missing = app_error(lambda: service.list_in_project(team.admin, uuid4(), ALL))

    # 同一個 transaction 建立的 target 建立時間相同，順序由 id 決定（分頁仍然穩定）。
    expected = sorted([first, second], key=lambda target: (target.created_at, target.id))
    assert [target.id for target in page.items] == [target.id for target in expected]
    assert page.total == 2
    assert service.list_in_project(team.admin, team.project_b, ALL).total == 1
    assert (other.status_code, other.code) == (404, ErrorCode.RESOURCE_NOT_FOUND)
    assert same_response(other, missing)


def test_target_of_another_project_looks_missing(db_session: Session, team: Members) -> None:
    service = TargetService(db_session, lab=LAB)
    target = _create(db_session, team.operator_a, team.project_a)

    assert service.get(team.viewer_a, target.id) == target
    assert service.get(team.admin, target.id) == target
    other = app_error(lambda: service.get(team.operator_b, target.id))
    missing = app_error(lambda: service.get(team.operator_b, uuid4()))
    assert (other.status_code, other.code) == (404, ErrorCode.RESOURCE_NOT_FOUND)
    assert same_response(other, missing)


# --- 修改 -----------------------------------------------------------------------------------


def test_operator_disables_and_renames_a_target(db_session: Session, team: Members) -> None:
    service = TargetService(db_session, lab=LAB)
    target = _create(db_session, team.operator_a, team.project_a)

    disabled = service.update(
        team.operator_a, target.id, TargetUpdate(enabled=False), request_id=REQUEST_ID
    )
    service.update(team.operator_a, target.id, TargetUpdate(enabled=False), request_id=None)
    renamed = service.update(team.admin, target.id, TargetUpdate(name="VAmPI 2"), request_id=None)

    assert disabled.enabled is False
    assert (renamed.name, renamed.enabled) == ("VAmPI 2", False)
    events = _events(db_session, team, team.project_a, "target.update")
    assert [event.redacted_changes for event in reversed(events)] == [
        {"enabled": {"from": True, "to": False}},
        {"name": {"from": "VAmPI", "to": "VAmPI 2"}},
    ]
    assert events[-1].actor_key_id == team.operator_a.key_id


def test_viewer_cannot_update_and_other_projects_look_missing(
    db_session: Session, team: Members
) -> None:
    service = TargetService(db_session, lab=LAB)
    target = _create(db_session, team.operator_a, team.project_a)
    change = TargetUpdate(enabled=False)

    forbidden = app_error(lambda: service.update(team.viewer_a, target.id, change, request_id=None))
    other = app_error(lambda: service.update(team.operator_b, target.id, change, request_id=None))
    missing = app_error(lambda: service.update(team.operator_b, uuid4(), change, request_id=None))

    assert (forbidden.status_code, forbidden.code) == (403, ErrorCode.ROLE_NOT_ALLOWED)
    assert (other.status_code, other.code) == (404, ErrorCode.RESOURCE_NOT_FOUND)
    assert same_response(other, missing)
    assert service.get(team.admin, target.id).enabled is True


def test_target_vanishing_before_the_update_looks_missing(
    db_session: Session, team: Members, monkeypatch: pytest.MonkeyPatch
) -> None:
    """授權檢查之後、上鎖之前 target 消失（只可能直接改 DB）：回 404。"""
    target = _create(db_session, team.operator_a, team.project_a)
    monkeypatch.setattr(TargetRepository, "update", lambda *_args, **_kwargs: None)

    error = app_error(
        lambda: TargetService(db_session, lab=LAB).update(
            team.operator_a, target.id, TargetUpdate(enabled=False), request_id=None
        )
    )

    assert (error.status_code, error.code) == (404, ErrorCode.RESOURCE_NOT_FOUND)
