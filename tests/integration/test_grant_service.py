"""ScopeGrantService：申請、核准、撤銷、查詢與掃描 gate（docs/DECISIONS.md §10.4 到 §10.6）。

在交易內執行，結束時回滾。期限以注入的 now 模擬，不依賴實際經過的時間。
"""

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Network
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from secscan.api_keys.domain import Principal
from secscan.audit.domain import AuditEvent
from secscan.core.errors import AppError, ErrorCode
from secscan.core.pagination import PageRequest
from secscan.grants.domain.lifecycle import GrantStatus, ScopeGrant
from secscan.grants.domain.scope import build_new_grant
from secscan.grants.repository import ScopeGrantRepository
from secscan.grants.service import MAX_PENDING_GRANTS_PER_TARGET, ScopeGrantService
from secscan.projects.service import ProjectService
from secscan.security.redaction import REDACTED
from secscan.targets.domain import LabNetwork, Target, TargetKind, TargetUpdate
from secscan.targets.repository import TargetRepository
from secscan.targets.service import TargetService
from tests.integration.scope_support import (
    LAB,
    VAMPI,
    Members,
    app_error,
    grant_request,
    members,
    same_response,
)

pytestmark = pytest.mark.integration

NOW = datetime.now(UTC)
LATER = NOW + timedelta(days=8)  # 預設的申請期限是 7 天，這時已過期
ALL = PageRequest(limit=100)
REQUEST_ID = "r" * 32


@pytest.fixture
def team(db_session: Session) -> Members:
    return members(db_session, NOW)


@pytest.fixture
def target(db_session: Session, team: Members) -> Target:
    return _target(db_session, team, VAMPI)


def _target(session: Session, team: Members, base_url: str) -> Target:
    return TargetService(session, lab=LAB).create(
        team.operator_a,
        team.project_a,
        name="VAmPI",
        kind=TargetKind.API,
        base_url=base_url,
        request_id=None,
    )


def _service(session: Session, lab: LabNetwork = LAB) -> ScopeGrantService:
    return ScopeGrantService(session, lab=lab)


def _request(
    session: Session, principal: Principal, target_id: UUID, **overrides: object
) -> ScopeGrant:
    return _service(session).request(
        principal, target_id, grant_request(NOW, **overrides), now=NOW, request_id=REQUEST_ID
    )


def _approve(
    session: Session, principal: Principal, grant_id: UUID, *, now: datetime = NOW
) -> ScopeGrant:
    return _service(session).approve(
        principal, grant_id, note="已核對 lab 資產與 IP", now=now, request_id=REQUEST_ID
    )


def _revoke(
    session: Session, principal: Principal, grant_id: UUID, *, now: datetime = NOW
) -> ScopeGrant:
    return _service(session).revoke(
        principal, grant_id, reason="實驗結束", now=now, request_id=REQUEST_ID
    )


def _events(session: Session, team: Members, action: str) -> list[AuditEvent]:
    events = ProjectService(session).list_audit_events(team.admin, team.project_a, ALL).items
    return [event for event in events if event.action == action]


# --- 申請 -----------------------------------------------------------------------------------


def test_operator_requests_grants_with_consecutive_versions(
    db_session: Session, team: Members, target: Target
) -> None:
    first = _request(db_session, team.operator_a, target.id)
    second = _request(db_session, team.admin, target.id, allow_all_paths=True, paths=())

    assert (first.version, second.version) == (1, 2)
    assert first.status is GrantStatus.PENDING
    assert (first.project_id, first.requested_by_key_id) == (team.project_a, team.operator_a.key_id)
    created = _events(db_session, team, "scope_grant.create")
    assert [event.object_id for event in created] == [second.id, first.id]
    assert created[-1].redacted_changes == {
        "version": 1,
        "target_id": str(target.id),
        "origins": [VAMPI],
        "ips": ["10.89.7.20"],
        "methods": ["GET"],
        "allow_all_paths": False,
        "path_count": 1,
        "excluded_path_count": 0,
        "budget": {"requests_per_second": 2, "max_requests": 5000, "max_duration_seconds": 1500},
        "valid_from": first.window.valid_from.isoformat(),
        "valid_until": first.window.valid_until.isoformat(),
        "reference": "LAB-ASSET-001",
    }


def test_viewer_cannot_request_and_other_projects_look_missing(
    db_session: Session, team: Members, target: Target
) -> None:
    forbidden = app_error(lambda: _request(db_session, team.viewer_a, target.id))
    other = app_error(lambda: _request(db_session, team.operator_b, target.id))
    missing = app_error(lambda: _request(db_session, team.operator_b, uuid4()))

    assert (forbidden.status_code, forbidden.code) == (403, ErrorCode.ROLE_NOT_ALLOWED)
    assert (other.status_code, other.code) == (404, ErrorCode.RESOURCE_NOT_FOUND)
    assert same_response(other, missing)


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"origins": ("https://vampi-vuln:5000",)}, ErrorCode.INVALID_TARGET),
        ({"origins": ("http://juice-shop:3000",)}, ErrorCode.INVALID_REQUEST),
        ({"paths": ("/users/../admin",)}, ErrorCode.INVALID_REQUEST),
        ({"methods": ("TRACE",)}, ErrorCode.INVALID_REQUEST),
        ({"max_requests": 5001}, ErrorCode.INVALID_REQUEST),
        ({"valid_until": NOW - timedelta(minutes=1)}, ErrorCode.INVALID_REQUEST),
        ({"ips": ("192.168.1.10",)}, ErrorCode.SCOPE_OUTSIDE_LAB),
        ({"ips": ("10.89.7.255",)}, ErrorCode.SCOPE_OUTSIDE_LAB),
    ],
)
def test_invalid_requests_store_nothing(
    db_session: Session,
    team: Members,
    target: Target,
    overrides: dict[str, object],
    code: ErrorCode,
) -> None:
    error = app_error(lambda: _request(db_session, team.operator_a, target.id, **overrides))

    assert (error.status_code, error.code) == (422, code)
    assert error.message.endswith("。")
    assert _service(db_session).list_for_target(team.admin, target.id, ALL).total == 0
    assert _events(db_session, team, "scope_grant.create") == []


def test_audit_changes_are_masked(db_session: Session, team: Members, target: Target) -> None:
    reference = "Bearer abcdefghijklmnopqrstuvwxyz"
    grant = _request(db_session, team.operator_a, target.id, authorization_reference=reference)

    [event] = _events(db_session, team, "scope_grant.create")

    assert grant.authorization_reference == reference
    assert event.redacted_changes["reference"] == REDACTED


# --- 核准與撤銷 -----------------------------------------------------------------------------


def test_admin_approves_a_pending_grant(db_session: Session, team: Members, target: Target) -> None:
    grant = _request(db_session, team.operator_a, target.id)

    approved = _approve(db_session, team.admin, grant.id)

    assert approved.status is GrantStatus.APPROVED
    assert (approved.approved_by_key_id, approved.approval_note) == (
        team.admin.key_id,
        "已核對 lab 資產與 IP",
    )
    [event] = _events(db_session, team, "scope_grant.approve")
    assert (event.object_id, event.actor_key_id, event.request_id) == (
        grant.id,
        team.admin.key_id,
        REQUEST_ID,
    )
    assert event.redacted_changes == {"version": 1, "note": "已核對 lab 資產與 IP"}


def test_only_admin_approves_or_revokes(db_session: Session, team: Members, target: Target) -> None:
    grant = _request(db_session, team.operator_a, target.id)

    for decide in (_approve, _revoke):
        operator = app_error(lambda: decide(db_session, team.operator_a, grant.id))  # noqa: B023
        viewer = app_error(lambda: decide(db_session, team.viewer_a, grant.id))  # noqa: B023
        other = app_error(lambda: decide(db_session, team.operator_b, grant.id))  # noqa: B023
        missing = app_error(lambda: decide(db_session, team.operator_b, uuid4()))  # noqa: B023
        assert (operator.status_code, operator.code) == (403, ErrorCode.ROLE_NOT_ALLOWED)
        assert (viewer.status_code, viewer.code) == (403, ErrorCode.ROLE_NOT_ALLOWED)
        assert (other.status_code, other.code) == (404, ErrorCode.RESOURCE_NOT_FOUND)
        assert same_response(other, missing)
    assert _service(db_session).get(team.admin, grant.id).status is GrantStatus.PENDING


def _conflict(call: object) -> AppError:
    error = app_error(call)  # type: ignore[arg-type]
    assert (error.status_code, error.code) == (409, ErrorCode.INVALID_STATE_TRANSITION)
    return error


def test_invalid_transitions_are_conflicts(
    db_session: Session, team: Members, target: Target
) -> None:
    approved = _request(db_session, team.operator_a, target.id)
    _approve(db_session, team.admin, approved.id)
    revoked = _request(db_session, team.operator_a, target.id)
    _revoke(db_session, team.admin, revoked.id)
    expired = _request(db_session, team.operator_a, target.id)

    assert "approved" in _conflict(lambda: _approve(db_session, team.admin, approved.id)).message
    assert "revoked" in _conflict(lambda: _approve(db_session, team.admin, revoked.id)).message
    _conflict(lambda: _approve(db_session, team.admin, expired.id, now=LATER))
    _conflict(lambda: _revoke(db_session, team.admin, expired.id, now=LATER))
    assert _service(db_session).get(team.admin, expired.id).status is GrantStatus.PENDING


def test_approval_rechecks_the_current_lab_network(
    db_session: Session, team: Members, target: Target
) -> None:
    grant = _request(db_session, team.operator_a, target.id, ips=("10.89.7.200",))
    narrowed = LabNetwork(IPv4Network("10.89.7.0/25"))

    error = app_error(
        lambda: _service(db_session, narrowed).approve(
            team.admin, grant.id, note="ok", now=NOW, request_id=None
        )
    )

    assert (error.status_code, error.code) == (422, ErrorCode.SCOPE_OUTSIDE_LAB)
    assert _service(db_session).get(team.admin, grant.id).status is GrantStatus.PENDING
    assert _events(db_session, team, "scope_grant.approve") == []


def test_revocation_is_recorded_once(db_session: Session, team: Members, target: Target) -> None:
    pending = _request(db_session, team.operator_a, target.id)
    approved = _request(db_session, team.operator_a, target.id)
    _approve(db_session, team.admin, approved.id)

    first = _revoke(db_session, team.admin, pending.id)
    again = _revoke(db_session, team.admin, pending.id)
    after_approval = _revoke(db_session, team.admin, approved.id)

    assert first.status is GrantStatus.REVOKED
    assert again == first
    assert after_approval.approved_at is not None
    events = _events(db_session, team, "scope_grant.revoke")
    assert [event.object_id for event in reversed(events)] == [pending.id, approved.id]
    assert [event.redacted_changes["previous_state"] for event in reversed(events)] == [
        "pending",
        "approved",
    ]
    assert events[0].redacted_changes["reason"] == "實驗結束"


# --- 查詢 -----------------------------------------------------------------------------------


def test_grants_are_read_by_project_members(
    db_session: Session, team: Members, target: Target
) -> None:
    service = _service(db_session)
    first = _request(db_session, team.operator_a, target.id)
    second = _request(db_session, team.operator_a, target.id)

    assert service.get(team.viewer_a, first.id) == first
    assert [grant.id for grant in service.list_for_target(team.viewer_a, target.id, ALL).items] == [
        second.id,
        first.id,
    ]
    other = app_error(lambda: service.get(team.operator_b, first.id))
    missing = app_error(lambda: service.get(team.operator_b, uuid4()))
    other_list = app_error(lambda: service.list_for_target(team.operator_b, target.id, ALL))
    assert same_response(other, missing)
    assert same_response(other_list, missing)


def test_expiry_is_derived_from_the_window_not_stored(
    db_session: Session, team: Members, target: Target
) -> None:
    """過期不改 DB：同一筆 grant 在到期前後讀出來的狀態不同。"""
    grant = _approve(db_session, team.admin, _request(db_session, team.operator_a, target.id).id)

    assert grant.state_at(NOW).value == "approved"
    assert grant.state_at(LATER).value == "expired"
    assert _service(db_session).get(team.admin, grant.id).status is GrantStatus.APPROVED


# --- 掃描 gate ------------------------------------------------------------------------------


def _usable(
    session: Session,
    principal: Principal,
    target_id: UUID,
    grant_id: UUID,
    *,
    now: datetime = NOW,
    lab: LabNetwork = LAB,
) -> ScopeGrant:
    return (
        _service(session, lab)
        .require_usable(principal, target_id=target_id, grant_id=grant_id, clock=lambda: now)
        .grant
    )


def test_approved_grant_is_usable_by_operators(
    db_session: Session, team: Members, target: Target
) -> None:
    grant = _approve(db_session, team.admin, _request(db_session, team.operator_a, target.id).id)

    assert _usable(db_session, team.operator_a, target.id, grant.id) == grant
    assert _usable(db_session, team.admin, target.id, grant.id) == grant


def _gate_error(call: object, status: int, code: ErrorCode) -> str:
    error = app_error(call)  # type: ignore[arg-type]
    assert (error.status_code, error.code) == (status, code)
    return error.message


def test_gate_rejects_grants_that_are_not_currently_approved(
    db_session: Session, team: Members, target: Target
) -> None:
    pending = _request(db_session, team.operator_a, target.id)
    revoked = _revoke(db_session, team.admin, _request(db_session, team.operator_a, target.id).id)
    approved = _approve(db_session, team.admin, _request(db_session, team.operator_a, target.id).id)
    future = _approve(
        db_session,
        team.admin,
        _request(
            db_session,
            team.operator_a,
            target.id,
            valid_from=NOW + timedelta(days=1),
            valid_until=NOW + timedelta(days=2),
        ).id,
    )
    user = team.operator_a

    messages = {
        _gate_error(
            lambda: _usable(db_session, user, target.id, pending.id),
            403,
            ErrorCode.SCOPE_NOT_APPROVED,
        ),
        _gate_error(
            lambda: _usable(db_session, user, target.id, revoked.id),
            403,
            ErrorCode.SCOPE_NOT_APPROVED,
        ),
        _gate_error(
            lambda: _usable(db_session, user, target.id, future.id),
            403,
            ErrorCode.SCOPE_NOT_APPROVED,
        ),
    }
    _gate_error(
        lambda: _usable(db_session, user, target.id, approved.id, now=LATER),
        403,
        ErrorCode.SCOPE_EXPIRED,
    )
    assert len(messages) == 3  # 未核准、已撤銷、尚未生效各有不同的說明


def test_gate_rejects_a_disabled_target_and_ips_outside_the_current_lab(
    db_session: Session, team: Members, target: Target
) -> None:
    grant = _approve(
        db_session,
        team.admin,
        _request(db_session, team.operator_a, target.id, ips=("10.89.7.200",)).id,
    )
    narrowed = LabNetwork(IPv4Network("10.89.7.0/25"))

    _gate_error(
        lambda: _usable(db_session, team.operator_a, target.id, grant.id, lab=narrowed),
        422,
        ErrorCode.SCOPE_OUTSIDE_LAB,
    )
    TargetService(db_session, lab=LAB).update(
        team.operator_a, target.id, TargetUpdate(enabled=False), request_id=None
    )
    _gate_error(
        lambda: _usable(db_session, team.operator_a, target.id, grant.id),
        409,
        ErrorCode.TARGET_DISABLED,
    )


def test_gate_checks_who_asks_and_which_target(
    db_session: Session, team: Members, target: Target
) -> None:
    grant = _approve(db_session, team.admin, _request(db_session, team.operator_a, target.id).id)
    sibling = _target(db_session, team, "http://juice-shop:3000")
    other_project_target = TargetService(db_session, lab=LAB).create(
        team.operator_b,
        team.project_b,
        name="VAmPI",
        kind=TargetKind.API,
        base_url=VAMPI,
        request_id=None,
    )

    _gate_error(
        lambda: _usable(db_session, team.viewer_a, target.id, grant.id),
        403,
        ErrorCode.ROLE_NOT_ALLOWED,
    )
    _gate_error(
        lambda: _usable(db_session, team.operator_a, sibling.id, grant.id),
        422,
        ErrorCode.INVALID_REQUEST,
    )
    other = app_error(lambda: _usable(db_session, team.operator_b, target.id, grant.id))
    foreign_grant = app_error(
        lambda: _usable(db_session, team.operator_b, other_project_target.id, grant.id)
    )
    missing = app_error(lambda: _usable(db_session, team.operator_b, target.id, uuid4()))
    assert (other.status_code, other.code) == (404, ErrorCode.RESOURCE_NOT_FOUND)
    assert same_response(other, missing)
    assert same_response(foreign_grant, missing)


# --- 其他 -----------------------------------------------------------------------------------


@pytest.mark.parametrize("text", ["", "   ", "x\x00", "x" * 501])
def test_decisions_need_a_readable_note(
    db_session: Session, team: Members, target: Target, text: str
) -> None:
    grant = _request(db_session, team.operator_a, target.id)
    service = _service(db_session)

    approve = app_error(
        lambda: service.approve(team.admin, grant.id, note=text, now=NOW, request_id=None)
    )
    revoke = app_error(
        lambda: service.revoke(team.admin, grant.id, reason=text, now=NOW, request_id=None)
    )

    assert (approve.status_code, approve.code) == (422, ErrorCode.INVALID_REQUEST)
    assert (revoke.status_code, revoke.code) == (422, ErrorCode.INVALID_REQUEST)
    assert service.get(team.admin, grant.id).status is GrantStatus.PENDING


def test_pending_requests_per_target_are_capped(
    db_session: Session, team: Members, target: Target
) -> None:
    """grant 無法刪除、單筆可達上百 KB：待核准的申請有上限，避免一把 operator key 塞滿磁碟。"""
    for _ in range(MAX_PENDING_GRANTS_PER_TARGET):
        _request(db_session, team.operator_a, target.id)

    error = app_error(lambda: _request(db_session, team.operator_a, target.id))

    assert (error.status_code, error.code) == (409, ErrorCode.QUOTA_EXCEEDED)
    oldest = _service(db_session).list_for_target(team.admin, target.id, ALL).items[-1]
    _revoke(db_session, team.admin, oldest.id)
    assert _request(db_session, team.operator_a, target.id).status is GrantStatus.PENDING
    # 已過期的申請不佔名額。
    later = _service(db_session).request(
        team.operator_a, target.id, grant_request(LATER), now=LATER, request_id=None
    )
    assert later.status is GrantStatus.PENDING


def test_permission_is_checked_before_the_note(
    db_session: Session, team: Members, target: Target
) -> None:
    """與其他 service 相同：先檢查權限，再驗證輸入（直接呼叫 service 時也一樣）。"""
    grant = _request(db_session, team.operator_a, target.id)
    service = _service(db_session)

    approve = app_error(
        lambda: service.approve(team.viewer_a, grant.id, note=" ", now=NOW, request_id=None)
    )
    revoke = app_error(
        lambda: service.revoke(team.operator_b, grant.id, reason="", now=NOW, request_id=None)
    )

    assert (approve.status_code, approve.code) == (403, ErrorCode.ROLE_NOT_ALLOWED)
    assert (revoke.status_code, revoke.code) == (404, ErrorCode.RESOURCE_NOT_FOUND)


def test_gate_rejects_a_target_whose_origin_is_not_in_the_grant(
    db_session: Session, team: Members, target: Target
) -> None:
    """API 不能改 origin；這裡直接改 DB，確認 gate 自己也會比對（縱深防禦）。"""
    grant = _approve(db_session, team.admin, _request(db_session, team.operator_a, target.id).id)
    db_session.execute(
        text("UPDATE targets SET canonical_origin = 'http://juice-shop:3000' WHERE id = :id"),
        {"id": target.id},
    )

    _gate_error(
        lambda: _usable(db_session, team.operator_a, target.id, grant.id),
        422,
        ErrorCode.INVALID_REQUEST,
    )


def test_rows_vanishing_before_the_lock_look_missing(
    db_session: Session, team: Members, target: Target, monkeypatch: pytest.MonkeyPatch
) -> None:
    """授權檢查之後、上鎖之前資料列消失（只可能直接改 DB）：回 404，不會用到舊的資料。"""
    grant = _approve(db_session, team.admin, _request(db_session, team.operator_a, target.id).id)
    monkeypatch.setattr(TargetRepository, "lock", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(ScopeGrantRepository, "lock", lambda *_args, **_kwargs: None)

    errors = [
        app_error(lambda: _request(db_session, team.operator_a, target.id)),
        app_error(lambda: _revoke(db_session, team.admin, grant.id)),
        app_error(lambda: _usable(db_session, team.operator_a, target.id, grant.id)),
    ]

    assert {(error.status_code, error.code) for error in errors} == {
        (404, ErrorCode.RESOURCE_NOT_FOUND)
    }


def test_repository_fails_loudly_if_a_written_grant_cannot_be_read_back(
    db_session: Session, team: Members, target: Target, monkeypatch: pytest.MonkeyPatch
) -> None:
    """寫入後在同一個 transaction 讀不回來代表程式有錯：直接失敗，不回傳不完整的資料。"""
    monkeypatch.setattr(ScopeGrantRepository, "get", lambda *_args, **_kwargs: None)

    with pytest.raises(LookupError):
        ScopeGrantRepository(db_session).create(
            build_new_grant(
                grant_request(NOW),
                target_id=target.id,
                target_origin=target.origin,
                requested_by=team.operator_a.key_id,
                now=NOW,
            ),
            version=1,
        )
