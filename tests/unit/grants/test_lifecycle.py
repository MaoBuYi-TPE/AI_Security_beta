"""grant 的狀態推導、轉換與掃描 gate（docs/DECISIONS.md §10.4、§10.6）；純函式，整張表都測。"""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Network
from typing import Any
from uuid import UUID, uuid4

import pytest

from secscan.grants.domain.lifecycle import (
    GrantAction,
    GrantState,
    GrantStatus,
    GrantUnusableError,
    InvalidTransitionError,
    ScopeGrant,
    UnusableReason,
    check_usable,
    effective_state,
    plan_transition,
)
from secscan.grants.domain.scope import ValidityWindow, build_scope, resolve_budget
from secscan.grants.service import UNUSABLE_ERRORS
from secscan.targets.domain import (
    LabNetwork,
    OutsideLabError,
    Target,
    TargetEnvironment,
    TargetKind,
    parse_origin,
)

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)
TICK = timedelta(microseconds=1)
LAB = LabNetwork(IPv4Network("10.89.7.0/24"))
ORIGIN = parse_origin("http://vampi-vuln:5000")

PENDING, APPROVED, REVOKED, EXPIRED = (
    GrantState.PENDING,
    GrantState.APPROVED,
    GrantState.REVOKED,
    GrantState.EXPIRED,
)
APPROVE, REVOKE = GrantAction.APPROVE, GrantAction.REVOKE


def _target(*, enabled: bool = True) -> Target:
    return Target(
        id=uuid4(),
        project_id=uuid4(),
        name="vampi",
        kind=TargetKind.API,
        origin=ORIGIN,
        environment=TargetEnvironment.LAB,
        enabled=enabled,
        created_at=NOW - timedelta(days=3),
    )


def _grant(
    target: Target,
    *,
    status: GrantStatus = GrantStatus.APPROVED,
    valid_from: datetime = NOW - timedelta(days=1),
    valid_until: datetime = NOW + timedelta(days=1),
    ip: str = "10.89.7.20",
) -> ScopeGrant:
    actor = uuid4()
    approved = status is GrantStatus.APPROVED
    revoked = status is GrantStatus.REVOKED
    return ScopeGrant(
        id=uuid4(),
        target_id=target.id,
        project_id=target.project_id,
        version=1,
        status=status,
        scope=build_scope(
            target_origin=ORIGIN,
            origins=[str(ORIGIN)],
            ips=[ip],
            paths=["/users/v1"],
            allow_all_paths=False,
            excluded_paths=[],
            methods=["GET"],
        ),
        budget=resolve_budget(),
        window=ValidityWindow(valid_from=valid_from, valid_until=valid_until),
        authorization_reference="LAB-ASSET-001",
        requested_by_key_id=actor,
        created_at=NOW - timedelta(days=2),
        approved_by_key_id=actor if approved else None,
        approved_at=NOW - timedelta(days=1) if approved else None,
        approval_note="已核對 lab 資產" if approved else None,
        revoked_by_key_id=actor if revoked else None,
        revoked_at=NOW - timedelta(hours=1) if revoked else None,
        revocation_reason="實驗結束" if revoked else None,
    )


# --- 狀態推導 -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "now", "expected"),
    [
        (GrantStatus.PENDING, NOW - TICK, PENDING),
        (GrantStatus.PENDING, NOW, EXPIRED),
        (GrantStatus.APPROVED, NOW - TICK, APPROVED),
        (GrantStatus.APPROVED, NOW, EXPIRED),
        (GrantStatus.APPROVED, NOW + timedelta(days=1), EXPIRED),
        # revoked 優先於 expired：已撤銷的 grant 到期後仍然顯示已撤銷。
        (GrantStatus.REVOKED, NOW - TICK, REVOKED),
        (GrantStatus.REVOKED, NOW + timedelta(days=1), REVOKED),
    ],
)
def test_effective_state(status: GrantStatus, now: datetime, expected: GrantState) -> None:
    """valid_until 那一刻起就是 expired（與平台 key 的到期規則相同）。"""
    assert effective_state(status, valid_until=NOW, now=now) is expected


def test_grant_reports_its_state_at_a_given_time() -> None:
    grant = _grant(_target(), valid_until=NOW + timedelta(hours=1))

    assert grant.state_at(NOW) is APPROVED
    assert grant.state_at(NOW + timedelta(hours=1)) is EXPIRED


# --- 轉換 -----------------------------------------------------------------------------------


ALLOWED_TRANSITIONS = [
    (APPROVE, PENDING, GrantStatus.APPROVED),
    (REVOKE, PENDING, GrantStatus.REVOKED),
    (REVOKE, APPROVED, GrantStatus.REVOKED),
    # 重複撤銷：不需要改變（回 200，不重記 audit）。
    (REVOKE, REVOKED, None),
]
REJECTED_TRANSITIONS = [
    (APPROVE, APPROVED),  # 重複核准是錯誤：核准是放行方向，必須明確
    (APPROVE, REVOKED),
    (APPROVE, EXPIRED),  # 過期的申請要重新提出
    (REVOKE, EXPIRED),
]


@pytest.mark.parametrize(("action", "state", "expected"), ALLOWED_TRANSITIONS)
def test_allowed_transitions(
    action: GrantAction, state: GrantState, expected: GrantStatus | None
) -> None:
    assert plan_transition(action, state) == expected


@pytest.mark.parametrize(("action", "state"), REJECTED_TRANSITIONS)
def test_other_transitions_are_rejected(action: GrantAction, state: GrantState) -> None:
    with pytest.raises(InvalidTransitionError) as caught:
        plan_transition(action, state)

    assert (caught.value.action, caught.value.state) == (action, state)


def test_transition_tables_cover_every_combination() -> None:
    """新增狀態或動作時，必須在上面兩張表中明確決定它的轉換。"""
    decided = [(action, state) for action, state, _ in ALLOWED_TRANSITIONS]
    decided += REJECTED_TRANSITIONS

    assert sorted(decided) == sorted(
        (action, state) for action in GrantAction for state in GrantState
    )


# --- grant 本身的一致性 ---------------------------------------------------------------------


def test_status_and_decision_fields_must_agree() -> None:
    target = _target()
    approved = _grant(target)

    with pytest.raises(ValueError, match="pending"):
        _replace(approved, status=GrantStatus.PENDING)
    with pytest.raises(ValueError, match="approved"):
        _replace(approved, approved_at=None, approved_by_key_id=None, approval_note=None)
    with pytest.raises(ValueError, match="revoked"):
        _replace(approved, status=GrantStatus.REVOKED)
    with pytest.raises(ValueError, match="成對"):
        _replace(approved, approval_note=None)


def _replace(grant: ScopeGrant, **changes: Any) -> ScopeGrant:
    """dataclasses.replace 會重新執行 __post_init__ 的一致性檢查。"""
    return replace(grant, **changes)


def test_revoked_grant_may_or_may_not_have_been_approved() -> None:
    target = _target()
    revoked = _grant(target, status=GrantStatus.REVOKED)
    actor: UUID = revoked.requested_by_key_id

    assert revoked.approved_at is None
    approved_then_revoked = _replace(
        revoked, approved_by_key_id=actor, approved_at=NOW - timedelta(days=1), approval_note="ok"
    )
    assert approved_then_revoked.state_at(NOW) is REVOKED


# --- 掃描 gate ------------------------------------------------------------------------------


def test_approved_grant_within_its_window_is_usable() -> None:
    target = _target()

    check_usable(_grant(target), target=target, lab=LAB, now=NOW)


@pytest.mark.parametrize(
    ("status", "valid_from", "valid_until", "reason"),
    [
        (GrantStatus.PENDING, NOW - TICK, NOW + TICK, UnusableReason.NOT_APPROVED),
        (GrantStatus.REVOKED, NOW - TICK, NOW + TICK, UnusableReason.REVOKED),
        (GrantStatus.APPROVED, NOW - timedelta(days=1), NOW, UnusableReason.EXPIRED),
        (GrantStatus.PENDING, NOW - timedelta(days=1), NOW, UnusableReason.EXPIRED),
        (GrantStatus.APPROVED, NOW + TICK, NOW + timedelta(days=1), UnusableReason.NOT_YET_VALID),
    ],
)
def test_grant_must_be_approved_and_currently_valid(
    status: GrantStatus,
    valid_from: datetime,
    valid_until: datetime,
    reason: UnusableReason,
) -> None:
    target = _target()
    grant = _grant(target, status=status, valid_from=valid_from, valid_until=valid_until)

    with pytest.raises(GrantUnusableError) as caught:
        check_usable(grant, target=target, lab=LAB, now=NOW)

    assert caught.value.reason is reason


def test_window_boundaries() -> None:
    """valid_from 那一刻起可以使用；valid_until 那一刻起不行。"""
    target = _target()
    grant = _grant(target, valid_from=NOW, valid_until=NOW + timedelta(hours=1))

    check_usable(grant, target=target, lab=LAB, now=NOW)
    check_usable(grant, target=target, lab=LAB, now=NOW + timedelta(hours=1) - TICK)
    with pytest.raises(GrantUnusableError):
        check_usable(grant, target=target, lab=LAB, now=NOW + timedelta(hours=1))


def test_disabled_target_cannot_be_scanned() -> None:
    enabled = _target()

    with pytest.raises(GrantUnusableError) as caught:
        check_usable(_grant(enabled), target=replace(enabled, enabled=False), lab=LAB, now=NOW)

    assert caught.value.reason is UnusableReason.TARGET_DISABLED


def test_grant_of_another_target_cannot_be_used() -> None:
    with pytest.raises(GrantUnusableError) as caught:
        check_usable(_grant(_target()), target=_target(), lab=LAB, now=NOW)

    assert caught.value.reason is UnusableReason.WRONG_TARGET


def test_target_origin_must_still_be_in_the_grant() -> None:
    """API 不能改 origin；若 target 的 origin 被直接改掉（只可能改 DB），grant 不能再用。"""
    target = _target()
    grant = _grant(target)
    moved = replace(target, origin=parse_origin("http://juice-shop:3000"))

    with pytest.raises(GrantUnusableError) as caught:
        check_usable(grant, target=moved, lab=LAB, now=NOW)

    assert caught.value.reason is UnusableReason.ORIGIN_NOT_GRANTED


def test_every_unusable_reason_has_an_api_error() -> None:
    assert set(UNUSABLE_ERRORS) == set(UnusableReason)


def test_ips_are_checked_against_the_current_lab_network() -> None:
    """核准之後 LAB_CIDR 縮小了：範圍外的 grant 不能再用。"""
    target = _target()
    grant = _grant(target, ip="10.89.7.200")

    check_usable(grant, target=target, lab=LAB, now=NOW)
    with pytest.raises(OutsideLabError):
        check_usable(grant, target=target, lab=LabNetwork(IPv4Network("10.89.7.0/25")), now=NOW)
