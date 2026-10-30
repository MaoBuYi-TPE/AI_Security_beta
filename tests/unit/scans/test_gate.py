"""runner 重新判斷 gate 的對照表（docs/DECISIONS.md §10.6、§17.5）：prepare 與心跳共用。

純函式：給 DB 讀到的 target、grant 與建立者的 key，回傳停止的錯誤碼（None 是可以繼續）。
"""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Network
from uuid import uuid4

import pytest

from secscan.api_keys.domain import ApiKey, Role
from secscan.grants.domain.lifecycle import GrantStatus, ScopeGrant
from secscan.scans.domain.gate import creator_error, gate_error
from secscan.scans.domain.lifecycle import RunErrorCode
from secscan.targets.domain import LabNetwork, Target, parse_origin
from tests.unit.grants.test_lifecycle import LAB, NOW, ORIGIN, _grant, _target

ELSEWHERE = LabNetwork(IPv4Network("10.99.0.0/24"))


def _gate(
    target: Target | None,
    grant: ScopeGrant | None,
    *,
    lab: LabNetwork = LAB,
    now: datetime = NOW,
) -> RunErrorCode | None:
    return gate_error(target=target, grant=grant, origin=ORIGIN, lab=lab, now=now)


def test_a_valid_snapshot_passes() -> None:
    target = _target()

    assert _gate(target, _grant(target)) is None


def test_missing_rows_or_a_moved_origin_are_a_mismatch() -> None:
    target = _target()
    grant = _grant(target)
    moved = replace(target, origin=parse_origin("http://elsewhere:5000"))

    assert _gate(None, grant) is RunErrorCode.SCOPE_MISMATCH
    assert _gate(target, None) is RunErrorCode.SCOPE_MISMATCH
    assert _gate(moved, grant) is RunErrorCode.SCOPE_MISMATCH
    assert _gate(_target(), grant) is RunErrorCode.SCOPE_MISMATCH  # 別的 target 的 grant


@pytest.mark.parametrize(
    ("status", "valid_from", "valid_until", "error_code"),
    [
        (GrantStatus.REVOKED, NOW - timedelta(days=1), NOW + timedelta(days=1), "SCOPE_REVOKED"),
        (GrantStatus.APPROVED, NOW - timedelta(days=1), NOW, "SCOPE_EXPIRED"),
        (
            GrantStatus.PENDING,
            NOW - timedelta(days=1),
            NOW + timedelta(days=1),
            "SCOPE_NOT_APPROVED",
        ),
        (
            GrantStatus.APPROVED,
            NOW + timedelta(hours=1),
            NOW + timedelta(days=1),
            "SCOPE_NOT_YET_VALID",
        ),
    ],
)
def test_the_grant_state_maps_to_an_error_code(
    status: GrantStatus, valid_from: datetime, valid_until: datetime, error_code: str
) -> None:
    target = _target()
    grant = _grant(target, status=status, valid_from=valid_from, valid_until=valid_until)

    assert _gate(target, grant) == RunErrorCode(error_code)


def test_a_disabled_target_stops_the_run() -> None:
    target = _target(enabled=False)

    assert _gate(target, _grant(target)) is RunErrorCode.TARGET_DISABLED


def test_ips_outside_the_current_lab_stop_the_run() -> None:
    target = _target()

    assert _gate(target, _grant(target), lab=ELSEWHERE) is RunErrorCode.SCOPE_OUTSIDE_LAB


def _key(*, revoked: bool = False, expired: bool = False) -> ApiKey:
    created = datetime(2026, 10, 1, tzinfo=UTC)
    return ApiKey(
        id=uuid4(),
        project_id=uuid4(),
        role=Role.OPERATOR,
        name="operator",
        prefix="abcdef012345",
        key_hash=b"\0" * 32,
        created_at=created,
        expires_at=created + timedelta(days=1) if expired else None,
        revoked_at=created + timedelta(hours=1) if revoked else None,
    )


def test_only_a_revoked_creator_key_stops_the_run() -> None:
    """到期不算：到期是例行的，不代表 key 外洩（§13.5）。"""
    assert creator_error(_key()) is None
    assert creator_error(_key(expired=True)) is None
    assert creator_error(_key(revoked=True)) is RunErrorCode.CREATOR_KEY_REVOKED
    assert creator_error(None) is RunErrorCode.CREATOR_KEY_REVOKED
