"""平台 key 的權限規則與期限規則（docs/DECISIONS.md §9.1、§9.2）；純函式，整張規則表都測。"""

from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest

from secscan.api_keys.domain import (
    DEFAULT_KEY_LIFETIME,
    MAX_KEY_LIFETIME,
    AccessDecision,
    AllProjects,
    ApiKey,
    ApiKeyRejectedError,
    IssuedApiKey,
    OneProject,
    Permission,
    Principal,
    RejectionReason,
    Role,
    decide,
    resolve_expiry,
)

OWN = UUID("00000000-0000-4000-8000-00000000000a")
OTHER = UUID("00000000-0000-4000-8000-00000000000b")
NOW = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)

ADMIN, OPERATOR, VIEWER = Role.PLATFORM_ADMIN, Role.OPERATOR, Role.VIEWER
MANAGE, READ, WRITE = Permission.PLATFORM_MANAGE, Permission.PROJECT_READ, Permission.PROJECT_WRITE
ALLOWED, NOT_FOUND, FORBIDDEN = (
    AccessDecision.ALLOWED,
    AccessDecision.NOT_FOUND,
    AccessDecision.FORBIDDEN,
)


def _principal(role: Role) -> Principal:
    return Principal(key_id=uuid4(), role=role, project_id=None if role is ADMIN else OWN)


@pytest.mark.parametrize(
    ("role", "permission", "project_id", "expected"),
    [
        # platform_admin：全部允許（project 不存在時由 service 回 404）。
        (ADMIN, MANAGE, None, ALLOWED),
        (ADMIN, MANAGE, OWN, ALLOWED),
        (ADMIN, MANAGE, OTHER, ALLOWED),
        (ADMIN, READ, OTHER, ALLOWED),
        (ADMIN, WRITE, OTHER, ALLOWED),
        # operator：自己的 project 可讀寫；管理操作 403；其他 project 一律 404。
        (OPERATOR, MANAGE, None, FORBIDDEN),
        (OPERATOR, MANAGE, OWN, FORBIDDEN),
        (OPERATOR, MANAGE, OTHER, NOT_FOUND),
        (OPERATOR, READ, OWN, ALLOWED),
        (OPERATOR, READ, OTHER, NOT_FOUND),
        (OPERATOR, WRITE, OWN, ALLOWED),
        (OPERATOR, WRITE, OTHER, NOT_FOUND),
        # viewer：自己的 project 只能讀；寫與管理 403；其他 project 一律 404。
        (VIEWER, MANAGE, None, FORBIDDEN),
        (VIEWER, MANAGE, OWN, FORBIDDEN),
        (VIEWER, MANAGE, OTHER, NOT_FOUND),
        (VIEWER, READ, OWN, ALLOWED),
        (VIEWER, READ, OTHER, NOT_FOUND),
        (VIEWER, WRITE, OWN, FORBIDDEN),
        (VIEWER, WRITE, OTHER, NOT_FOUND),
    ],
    ids=lambda value: getattr(value, "value", str(value)),
)
def test_access_matrix(
    role: Role, permission: Permission, project_id: UUID | None, expected: AccessDecision
) -> None:
    assert decide(_principal(role), permission, project_id) is expected


@pytest.mark.parametrize("role", list(Role))
@pytest.mark.parametrize("permission", [READ, WRITE])
def test_project_permissions_require_a_project(role: Role, permission: Permission) -> None:
    """讀寫一定是針對某個 project；沒有 project 是呼叫端的程式錯誤，不能默默放行。"""
    with pytest.raises(ValueError, match="project_id"):
        decide(_principal(role), permission, None)


def test_principal_follows_the_role_scope_rules() -> None:
    with pytest.raises(ValueError, match="platform_admin"):
        Principal(key_id=uuid4(), role=ADMIN, project_id=OWN)
    with pytest.raises(ValueError, match="viewer"):
        Principal(key_id=uuid4(), role=VIEWER, project_id=None)


def test_project_scope_is_all_projects_only_for_platform_admin() -> None:
    assert _principal(ADMIN).project_scope == AllProjects()
    assert _principal(OPERATOR).project_scope == OneProject(OWN)
    assert _principal(VIEWER).project_scope == OneProject(OWN)


def test_one_project_scope_refuses_a_missing_project() -> None:
    """不用 None 代表「全部」：漏傳的 project 不會變成看得到所有 project（fail closed）。"""
    with pytest.raises(TypeError, match="project_id"):
        OneProject(None)  # type: ignore[arg-type]


def test_principal_from_stored_key() -> None:
    stored = ApiKey(
        id=uuid4(),
        project_id=OWN,
        role=VIEWER,
        name="ci",
        prefix="0123456789abcdef",
        key_hash=bytes(32),
        created_at=NOW,
        expires_at=None,
        revoked_at=None,
    )

    principal = Principal.of(stored)

    assert (principal.key_id, principal.role, principal.project_id) == (stored.id, VIEWER, OWN)


# --- 期限 -----------------------------------------------------------------------------------


def test_expiry_defaults_to_the_default_lifetime() -> None:
    assert resolve_expiry(None, now=NOW) == NOW + DEFAULT_KEY_LIFETIME


def test_expiry_accepts_any_future_time_up_to_the_maximum() -> None:
    assert resolve_expiry(NOW + MAX_KEY_LIFETIME, now=NOW) == NOW + MAX_KEY_LIFETIME


def test_expiry_is_normalized_to_utc() -> None:
    """回應與 audit 的時間一律是 UTC（CLAUDE.md §11），不保留 client 送來的時區。"""
    taipei = timezone(timedelta(hours=8))
    tomorrow_in_taipei = (NOW + timedelta(days=1)).astimezone(taipei)

    resolved = resolve_expiry(tomorrow_in_taipei, now=NOW)

    assert resolved == NOW + timedelta(days=1)
    assert resolved.tzinfo is UTC


@pytest.mark.parametrize(
    "expires_at",
    [
        NOW,
        NOW - timedelta(seconds=1),
        NOW + MAX_KEY_LIFETIME + timedelta(seconds=1),
        datetime(2027, 1, 1),
    ],
    ids=["now", "past", "beyond-max", "naive"],
)
def test_expiry_rejects_past_too_far_or_naive_times(expires_at: datetime) -> None:
    with pytest.raises(ValueError, match="expires_at"):
        resolve_expiry(expires_at, now=NOW)


def test_lifetimes_match_the_documented_policy() -> None:
    """docs/DECISIONS.md §9.1：預設 90 天、最多 365 天。"""
    assert timedelta(days=90) == DEFAULT_KEY_LIFETIME
    assert timedelta(days=365) == MAX_KEY_LIFETIME


# --- 其他 -----------------------------------------------------------------------------------


def test_rejection_carries_reason_and_optional_key() -> None:
    key_id = uuid4()

    assert ApiKeyRejectedError(RejectionReason.MALFORMED).key_id is None
    rejected = ApiKeyRejectedError(RejectionReason.EXPIRED, key_id)
    assert (rejected.reason, rejected.key_id) == (RejectionReason.EXPIRED, key_id)


def test_issued_key_value_is_hidden_from_repr() -> None:
    stored = ApiKey(
        id=uuid4(),
        project_id=None,
        role=ADMIN,
        name="admin",
        prefix="0123456789abcdef",
        key_hash=bytes(32),
        created_at=NOW,
        expires_at=NOW + DEFAULT_KEY_LIFETIME,
        revoked_at=None,
    )
    value = f"secscan_0123456789abcdef_{'d' * 64}"

    issued = IssuedApiKey(key=stored, value=value)

    assert value not in repr(issued)
