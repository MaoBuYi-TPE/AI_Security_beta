"""domain model 的不變式與不可變性（純 Python，不連 DB）。

DB 也有對應的 CHECK，但 domain 先擋：錯誤訊息清楚，也不會讓過長字串變成 DB 的 DataError。
"""

import dataclasses
from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid4

import pytest

from secscan.api_keys.domain import (
    API_KEY_NAME_MAX_LENGTH,
    API_KEY_PREFIX_MAX_LENGTH,
    KEY_HASH_BYTES,
    ApiKey,
    NewApiKey,
    Role,
)
from secscan.audit.domain import (
    AUDIT_CHANGES_MAX_BYTES,
    AUDIT_LABEL_MAX_LENGTH,
    REQUEST_ID_MAX_LENGTH,
    AuditEvent,
    NewAuditEvent,
)
from secscan.core.json_types import JsonObject
from secscan.core.text import require_text
from secscan.projects.domain import PROJECT_NAME_MAX_LENGTH, NewProject, Project
from secscan.security.redaction import REDACTED, redact_object

NOW = datetime(2026, 10, 18, tzinfo=UTC)
HASH = bytes(range(KEY_HASH_BYTES))
# 空字串、半形與全形空白、tab：Python 的 strip 都會清掉，DB 的 btrim 只清半形空白。
BLANKS = ["", "   ", "　", "\t\n"]


def _admin_key(**overrides: object) -> NewApiKey:
    fields: dict[str, object] = {
        "role": Role.PLATFORM_ADMIN,
        "name": "admin",
        "prefix": "p1",
        "key_hash": HASH,
        "expires_at": NOW + timedelta(days=90),
    }
    fields.update(overrides)
    return NewApiKey(**fields)  # type: ignore[arg-type]


def test_new_key_requires_an_expiry() -> None:
    """所有 key 都會過期（docs/DECISIONS.md §9.1）：沒有到期時間的 key 建立不出來。"""
    fields: dict[str, object] = {
        "role": Role.PLATFORM_ADMIN,
        "name": "admin",
        "prefix": "p1",
        "key_hash": HASH,
    }

    with pytest.raises(TypeError, match="expires_at"):
        NewApiKey(**fields)  # type: ignore[arg-type]


# --- 共用文字規則 ----------------------------------------------------------------------------


@pytest.mark.parametrize("value", BLANKS)
def test_require_text_rejects_blank(value: str) -> None:
    with pytest.raises(ValueError, match="name 不可為空白"):
        require_text(value, field="name", max_length=10)


def test_require_text_rejects_too_long_and_nul() -> None:
    with pytest.raises(ValueError, match="不可超過 3 個字元"):
        require_text("abcd", field="name", max_length=3)
    with pytest.raises(ValueError, match="NUL"):
        require_text("a\x00b", field="name", max_length=10)


def test_require_text_accepts_cjk_up_to_the_limit() -> None:
    require_text("教" * 3, field="name", max_length=3)


# --- projects -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name", [*BLANKS, "x" * (PROJECT_NAME_MAX_LENGTH + 1), "lab\x00"], ids=repr
)
def test_new_project_validates_name(name: str) -> None:
    with pytest.raises(ValueError, match="name"):
        NewProject(name=name)


def test_new_project_accepts_valid_name() -> None:
    assert NewProject(name="API 教學靶場").name == "API 教學靶場"


# --- api_keys -------------------------------------------------------------------------------


def test_platform_admin_key_must_not_belong_to_a_project() -> None:
    with pytest.raises(ValueError, match="platform_admin"):
        _admin_key(project_id=uuid4())


@pytest.mark.parametrize("role", [Role.OPERATOR, Role.VIEWER])
def test_project_roles_require_a_project(role: Role) -> None:
    with pytest.raises(ValueError, match=role.value):
        _admin_key(role=role)


@pytest.mark.parametrize("length", [0, KEY_HASH_BYTES - 1, KEY_HASH_BYTES + 1])
def test_key_hash_must_have_fixed_length(length: int) -> None:
    with pytest.raises(ValueError, match="key_hash"):
        _admin_key(key_hash=b"x" * length)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        *[("name", blank) for blank in BLANKS],
        ("name", "x" * (API_KEY_NAME_MAX_LENGTH + 1)),
        ("name", "ad\x00min"),
        *[("prefix", blank) for blank in BLANKS],
        ("prefix", "p" * (API_KEY_PREFIX_MAX_LENGTH + 1)),
    ],
    ids=repr,
)
def test_new_key_validates_text_fields(field: str, value: str) -> None:
    with pytest.raises(ValueError, match=field):
        _admin_key(**{field: value})


def test_new_key_expiry_must_be_timezone_aware() -> None:
    """沒有時區的時間（例如台北機器上的 datetime.now()）會被當成 UTC 存，到期時間差 8 小時。"""
    with pytest.raises(ValueError, match="expires_at"):
        _admin_key(expires_at=datetime(2027, 6, 30))


def test_valid_new_keys_are_accepted() -> None:
    taipei = timezone(timedelta(hours=8))
    admin = _admin_key(expires_at=datetime(2027, 6, 30, tzinfo=taipei))
    viewer = _admin_key(role=Role.VIEWER, prefix="p2", project_id=uuid4())

    assert admin.project_id is None
    assert admin.expires_at == datetime(2027, 6, 29, 16, tzinfo=UTC)
    assert viewer.role is Role.VIEWER


def test_key_hash_is_hidden_from_repr() -> None:
    stored = ApiKey(
        id=uuid4(),
        project_id=None,
        role=Role.PLATFORM_ADMIN,
        name="admin",
        prefix="p1",
        key_hash=HASH,
        created_at=NOW,
        expires_at=None,
        revoked_at=None,
    )

    assert repr(HASH) not in repr(_admin_key())
    assert repr(HASH) not in repr(stored)


# --- audit ----------------------------------------------------------------------------------


def test_new_audit_event_defaults_to_global_system_action() -> None:
    event = NewAuditEvent(action="project.create", object_type="project")

    assert (event.actor_key_id, event.project_id, event.object_id) == (None, None, None)
    assert dict(event.redacted_changes) == {}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        *[("action", blank) for blank in BLANKS],
        ("action", "a" * (AUDIT_LABEL_MAX_LENGTH + 1)),
        ("action", "project\x00.create"),
        *[("object_type", blank) for blank in BLANKS],
        ("object_type", "o" * (AUDIT_LABEL_MAX_LENGTH + 1)),
        ("request_id", "r" * (REQUEST_ID_MAX_LENGTH + 1)),
        ("request_id", ""),
    ],
    ids=repr,
)
def test_new_audit_event_validates_text_fields(field: str, value: str) -> None:
    fields: dict[str, object] = {"action": "project.create", "object_type": "project"}
    fields[field] = value

    with pytest.raises(ValueError, match=field):
        NewAuditEvent(**fields)  # type: ignore[arg-type]


def test_new_audit_event_requires_changes_to_be_redacted_first() -> None:
    """欄位名稱叫 redacted_changes，就必須真的遮罩過；沒遮罩的內容在送進 DB 前就拒絕。"""
    with pytest.raises(ValueError, match="redacted_changes"):
        NewAuditEvent(
            action="api_key.create", object_type="api_key", redacted_changes={"token": "abc"}
        )


def test_new_audit_event_accepts_redacted_changes() -> None:
    event = NewAuditEvent(
        action="api_key.create",
        object_type="api_key",
        redacted_changes=redact_object({"token": "abc", "name": "ci"}),
    )

    assert event.redacted_changes == {"token": REDACTED, "name": "ci"}


@pytest.mark.parametrize(
    "changes",
    [
        # 每個值都在遮罩的長度上限內，但合計超過 AUDIT_CHANGES_MAX_BYTES。
        redact_object({f"field{n}": "x" * 250 for n in range(AUDIT_CHANGES_MAX_BYTES // 250 + 1)}),
        # NaN 不是合法的 JSON，JSONB 也存不進去。
        {"ratio": float("nan")},
        # tuple 不是 JSON 型別；遮罩會把它變成 list，與原本不同，所以視為沒遮罩而拒絕。
        {"headers": ("Authorization", "Bearer abc")},
    ],
    ids=["too-large", "not-json", "tuple"],
)
def test_new_audit_event_rejects_oversized_or_non_json_changes(changes: JsonObject) -> None:
    with pytest.raises(ValueError, match="redacted_changes"):
        NewAuditEvent(action="api_key.create", object_type="api_key", redacted_changes=changes)


def test_audit_changes_limit_leaves_room_for_ordinary_events() -> None:
    """名稱上限 100 個中文字（每字 3 bytes）的 key 事件，必須遠低於上限。"""
    changes = redact_object({"name": "教" * 100, "role": "viewer", "expires_at": "2027-01-17"})

    event = NewAuditEvent(action="api_key.create", object_type="api_key", redacted_changes=changes)

    assert event.redacted_changes == changes


# --- 不可變 ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "instance",
    [
        Project(id=uuid4(), name="lab", created_at=NOW),
        NewProject(name="lab"),
        _admin_key(),
        NewAuditEvent(action="project.create", object_type="project"),
        AuditEvent(
            id=uuid4(),
            created_at=NOW,
            action="project.create",
            object_type="project",
            actor_key_id=None,
            project_id=None,
            object_id=None,
            request_id=None,
            redacted_changes={},
        ),
    ],
    ids=lambda instance: type(instance).__name__,
)
def test_domain_models_are_immutable(instance: object) -> None:
    field_name = dataclasses.fields(instance)[0].name  # type: ignore[arg-type]

    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(instance, field_name, "changed")
