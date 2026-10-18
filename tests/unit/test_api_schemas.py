"""請求與回應 schema：輸入驗證重用 domain 的文字規則、拒絕多餘欄位；回應不含 key_hash。"""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import BaseModel, ValidationError

from secscan.api_keys.domain import (
    API_KEY_NAME_MAX_LENGTH,
    ApiKey,
    IssuedApiKey,
    Role,
)
from secscan.api_keys.schemas import ApiKeyCreate, IssuedApiKeyOut
from secscan.audit.domain import AuditEvent
from secscan.audit.schemas import AuditEventOut
from secscan.projects.domain import PROJECT_NAME_MAX_LENGTH, Project
from secscan.projects.schemas import ProjectCreate, ProjectOut
from secscan.security.redaction import REDACTED

NOW = datetime(2026, 10, 19, tzinfo=UTC)
BAD_NAMES = ["", "   ", "　", "\t\n", "lab\x00"]
KEY_VALUE = f"secscan_0123456789abcdef_{'e' * 64}"


def _valid_key_request(**overrides: object) -> dict[str, object]:
    return {"name": "ci", "role": "viewer", **overrides}


# --- 請求 -----------------------------------------------------------------------------------


@pytest.mark.parametrize("name", [*BAD_NAMES, "x" * (PROJECT_NAME_MAX_LENGTH + 1)], ids=repr)
def test_project_create_rejects_invalid_names(name: str) -> None:
    with pytest.raises(ValidationError):
        ProjectCreate.model_validate({"name": name})


def test_project_create_accepts_a_name_and_nothing_else() -> None:
    assert ProjectCreate.model_validate({"name": "API 教學靶場"}).name == "API 教學靶場"
    with pytest.raises(ValidationError):
        ProjectCreate.model_validate({"name": "lab", "id": str(uuid4())})


@pytest.mark.parametrize("role", ["operator", "viewer"])
def test_key_request_accepts_project_roles(role: str) -> None:
    request = ApiKeyCreate.model_validate(_valid_key_request(role=role))

    assert request.role is Role(role)
    assert request.expires_at is None


@pytest.mark.parametrize("role", ["platform_admin", "admin", "VIEWER", ""])
def test_key_request_rejects_other_roles(role: str) -> None:
    """platform_admin key 只能由本機 CLI 建立（docs/DECISIONS.md §9.1）。"""
    with pytest.raises(ValidationError):
        ApiKeyCreate.model_validate(_valid_key_request(role=role))


@pytest.mark.parametrize("name", [*BAD_NAMES, "x" * (API_KEY_NAME_MAX_LENGTH + 1)], ids=repr)
def test_key_request_rejects_invalid_names(name: str) -> None:
    with pytest.raises(ValidationError):
        ApiKeyCreate.model_validate(_valid_key_request(name=name))


def test_key_request_requires_timezone_aware_expiry() -> None:
    aware = ApiKeyCreate.model_validate(_valid_key_request(expires_at="2027-01-01T00:00:00Z"))

    assert aware.expires_at == datetime(2027, 1, 1, tzinfo=UTC)
    with pytest.raises(ValidationError):
        ApiKeyCreate.model_validate(_valid_key_request(expires_at="2027-01-01T00:00:00"))


@pytest.mark.parametrize("field", ["project_id", "key_hash", "prefix", "revoked_at"])
def test_key_request_rejects_unknown_fields(field: str) -> None:
    with pytest.raises(ValidationError):
        ApiKeyCreate.model_validate(_valid_key_request(**{field: "x"}))


# --- 回應 -----------------------------------------------------------------------------------


def test_issued_key_response_shows_the_key_once_but_never_its_hash() -> None:
    stored = ApiKey(
        id=uuid4(),
        project_id=uuid4(),
        role=Role.VIEWER,
        name="ci",
        prefix="0123456789abcdef",
        key_hash=b"\x01" * 32,
        created_at=NOW,
        expires_at=NOW,
        revoked_at=None,
    )

    body = IssuedApiKeyOut.of(IssuedApiKey(key=stored, value=KEY_VALUE)).model_dump(mode="json")

    assert body == {
        "id": str(stored.id),
        "project_id": str(stored.project_id),
        "role": "viewer",
        "name": "ci",
        "prefix": "0123456789abcdef",
        "created_at": "2026-10-19T00:00:00Z",
        "expires_at": "2026-10-19T00:00:00Z",
        "key": KEY_VALUE,
    }


def test_project_response() -> None:
    project = Project(id=uuid4(), name="lab", created_at=NOW)

    body = ProjectOut.of(project).model_dump(mode="json")

    assert body == {"id": str(project.id), "name": "lab", "created_at": "2026-10-19T00:00:00Z"}


def test_audit_event_response_masks_changes_again() -> None:
    """讀出時再遮罩一次：不是經由 audit service 寫入的資料列（例如直接以 SQL 寫入）也不外流。"""
    event = AuditEvent(
        id=uuid4(),
        created_at=NOW,
        action="api_key.create",
        object_type="api_key",
        actor_key_id=None,
        project_id=uuid4(),
        object_id=uuid4(),
        request_id="0" * 32,
        redacted_changes={"token": "leaked", "name": "ci"},
    )

    body = AuditEventOut.of(event).model_dump(mode="json")

    assert body["changes"] == {"token": REDACTED, "name": "ci"}
    assert body["action"] == "api_key.create"


@pytest.mark.parametrize("schema", [IssuedApiKeyOut, ProjectOut, AuditEventOut])
def test_response_schemas_have_no_hash_fields(schema: type[BaseModel]) -> None:
    assert not any("hash" in name for name in schema.model_fields)
