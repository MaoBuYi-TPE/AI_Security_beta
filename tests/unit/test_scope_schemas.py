"""target 與 grant 的請求、回應 schema（docs/API_CONTRACT.md §3、§4、§14）。

請求：拒絕多餘欄位、不接受字串冒充數字或布林、時間必須帶時區、清單與每個項目都有上限
（在讀進 domain 之前就限制處理量）。回應：grant 的 status 是讀取當下推導出的狀態。
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError

from secscan.grants.domain.lifecycle import GrantStatus, ScopeGrant
from secscan.grants.domain.scope import (
    MAX_ALLOWED_IPS,
    MAX_ALLOWED_ORIGINS,
    MAX_ALLOWED_PATHS,
    MAX_EXCLUDED_PATHS,
    PATH_MAX_LENGTH,
    ValidityWindow,
    build_scope,
    resolve_budget,
)
from secscan.grants.schemas import GrantDecision, GrantRevocation, ScopeGrantCreate, ScopeGrantOut
from secscan.targets.domain import (
    ORIGIN_MAX_LENGTH,
    Target,
    TargetEnvironment,
    TargetKind,
    TargetUpdate,
    parse_origin,
)
from secscan.targets.schemas import TargetCreate, TargetOut, TargetPatch

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)
BAD_TEXT = ["", "   ", "\t\n", "x\x00"]


def _target_body(**overrides: object) -> dict[str, object]:
    return {"name": "API 教學靶場", "kind": "api", "base_url": "http://api-lab:8000", **overrides}


def _grant_body(**overrides: object) -> dict[str, Any]:
    return {
        "allowed_origins": ["http://api-lab:8000"],
        "allowed_ips": ["10.89.7.20"],
        "allowed_paths": ["/api/search", "/api/items/{id}", "/api/me"],
        "allowed_methods": ["GET", "HEAD", "OPTIONS"],
        "excluded_paths": ["/api/logout", "/api/admin", "/api/delete"],
        "budget": {"requests_per_second": 2, "max_requests": 5000, "max_duration_seconds": 1500},
        "authorization_reference": "LAB-ASSET-RECORD-001",
        "valid_from": "2026-10-19T00:00:00Z",
        "valid_until": "2026-10-26T00:00:00Z",
        **overrides,
    }


# --- target ---------------------------------------------------------------------------------


def test_target_create_accepts_the_contract_example() -> None:
    body = TargetCreate.model_validate(_target_body(environment="lab"))

    assert (body.kind, body.environment) == (TargetKind.API, TargetEnvironment.LAB)
    assert TargetCreate.model_validate(_target_body()).environment is TargetEnvironment.LAB


@pytest.mark.parametrize(
    "overrides",
    [
        *({"name": name} for name in BAD_TEXT),
        {"name": "x" * 101},
        {"kind": "graphql"},
        {"kind": "API"},
        {"environment": "prod"},
        {"base_url": 8000},
        {"base_url": "http://" + "a" * ORIGIN_MAX_LENGTH},
        {"canonical_origin": "http://api-lab:8000"},
        {"project_id": str(uuid4())},
        {"enabled": True},
    ],
    ids=repr,
)
def test_target_create_rejects_invalid_or_extra_fields(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        TargetCreate.model_validate(_target_body(**overrides))


def test_target_patch_changes_only_name_and_enabled() -> None:
    assert TargetPatch.model_validate({"enabled": False}).to_update() == TargetUpdate(enabled=False)
    assert TargetPatch.model_validate({"name": "新名稱"}).to_update() == TargetUpdate(name="新名稱")


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"name": None},
        {"enabled": None},
        {"enabled": "false"},
        {"enabled": 0},
        {"name": "   "},
        {"base_url": "http://other:8000"},
        {"kind": "web"},
    ],
    ids=repr,
)
def test_target_patch_rejects_empty_null_or_other_fields(payload: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        TargetPatch.model_validate(payload)


def test_target_response() -> None:
    target = Target(
        id=uuid4(),
        project_id=uuid4(),
        name="lab",
        kind=TargetKind.WEB,
        origin=parse_origin("http://juice-shop:3000"),
        environment=TargetEnvironment.LAB,
        enabled=True,
        created_at=NOW,
    )

    body = TargetOut.of(target).model_dump(mode="json")

    assert body == {
        "id": str(target.id),
        "project_id": str(target.project_id),
        "name": "lab",
        "kind": "web",
        "canonical_origin": "http://juice-shop:3000",
        "environment": "lab",
        "enabled": True,
        "created_at": "2026-10-19T12:00:00Z",
    }


# --- grant ----------------------------------------------------------------------------------


def test_grant_create_accepts_the_contract_example() -> None:
    request = ScopeGrantCreate.model_validate(_grant_body()).to_request()

    assert request.origins == ("http://api-lab:8000",)
    assert request.paths == ("/api/search", "/api/items/{id}", "/api/me")
    assert request.methods == ("GET", "HEAD", "OPTIONS")
    assert (request.requests_per_second, request.max_requests, request.max_duration_seconds) == (
        2,
        5000,
        1500,
    )
    assert request.valid_from == datetime(2026, 10, 19, tzinfo=UTC)
    assert request.allow_all_paths is False


def test_grant_create_defaults() -> None:
    body = _grant_body(allowed_paths=[], allow_all_paths=True)
    for optional in ("budget", "excluded_paths", "valid_from"):
        body.pop(optional)

    request = ScopeGrantCreate.model_validate(body).to_request()

    assert request.allow_all_paths is True
    assert (request.paths, request.excluded_paths, request.valid_from) == ((), (), None)
    assert (request.requests_per_second, request.max_requests) == (None, None)


@pytest.mark.parametrize(
    "overrides",
    [
        {"valid_until": "2026-10-26T00:00:00"},
        {"valid_from": "2026-10-19T00:00:00"},
        {"valid_until": None},
        {"budget": {"requests_per_second": "2"}},
        {"budget": {"max_requests": 5000.0}},
        {"budget": {"max_requests": True}},
        {"budget": {"burst": 1}},
        {"allow_all_paths": "true"},
        {"allowed_ips": [167772160]},
        {"allowed_methods": [1]},
        {"allowed_origins": []},
        {"allowed_origins": [f"http://lab-{n}" for n in range(MAX_ALLOWED_ORIGINS + 1)]},
        {"allowed_origins": ["http://" + "a" * ORIGIN_MAX_LENGTH]},
        {"allowed_ips": []},
        {"allowed_ips": [f"10.89.7.{n + 1}" for n in range(MAX_ALLOWED_IPS + 1)]},
        {"allowed_ips": ["10.89.7.20" + " " * 10]},
        {"allowed_paths": [f"/p{n}" for n in range(MAX_ALLOWED_PATHS + 1)]},
        {"allowed_paths": ["/" + "a" * PATH_MAX_LENGTH]},
        {"excluded_paths": [f"/x{n}" for n in range(MAX_EXCLUDED_PATHS + 1)]},
        {"allowed_methods": []},
        {"allowed_methods": ["GET"] * 8},
        *({"authorization_reference": text} for text in BAD_TEXT),
        {"status": "approved"},
        {"version": 1},
        {"project_id": str(uuid4())},
        {"approved_by_key_id": str(uuid4())},
    ],
    ids=repr,
)
def test_grant_create_rejects_invalid_or_extra_fields(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ScopeGrantCreate.model_validate(_grant_body(**overrides))


@pytest.mark.parametrize("schema", [GrantDecision, GrantRevocation])
@pytest.mark.parametrize("text", [*BAD_TEXT, "x" * 501])
def test_decisions_need_a_note(schema: type[GrantDecision | GrantRevocation], text: str) -> None:
    field = "note" if schema is GrantDecision else "reason"

    assert getattr(schema.model_validate({field: "已核對"}), field) == "已核對"
    with pytest.raises(ValidationError):
        schema.model_validate({field: text})
    with pytest.raises(ValidationError):
        schema.model_validate({field: "ok", "status": "approved"})


def test_grant_response_shows_the_state_at_read_time() -> None:
    origin = parse_origin("http://api-lab:8000")
    grant = ScopeGrant(
        id=uuid4(),
        target_id=uuid4(),
        project_id=uuid4(),
        version=3,
        status=GrantStatus.PENDING,
        scope=build_scope(
            target_origin=origin,
            origins=[str(origin)],
            ips=["10.89.7.20"],
            paths=[],
            allow_all_paths=True,
            excluded_paths=["/logout"],
            methods=["GET"],
        ),
        budget=resolve_budget(),
        window=ValidityWindow(valid_from=NOW, valid_until=NOW + timedelta(days=1)),
        authorization_reference="LAB-1",
        requested_by_key_id=uuid4(),
        created_at=NOW,
    )

    current = ScopeGrantOut.of(grant, now=NOW).model_dump(mode="json")
    later = ScopeGrantOut.of(grant, now=NOW + timedelta(days=1)).model_dump(mode="json")

    assert (current["status"], later["status"]) == ("pending", "expired")
    assert current == {
        "id": str(grant.id),
        "target_id": str(grant.target_id),
        "project_id": str(grant.project_id),
        "version": 3,
        "status": "pending",
        "allowed_origins": ["http://api-lab:8000"],
        "allowed_ips": ["10.89.7.20"],
        "allowed_paths": [],
        "allow_all_paths": True,
        "excluded_paths": ["/logout"],
        "allowed_methods": ["GET"],
        "budget": {"requests_per_second": 2, "max_requests": 5000, "max_duration_seconds": 1500},
        "authorization_reference": "LAB-1",
        "valid_from": "2026-10-19T12:00:00Z",
        "valid_until": "2026-10-20T12:00:00Z",
        "requested_by_key_id": str(grant.requested_by_key_id),
        "created_at": "2026-10-19T12:00:00Z",
        "approved_by_key_id": None,
        "approved_at": None,
        "approval_note": None,
        "revoked_by_key_id": None,
        "revoked_at": None,
        "revocation_reason": None,
    }
