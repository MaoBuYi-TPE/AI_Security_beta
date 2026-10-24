"""ApiSpecService：上傳、查詢、inventory 與 grant 預覽（docs/DECISIONS.md §11）。

在交易內執行，結束時回滾。權限先於解析：沒有權限的呼叫者看不到解析的結果。
"""

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from secscan.api_keys.domain import Principal
from secscan.audit.domain import AuditEvent
from secscan.core.errors import ErrorCode
from secscan.core.pagination import PageRequest
from secscan.grants.domain.lifecycle import ScopeGrant
from secscan.grants.domain.matching import IneligibleReason
from secscan.grants.service import ScopeGrantService
from secscan.projects.service import ProjectService
from secscan.specs.domain.documents import SpecFormat
from secscan.specs.domain.model import ApiSpec, InventoryEntry, SpecOperation, SpecUpload
from secscan.specs.service import MAX_SPECS_PER_TARGET, ApiSpecService
from secscan.targets.domain import Target, TargetKind, TargetUpdate
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

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "openapi" / "vampi-openapi3.yml"
NOW = datetime.now(UTC)
ALL = PageRequest(limit=100)
REQUEST_ID = "s" * 32
TINY = json.dumps(
    {"openapi": "3.0.3", "info": {"title": "t", "version": "1"}, "paths": {"/a": {"get": {}}}}
).encode()
VAMPI_UPLOAD = SpecUpload(spec_format=SpecFormat.YAML, content=FIXTURE.read_bytes())


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


def _upload(
    session: Session, principal: Principal, target_id: UUID, upload: SpecUpload = VAMPI_UPLOAD
) -> ApiSpec:
    return ApiSpecService(session).upload(principal, target_id, upload, request_id=REQUEST_ID)


def _json(content: bytes) -> SpecUpload:
    return SpecUpload(spec_format=SpecFormat.JSON, content=content)


def _events(session: Session, team: Members) -> list[AuditEvent]:
    events = ProjectService(session).list_audit_events(team.admin, team.project_a, ALL).items
    return [event for event in events if event.action == "api_spec.create"]


def _spec_rows(session: Session) -> int:
    return int(session.execute(text("SELECT count(*) FROM api_specs")).scalar_one())


def _grant(session: Session, team: Members, target: Target, **scope: object) -> ScopeGrant:
    return ScopeGrantService(session, lab=LAB).request(
        team.operator_a, target.id, grant_request(NOW, **scope), now=NOW, request_id=None
    )


# --- 上傳 -----------------------------------------------------------------------------------


def test_operator_uploads_a_spec_and_it_is_audited(
    db_session: Session, team: Members, target: Target
) -> None:
    spec = _upload(db_session, team.operator_a, target.id)

    assert (spec.version, spec.operation_count, spec.server_url) == (
        1,
        14,
        "http://vampi-vuln:5000",
    )
    [event] = _events(db_session, team)
    assert event.object_id == spec.id
    assert event.actor_key_id == team.operator_a.key_id
    assert event.request_id == REQUEST_ID
    assert event.redacted_changes == {
        "version": 1,
        "target_id": str(target.id),
        "format": "yaml",
        "size_bytes": spec.source_size,
        "source_sha256": spec.source_sha256.hex(),
        "document_sha256": spec.document_sha256.hex(),
        "operation_count": 14,
        "base_path": "",
    }


def test_versions_are_consecutive_and_listed_newest_first(
    db_session: Session, team: Members, target: Target
) -> None:
    first = _upload(db_session, team.operator_a, target.id)
    second = _upload(db_session, team.admin, target.id, _json(TINY))
    service = ApiSpecService(db_session)

    listed = service.list_for_target(team.viewer_a, target.id, ALL)

    assert [spec.id for spec in listed.items] == [second.id, first.id]
    assert [spec.version for spec in listed.items] == [2, 1]
    assert service.get(team.viewer_a, first.id) == first


def test_disabled_targets_still_accept_specs(
    db_session: Session, team: Members, target: Target
) -> None:
    """上傳規格不會送出任何流量；停用只影響建立 scan。"""
    TargetService(db_session, lab=LAB).update(
        team.operator_a, target.id, TargetUpdate(enabled=False), request_id=None
    )

    assert _upload(db_session, team.operator_a, target.id).version == 1


@pytest.mark.parametrize(
    ("content", "status", "code"),
    [
        (b'{"openapi": ', 422, ErrorCode.INVALID_SPEC),
        (b'{"swagger": "2.0", "info": {}, "paths": {}}', 422, ErrorCode.UNSUPPORTED_SCHEMA),
        (
            b'{"openapi": "3.0.3", "info": {"title": "t", "version": "1"}, "paths": {},'
            b' "components": {"schemas": {"A": {"$ref": "http://evil.example/a.json"}}}}',
            422,
            ErrorCode.EXTERNAL_REF_FORBIDDEN,
        ),
        (b" " * (1024 * 1024 + 1), 413, ErrorCode.SPEC_TOO_LARGE),
    ],
    ids=["invalid", "unsupported", "external-ref", "too-large"],
)
def test_rejected_specs_leave_nothing_behind(
    db_session: Session, team: Members, target: Target, content: bytes, status: int, code: str
) -> None:
    error = app_error(lambda: _upload(db_session, team.operator_a, target.id, _json(content)))

    assert (error.status_code, error.code) == (status, code)
    assert error.message.endswith("。")
    assert "evil" not in error.message
    assert _spec_rows(db_session) == 0
    assert _events(db_session, team) == []


def test_permission_is_checked_before_the_content_is_parsed(
    db_session: Session, team: Members, target: Target
) -> None:
    broken = _json(b"not json")
    missing_target = app_error(lambda: _upload(db_session, team.operator_a, uuid4(), broken))

    viewer = app_error(lambda: _upload(db_session, team.viewer_a, target.id, broken))
    other_project = app_error(lambda: _upload(db_session, team.operator_b, target.id, broken))

    assert (viewer.status_code, viewer.code) == (403, ErrorCode.ROLE_NOT_ALLOWED)
    assert (other_project.status_code, other_project.code) == (404, ErrorCode.RESOURCE_NOT_FOUND)
    assert same_response(other_project, missing_target)
    assert _spec_rows(db_session) == 0


def test_spec_versions_per_target_are_capped(
    db_session: Session, team: Members, target: Target
) -> None:
    for _ in range(MAX_SPECS_PER_TARGET):
        _upload(db_session, team.operator_a, target.id, _json(TINY))

    error = app_error(lambda: _upload(db_session, team.operator_a, target.id, _json(TINY)))

    assert (error.status_code, error.code) == (409, ErrorCode.QUOTA_EXCEEDED)
    assert _spec_rows(db_session) == MAX_SPECS_PER_TARGET
    assert len(_events(db_session, team)) == MAX_SPECS_PER_TARGET
    other = _target(db_session, team, "http://juice-shop:3000")
    assert _upload(db_session, team.operator_a, other.id, _json(TINY)).version == 1


def test_target_vanishing_before_the_lock_looks_missing(
    db_session: Session, team: Members, target: Target, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(TargetRepository, "lock", lambda *_args, **_kwargs: None)

    error = app_error(lambda: _upload(db_session, team.operator_a, target.id))

    assert (error.status_code, error.code) == (404, ErrorCode.RESOURCE_NOT_FOUND)


# --- 查詢 -----------------------------------------------------------------------------------


def test_other_projects_specs_look_missing(
    db_session: Session, team: Members, target: Target
) -> None:
    spec = _upload(db_session, team.operator_a, target.id)
    service = ApiSpecService(db_session)
    missing = app_error(lambda: service.get(team.operator_b, uuid4()))

    errors = [
        app_error(lambda: service.get(team.operator_b, spec.id)),
        app_error(lambda: service.list_for_target(team.operator_b, target.id, ALL)),
        app_error(lambda: service.list_for_target(team.operator_b, uuid4(), ALL)),
        app_error(lambda: service.operations(team.operator_b, spec.id, ALL, grant_id=None)),
    ]

    assert all(same_response(error, missing) for error in errors)


def test_inventory_without_a_grant_has_no_verdict(
    db_session: Session, team: Members, target: Target
) -> None:
    spec = _upload(db_session, team.operator_a, target.id)

    page = ApiSpecService(db_session).operations(
        team.viewer_a, spec.id, PageRequest(page=1, limit=2), grant_id=None
    )

    assert page.total == 14
    assert page.items == (
        InventoryEntry(SpecOperation("GET", "/", "api_views.main.basic")),
        InventoryEntry(SpecOperation("GET", "/books/v1", "api_views.books.get_all_books")),
    )
    assert all(entry.eligible is None and entry.reason is None for entry in page.items)


def test_inventory_is_previewed_against_a_grant(
    db_session: Session, team: Members, target: Target
) -> None:
    spec = _upload(db_session, team.operator_a, target.id)
    grant = _grant(
        db_session,
        team,
        target,
        paths=("/users/v1", "/users/v1/{username}", "/books/v1/{book_title}"),
        excluded_paths=("/users/v1/_debug",),
        methods=("GET",),
    )

    page = ApiSpecService(db_session).operations(team.viewer_a, spec.id, ALL, grant_id=grant.id)

    verdicts = {(entry.operation.method, entry.operation.path): entry for entry in page.items}
    assert verdicts["GET", "/users/v1"].eligible is True
    assert verdicts["GET", "/users/v1/{username}"].reason is None
    assert verdicts["GET", "/books/v1/{book_title}"].eligible is True
    assert verdicts["GET", "/users/v1/_debug"].reason is IneligibleReason.PATH_EXCLUDED
    assert verdicts["DELETE", "/users/v1/{username}"].reason is (
        IneligibleReason.METHOD_NOT_AUTHORIZED
    )
    assert verdicts["GET", "/books/v1"].reason is IneligibleReason.PATH_NOT_AUTHORIZED
    assert verdicts["GET", "/books/v1"].eligible is False
    assert sum(entry.eligible is True for entry in page.items) == 3


def test_preview_grant_must_belong_to_the_same_target(
    db_session: Session, team: Members, target: Target
) -> None:
    spec = _upload(db_session, team.operator_a, target.id)
    other_target = _target(db_session, team, "http://juice-shop:3000")
    other_grant = ScopeGrantService(db_session, lab=LAB).request(
        team.operator_a,
        other_target.id,
        grant_request(NOW, origins=("http://juice-shop:3000",)),
        now=NOW,
        request_id=None,
    )
    service = ApiSpecService(db_session)

    wrong_target = app_error(
        lambda: service.operations(team.viewer_a, spec.id, ALL, grant_id=other_grant.id)
    )
    missing = app_error(lambda: service.operations(team.viewer_a, spec.id, ALL, grant_id=uuid4()))

    assert (wrong_target.status_code, wrong_target.code) == (422, ErrorCode.INVALID_REQUEST)
    assert (missing.status_code, missing.code) == (404, ErrorCode.RESOURCE_NOT_FOUND)


def test_preview_grant_of_another_project_looks_missing(
    db_session: Session, team: Members, target: Target
) -> None:
    """A 的 operator 讀不到 B 的 grant，與不存在的一樣回 404。

    admin 兩邊都讀得到：用 B 的 grant 預覽 A 的規格，是「其他 target 的 grant」（422）。
    """
    spec = _upload(db_session, team.operator_a, target.id)
    target_b = TargetService(db_session, lab=LAB).create(
        team.admin, team.project_b, name="B", kind=TargetKind.API, base_url=VAMPI, request_id=None
    )
    grant_b = ScopeGrantService(db_session, lab=LAB).request(
        team.operator_b, target_b.id, grant_request(NOW), now=NOW, request_id=None
    )
    service = ApiSpecService(db_session)

    error = app_error(
        lambda: service.operations(team.operator_a, spec.id, ALL, grant_id=grant_b.id)
    )
    admin = app_error(lambda: service.operations(team.admin, spec.id, ALL, grant_id=grant_b.id))

    assert (error.status_code, error.code) == (404, ErrorCode.RESOURCE_NOT_FOUND)
    assert (admin.status_code, admin.code) == (422, ErrorCode.INVALID_REQUEST)


def test_missing_spec_operations_look_missing(db_session: Session, team: Members) -> None:
    error = app_error(
        lambda: ApiSpecService(db_session).operations(team.admin, uuid4(), ALL, grant_id=None)
    )

    assert (error.status_code, error.code) == (404, ErrorCode.RESOURCE_NOT_FOUND)
