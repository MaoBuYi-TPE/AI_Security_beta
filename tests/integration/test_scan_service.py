"""建立 scan：快照、檢查的先後、Idempotency-Key、忙碌與上限、audit。

規則見 docs/DECISIONS.md §13.1、§13.2、§13.3。

每個測試在 db_session 的交易中執行並回滾（佇列與併發的測試另有會 commit 的資料庫）。
"""

import dataclasses
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from secscan.auth_profiles.domain.credentials import SecretValue
from secscan.auth_profiles.domain.model import ChangeInput, PreflightInput
from secscan.auth_profiles.service import AuthProfileService
from secscan.core.errors import ErrorCode
from secscan.core.pagination import PageRequest
from secscan.grants.domain.matching import IneligibleReason
from secscan.grants.service import ScopeGrantService
from secscan.scans import service as scan_service
from secscan.scans.domain.catalog import Engine, ScanProfile
from secscan.scans.domain.lifecycle import RunStatus, ScanStatus
from secscan.scans.domain.model import AuthBinding, Coverage, VersionRef
from secscan.scans.domain.request import BudgetRequest
from secscan.specs.service import ApiSpecService
from secscan.targets.domain import TargetKind, TargetUpdate
from secscan.targets.service import TargetService
from tests.integration.scan_support import (
    CANARY_SECRET,
    ELIGIBLE,
    INELIGIBLE,
    NOW,
    ScanWorld,
    approved_grant,
    clock_at,
    create_profile,
    create_scan,
    make_target,
    new_key,
    scan_world,
    upload_spec,
    with_budget,
)
from tests.integration.scope_support import LAB, app_error, grant_request
from tests.secret_support import shared_cipher

pytestmark = pytest.mark.integration


@pytest.fixture
def world(db_session: Session) -> ScanWorld:
    return scan_world(db_session)


def _count(session: Session, table: str) -> int:
    statements = {
        "scans": "SELECT count(*) FROM scans",
        "scanner_runs": "SELECT count(*) FROM scanner_runs",
        "scan_operations": "SELECT count(*) FROM scan_operations",
        "scan_events": "SELECT count(*) FROM scan_events",
        "audit": "SELECT count(*) FROM audit_events WHERE action LIKE 'scan.%'",
    }
    return int(session.execute(text(statements[table])).scalar_one())


def _counts(session: Session) -> dict[str, int]:
    tables = ("scans", "scanner_runs", "scan_operations", "scan_events", "audit")
    return {table: _count(session, table) for table in tables}


def _finish(session: Session, scan_id: object) -> None:
    """模擬 scan 已結束（佇列的轉換由 queue 的測試負責）。"""
    session.execute(
        text(
            "UPDATE scanner_runs SET status = 'cancelled', finished_at = now() WHERE scan_id = :id"
        ),
        {"id": scan_id},
    )
    session.execute(
        text(
            "UPDATE scans SET status = 'cancelled', cancel_requested_at = now(), "
            "finished_at = now() WHERE id = :id"
        ),
        {"id": scan_id},
    )


# --- 建立與快照 ----------------------------------------------------------------------------


def test_creates_a_queued_scan_with_its_run_operations_event_and_audit(
    db_session: Session, world: ScanWorld
) -> None:
    before = _counts(db_session)

    scan = create_scan(db_session, world)

    assert scan.status is ScanStatus.QUEUED
    assert (scan.project_id, scan.target_id) == (world.team.project_a, world.target.id)
    assert scan.target_origin == world.target.origin
    assert scan.profile is ScanProfile.API_ACTIVE_LAB
    assert scan.scope_grant == VersionRef(id=world.grant.id, version=world.grant.version)
    assert scan.api_spec == VersionRef(id=world.spec.id, version=world.spec.version)
    assert scan.auth == AuthBinding(
        profile_id=world.profile.id, version=1, role_label="standard_user"
    )
    assert scan.auth_role == "standard_user"
    assert scan.budget == world.grant.budget
    assert scan.coverage == Coverage(eligible_operations=ELIGIBLE, ineligible_operations=INELIGIBLE)
    assert [(run.engine, run.sequence, run.status) for run in scan.runs] == [
        (Engine.FAKE, 1, RunStatus.QUEUED)
    ]
    assert scan.fixture is True
    assert scan.results_complete is False
    assert scan.created_by_key_id == world.operator.key_id
    assert (scan.cancel_requested_at, scan.finished_at) == (None, None)
    after = _counts(db_session)
    assert {table: after[table] - before[table] for table in after} == {
        "scans": 1,
        "scanner_runs": 1,
        "scan_operations": ELIGIBLE + INELIGIBLE,
        "scan_events": 1,
        "audit": 1,
    }


def test_operations_are_frozen_with_the_grant_decision(
    db_session: Session, world: ScanWorld
) -> None:
    scan = create_scan(db_session, world)

    rows = db_session.execute(
        text(
            "SELECT ordinal, method, path, operation_id, ineligible_reason FROM scan_operations "
            "WHERE scan_id = :id ORDER BY ordinal"
        ),
        {"id": scan.id},
    ).all()
    inventory = ApiSpecService(db_session).operations(
        world.team.admin, world.spec.id, PageRequest(page=1, limit=100), grant_id=world.grant.id
    )
    assert [(row.method, row.path, row.operation_id) for row in rows] == [
        (entry.operation.method, entry.operation.path, entry.operation.operation_id)
        for entry in inventory.items
    ]
    assert [row.ordinal for row in rows] == list(range(len(rows)))
    reasons = {(row.method, row.path): row.ineligible_reason for row in rows}
    assert reasons == {
        ("GET", "/me"): None,
        ("GET", "/users/v1"): None,
        ("GET", "/users/v1/{username}"): None,
        ("GET", "/users/v1/_debug"): IneligibleReason.PATH_EXCLUDED.value,
        ("POST", "/users/v1"): IneligibleReason.METHOD_NOT_AUTHORIZED.value,
        ("DELETE", "/users/v1/{username}"): IneligibleReason.METHOD_NOT_AUTHORIZED.value,
        ("GET", "/books/v1"): IneligibleReason.PATH_NOT_AUTHORIZED.value,
    }


def test_the_first_event_records_the_creation(db_session: Session, world: ScanWorld) -> None:
    scan = create_scan(db_session, world)

    [event] = db_session.execute(
        text(
            "SELECT sequence, event_type, scanner_run_id, payload FROM scan_events "
            "WHERE scan_id = :id"
        ),
        {"id": scan.id},
    ).all()
    assert (event.sequence, event.event_type, event.scanner_run_id) == (1, "scan.created", None)
    assert event.payload == {"status": "queued", "profile": "api_active_lab", "engines": ["fake"]}


def test_binds_the_latest_profile_version(db_session: Session, world: ScanWorld) -> None:
    AuthProfileService(db_session, cipher=shared_cipher()).update(
        world.team.admin, world.profile.id, ChangeInput(secret=SecretValue("t2")), request_id=None
    )

    scan = create_scan(db_session, world)

    assert scan.auth == AuthBinding(
        profile_id=world.profile.id, version=2, role_label="standard_user"
    )


def test_an_unauthenticated_scan_is_anonymous(db_session: Session, world: ScanWorld) -> None:
    scan = create_scan(db_session, world, world.request(auth_profile_id=None))

    assert scan.auth is None
    assert scan.auth_role == "anonymous"


def test_a_web_scan_has_no_spec_and_no_operations(db_session: Session, world: ScanWorld) -> None:
    team = world.team
    target = make_target(db_session, team.admin, team.project_a, kind=TargetKind.WEB)
    grant = approved_grant(db_session, team, target)

    scan = create_scan(
        db_session,
        world,
        world.request(
            target_id=target.id,
            scope_grant_id=grant.id,
            api_spec_id=None,
            auth_profile_id=None,
            profile=ScanProfile.WEB_ACTIVE_LAB,
        ),
    )

    assert (scan.api_spec, scan.coverage, scan.auth_role) == (None, None, "anonymous")


def test_a_hybrid_target_takes_both_profiles(db_session: Session, world: ScanWorld) -> None:
    team = world.team
    target = make_target(db_session, team.admin, team.project_a, kind=TargetKind.HYBRID)
    grant = approved_grant(db_session, team, target)
    spec = upload_spec(db_session, team, target)
    request = world.request(
        target_id=target.id, scope_grant_id=grant.id, api_spec_id=spec.id, auth_profile_id=None
    )

    api_scan = create_scan(db_session, world, request)
    _finish(db_session, api_scan.id)
    web_scan = create_scan(
        db_session,
        world,
        dataclasses.replace(request, api_spec_id=None, profile=ScanProfile.WEB_ACTIVE_LAB),
    )

    assert (api_scan.profile, web_scan.profile) == (
        ScanProfile.API_ACTIVE_LAB,
        ScanProfile.WEB_ACTIVE_LAB,
    )


def test_budget_items_default_to_the_grant_and_may_be_lower(
    db_session: Session, world: ScanWorld
) -> None:
    scan = create_scan(db_session, world, with_budget(world.request(), max_requests=100))

    assert (scan.budget.requests_per_second, scan.budget.max_requests) == (
        world.grant.budget.requests_per_second,
        100,
    )
    assert scan.budget.max_duration_seconds == world.grant.budget.max_duration_seconds


def test_admins_can_create_scans_in_any_project(db_session: Session, world: ScanWorld) -> None:
    scan = create_scan(db_session, world, principal=world.team.admin)

    assert scan.created_by_key_id == world.team.admin.key_id


# --- Idempotency-Key -----------------------------------------------------------------------


def test_the_same_key_and_content_returns_the_same_scan_without_writing(
    db_session: Session, world: ScanWorld
) -> None:
    key = new_key()
    first = create_scan(db_session, world, key=key)
    before = _counts(db_session)

    again = create_scan(db_session, world, key=key)

    assert again == first
    assert _counts(db_session) == before


def test_a_replay_returns_the_current_state_of_the_scan(
    db_session: Session, world: ScanWorld
) -> None:
    key = new_key()
    first = create_scan(db_session, world, key=key)
    _finish(db_session, first.id)

    again = create_scan(db_session, world, key=key)

    assert again.id == first.id
    assert again.status is ScanStatus.CANCELLED


def test_a_replay_does_not_check_the_gate_again(db_session: Session, world: ScanWorld) -> None:
    """重送是要知道當初那一次的結果：grant 撤銷之後重送，仍回原本的 scan。"""
    key = new_key()
    first = create_scan(db_session, world, key=key)
    ScopeGrantService(db_session, lab=LAB).revoke(
        world.team.admin, world.grant.id, reason="停止", now=NOW, request_id=None
    )

    assert create_scan(db_session, world, key=key).id == first.id


def test_an_explicit_null_budget_item_is_the_same_content(
    db_session: Session, world: ScanWorld
) -> None:
    key = new_key()
    first = create_scan(db_session, world, key=key)

    again = create_scan(
        db_session, world, with_budget(world.request(), requests_per_second=None), key=key
    )

    assert again.id == first.id


@pytest.mark.parametrize(
    "change",
    [
        {"api_spec_id": None},
        {"auth_profile_id": None},
        {"profile": ScanProfile.WEB_ACTIVE_LAB},
        {"engines": (Engine.ZAP,)},
        {"budget": BudgetRequest(max_requests=10)},
        {"scope_grant_id": uuid4()},
    ],
    ids=["spec", "profile", "scan_profile", "engines", "budget", "grant"],
)
def test_the_same_key_with_other_content_is_a_conflict(
    db_session: Session, world: ScanWorld, change: dict[str, object]
) -> None:
    """不同的內容回 409，不先判斷新內容的其他錯誤（例如不支援的引擎），也什麼都不寫。"""
    key = new_key()
    create_scan(db_session, world, key=key)
    before = _counts(db_session)

    error = app_error(lambda: create_scan(db_session, world, world.request(**change), key=key))

    assert (error.status_code, error.code) == (409, ErrorCode.IDEMPOTENCY_CONFLICT)
    assert _counts(db_session) == before


def test_another_target_of_the_project_with_the_same_key_is_a_conflict(
    db_session: Session, world: ScanWorld
) -> None:
    key = new_key()
    create_scan(db_session, world, key=key)
    other = scan_world(db_session, world.team)

    error = app_error(lambda: create_scan(db_session, other, key=key))

    assert (error.status_code, error.code) == (409, ErrorCode.IDEMPOTENCY_CONFLICT)


def test_keys_are_scoped_to_the_project(db_session: Session, world: ScanWorld) -> None:
    key = new_key()
    first = create_scan(db_session, world, key=key)
    team_b = dataclasses.replace(
        world.team, project_a=world.team.project_b, operator_a=world.team.operator_b
    )
    other = scan_world(db_session, team_b)

    second = create_scan(db_session, other, key=key)

    assert second.id != first.id
    assert second.project_id == world.team.project_b


def test_a_viewer_replaying_a_used_key_is_still_forbidden(
    db_session: Session, world: ScanWorld
) -> None:
    key = new_key()
    create_scan(db_session, world, key=key)

    error = app_error(
        lambda: create_scan(db_session, world, principal=world.team.viewer_a, key=key)
    )

    assert (error.status_code, error.code) == (403, ErrorCode.ROLE_NOT_ALLOWED)


# --- 檢查的先後 ----------------------------------------------------------------------------


def test_targets_of_other_projects_look_missing(db_session: Session, world: ScanWorld) -> None:
    missing = app_error(lambda: create_scan(db_session, world, world.request(target_id=uuid4())))
    other = app_error(lambda: create_scan(db_session, world, principal=world.team.operator_b))

    assert (missing.status_code, missing.code) == (404, ErrorCode.RESOURCE_NOT_FOUND)
    assert (other.status_code, other.code, other.message) == (
        missing.status_code,
        missing.code,
        missing.message,
    )


def test_viewers_cannot_create_scans(db_session: Session, world: ScanWorld) -> None:
    error = app_error(lambda: create_scan(db_session, world, principal=world.team.viewer_a))

    assert (error.status_code, error.code) == (403, ErrorCode.ROLE_NOT_ALLOWED)


@pytest.mark.parametrize(
    ("engines", "code"),
    [
        ((Engine.ZAP,), ErrorCode.ENGINE_UNSUPPORTED),
        ((Engine.NUCLEI,), ErrorCode.ENGINE_UNSUPPORTED),
        ((Engine.SCHEMATHESIS,), ErrorCode.ENGINE_UNSUPPORTED),
        ((Engine.FAKE, Engine.FAKE), ErrorCode.INVALID_REQUEST),
        ((Engine.FAKE, Engine.ZAP), ErrorCode.INVALID_REQUEST),
    ],
)
def test_engine_rules(
    db_session: Session, world: ScanWorld, engines: tuple[Engine, ...], code: ErrorCode
) -> None:
    error = app_error(lambda: create_scan(db_session, world, world.request(engines=engines)))

    assert (error.status_code, error.code) == (422, code)


def test_engine_rules_come_before_the_gate(db_session: Session, world: ScanWorld) -> None:
    """引擎與 profile 的規則只看請求本身，比 gate（要取得鎖）先判斷。"""
    ScopeGrantService(db_session, lab=LAB).revoke(
        world.team.admin, world.grant.id, reason="停止", now=NOW, request_id=None
    )

    error = app_error(lambda: create_scan(db_session, world, world.request(engines=(Engine.ZAP,))))

    assert error.code is ErrorCode.ENGINE_UNSUPPORTED


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"profile": ScanProfile.WEB_ACTIVE_LAB}, "web 或 hybrid"),
        ({"api_spec_id": None}, "api_spec_id"),
    ],
)
def test_profile_rules(
    db_session: Session, world: ScanWorld, change: dict[str, object], reason: str
) -> None:
    error = app_error(lambda: create_scan(db_session, world, world.request(**change)))

    assert (error.status_code, error.code) == (422, ErrorCode.PROFILE_INCOMPATIBLE)
    assert reason in error.message


def test_a_web_profile_with_a_spec_is_incompatible(db_session: Session, world: ScanWorld) -> None:
    team = world.team
    target = make_target(db_session, team.admin, team.project_a, kind=TargetKind.HYBRID)
    grant = approved_grant(db_session, team, target)
    spec = upload_spec(db_session, team, target)
    request = world.request(
        target_id=target.id,
        scope_grant_id=grant.id,
        api_spec_id=spec.id,
        auth_profile_id=None,
        profile=ScanProfile.WEB_ACTIVE_LAB,
    )

    error = app_error(lambda: create_scan(db_session, world, request))

    assert (error.status_code, error.code) == (422, ErrorCode.PROFILE_INCOMPATIBLE)


def test_the_gate_rejects_unusable_grants(db_session: Session, world: ScanWorld) -> None:
    team = world.team
    pending = ScopeGrantService(db_session, lab=LAB).request(
        team.admin,
        world.target.id,
        grant_request(NOW, origins=(str(world.target.origin),)),
        now=NOW,
        request_id=None,
    )
    expired_clock = clock_at(world.grant.window.valid_until)

    not_approved = app_error(
        lambda: create_scan(db_session, world, world.request(scope_grant_id=pending.id))
    )
    expired = app_error(lambda: create_scan(db_session, world, clock=expired_clock))
    missing = app_error(
        lambda: create_scan(db_session, world, world.request(scope_grant_id=uuid4()))
    )

    assert (not_approved.status_code, not_approved.code) == (403, ErrorCode.SCOPE_NOT_APPROVED)
    assert (expired.status_code, expired.code) == (403, ErrorCode.SCOPE_EXPIRED)
    assert (missing.status_code, missing.code) == (404, ErrorCode.RESOURCE_NOT_FOUND)


def test_the_gate_rejects_a_grant_of_another_target(db_session: Session, world: ScanWorld) -> None:
    other = scan_world(db_session, world.team)

    error = app_error(
        lambda: create_scan(db_session, world, world.request(scope_grant_id=other.grant.id))
    )

    assert (error.status_code, error.code) == (422, ErrorCode.INVALID_REQUEST)


def test_the_gate_rejects_a_disabled_target(db_session: Session, world: ScanWorld) -> None:
    TargetService(db_session, lab=LAB).update(
        world.team.admin, world.target.id, TargetUpdate(enabled=False), request_id=None
    )

    error = app_error(lambda: create_scan(db_session, world))

    assert (error.status_code, error.code) == (409, ErrorCode.TARGET_DISABLED)


def test_the_gate_comes_before_the_spec_and_the_profile(
    db_session: Session, world: ScanWorld
) -> None:
    ScopeGrantService(db_session, lab=LAB).revoke(
        world.team.admin, world.grant.id, reason="停止", now=NOW, request_id=None
    )

    error = app_error(
        lambda: create_scan(
            db_session, world, world.request(api_spec_id=uuid4(), auth_profile_id=uuid4())
        )
    )

    assert (error.status_code, error.code) == (403, ErrorCode.SCOPE_NOT_APPROVED)


def test_specs_must_exist_belong_to_the_project_and_the_target(
    db_session: Session, world: ScanWorld
) -> None:
    sibling = scan_world(db_session, world.team)
    team_b = dataclasses.replace(
        world.team, project_a=world.team.project_b, operator_a=world.team.operator_b
    )
    other_project = scan_world(db_session, team_b)

    missing = app_error(lambda: create_scan(db_session, world, world.request(api_spec_id=uuid4())))
    foreign = app_error(
        lambda: create_scan(db_session, world, world.request(api_spec_id=other_project.spec.id))
    )
    wrong_target = app_error(
        lambda: create_scan(db_session, world, world.request(api_spec_id=sibling.spec.id))
    )

    assert (missing.status_code, missing.code) == (404, ErrorCode.RESOURCE_NOT_FOUND)
    assert (foreign.status_code, foreign.code, foreign.message) == (
        missing.status_code,
        missing.code,
        missing.message,
    )
    assert (wrong_target.status_code, wrong_target.code) == (422, ErrorCode.INVALID_REQUEST)


def test_an_api_scan_needs_an_operation_in_scope(db_session: Session, world: ScanWorld) -> None:
    team = world.team
    target = make_target(db_session, team.admin, team.project_a)
    grant = approved_grant(db_session, team, target, paths=("/nothing/here",), excluded_paths=())
    spec = upload_spec(db_session, team, target)
    request = world.request(
        target_id=target.id, scope_grant_id=grant.id, api_spec_id=spec.id, auth_profile_id=None
    )

    error = app_error(lambda: create_scan(db_session, world, request))

    assert (error.status_code, error.code) == (422, ErrorCode.PROFILE_INCOMPATIBLE)


def test_profiles_must_exist_belong_to_the_project_and_the_target(
    db_session: Session, world: ScanWorld
) -> None:
    sibling = scan_world(db_session, world.team)
    team_b = dataclasses.replace(
        world.team, project_a=world.team.project_b, operator_a=world.team.operator_b
    )
    other_project = scan_world(db_session, team_b)

    missing = app_error(
        lambda: create_scan(db_session, world, world.request(auth_profile_id=uuid4()))
    )
    foreign = app_error(
        lambda: create_scan(
            db_session, world, world.request(auth_profile_id=other_project.profile.id)
        )
    )
    wrong_target = app_error(
        lambda: create_scan(db_session, world, world.request(auth_profile_id=sibling.profile.id))
    )

    assert (missing.status_code, missing.code) == (404, ErrorCode.RESOURCE_NOT_FOUND)
    assert (foreign.status_code, foreign.code, foreign.message) == (
        missing.status_code,
        missing.code,
        missing.message,
    )
    assert (wrong_target.status_code, wrong_target.code) == (422, ErrorCode.INVALID_REQUEST)


def test_a_profile_without_a_secret_cannot_be_bound(db_session: Session, world: ScanWorld) -> None:
    """只有直接改了 DB 才會發生（trigger 允許清除）：沒有 secret 就不能掃描。"""
    db_session.execute(
        text(
            "UPDATE auth_profile_versions SET encrypted_secret = NULL, "
            "secret_erased_at = now() WHERE profile_id = :id"
        ),
        {"id": world.profile.id},
    )

    error = app_error(lambda: create_scan(db_session, world))

    assert (error.status_code, error.code) == (409, ErrorCode.INVALID_STATE_TRANSITION)


@pytest.mark.parametrize(
    ("path", "grant_methods", "reason"),
    [
        ("/users/v1/_debug", ("GET",), IneligibleReason.PATH_EXCLUDED),
        ("/books/v1", ("GET",), IneligibleReason.PATH_NOT_AUTHORIZED),
        ("/me", ("POST",), IneligibleReason.METHOD_NOT_AUTHORIZED),
    ],
)
def test_the_preflight_must_be_in_the_grant_scope(
    db_session: Session,
    world: ScanWorld,
    path: str,
    grant_methods: tuple[str, ...],
    reason: IneligibleReason,
) -> None:
    """preflight 是實際送出的請求（docs/DECISIONS.md §12.5）：不在範圍內就不能綁定。"""
    team = world.team
    target = make_target(db_session, team.admin, team.project_a)
    grant = approved_grant(db_session, team, target, methods=grant_methods)
    preflight = PreflightInput(
        method="GET", path=path, expected_status=200, expected_json={"/status": "success"}
    )
    profile = create_profile(db_session, team, target, preflight=preflight)
    spec = upload_spec(db_session, team, target)
    request = world.request(
        target_id=target.id,
        scope_grant_id=grant.id,
        api_spec_id=spec.id,
        auth_profile_id=profile.id,
    )

    error = app_error(lambda: create_scan(db_session, world, request))

    assert error.status_code == 422
    assert reason.value in error.message
    assert path not in error.message


@pytest.mark.parametrize(
    ("budget", "field"),
    [
        ({"requests_per_second": 3}, "requests_per_second"),
        ({"max_requests": 5_001}, "max_requests"),
        ({"max_duration_seconds": 1_501}, "max_duration_seconds"),
    ],
)
def test_the_budget_cannot_exceed_the_grant(
    db_session: Session, world: ScanWorld, budget: dict[str, int], field: str
) -> None:
    error = app_error(
        lambda: create_scan(db_session, world, with_budget(world.request(), **budget))
    )

    assert (error.status_code, error.code) == (422, ErrorCode.INVALID_REQUEST)
    assert field in error.message


def test_a_target_runs_one_scan_at_a_time(db_session: Session, world: ScanWorld) -> None:
    first = create_scan(db_session, world)

    busy = app_error(lambda: create_scan(db_session, world))
    _finish(db_session, first.id)
    second = create_scan(db_session, world)

    assert (busy.status_code, busy.code) == (409, ErrorCode.TARGET_BUSY)
    assert second.id != first.id


def test_scans_per_target_are_limited_per_day(
    db_session: Session, world: ScanWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_service, "MAX_SCANS_PER_TARGET_PER_DAY", 2)
    for _ in range(2):
        _finish(db_session, create_scan(db_session, world).id)

    full = app_error(lambda: create_scan(db_session, world))
    next_day = create_scan(db_session, world, clock=clock_at(NOW + timedelta(hours=25)))

    assert (full.status_code, full.code) == (409, ErrorCode.QUOTA_EXCEEDED)
    assert next_day.status is ScanStatus.QUEUED


def test_the_scan_quota_is_fifty_per_target_per_day() -> None:
    assert scan_service.MAX_SCANS_PER_TARGET_PER_DAY == 50


# --- audit ---------------------------------------------------------------------------------


def test_the_audit_records_the_snapshot_without_secrets_or_keys(
    db_session: Session, world: ScanWorld
) -> None:
    key = new_key()
    scan = create_scan(db_session, world, key=key)

    [row] = db_session.execute(
        text(
            "SELECT action, object_type, object_id, actor_key_id, project_id, request_id, "
            "redacted_changes FROM audit_events WHERE object_id = :id"
        ),
        {"id": scan.id},
    ).all()
    assert (row.action, row.object_type, row.actor_key_id, row.project_id, row.request_id) == (
        "scan.create",
        "scan",
        world.operator.key_id,
        world.team.project_a,
        "req-scan-test",
    )
    assert row.redacted_changes == {
        "target_id": str(world.target.id),
        "scope_grant": {"id": str(world.grant.id), "version": world.grant.version},
        "api_spec": {"id": str(world.spec.id), "version": world.spec.version},
        "identity": {
            "profile_id": str(world.profile.id),
            "version": 1,
            "role_label": "standard_user",
        },
        "scan_profile": "api_active_lab",
        "engines": ["fake"],
        "budget": {
            "requests_per_second": world.grant.budget.requests_per_second,
            "max_requests": world.grant.budget.max_requests,
            "max_duration_seconds": world.grant.budget.max_duration_seconds,
        },
        "eligible_operations": ELIGIBLE,
    }
    assert key not in str(row.redacted_changes)
    assert CANARY_SECRET not in str(row.redacted_changes)
