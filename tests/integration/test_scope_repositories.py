"""targets 與 scope_grants 的 repository：回傳 frozen domain model，鎖住資料列時讀 DB 的最新值。"""

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import event, text
from sqlalchemy.orm import Session

from secscan.core.db import ConstraintViolationError
from secscan.core.pagination import PageRequest
from secscan.grants.domain.lifecycle import GrantStatus, ScopeGrant
from secscan.grants.domain.scope import (
    HttpMethod,
    NewScopeGrant,
    build_scope,
    resolve_budget,
    resolve_window,
)
from secscan.grants.models import ScopeGrantModel
from secscan.grants.repository import ScopeGrantRepository
from secscan.projects.domain import NewProject
from secscan.projects.repository import ProjectRepository
from secscan.targets.domain import NewTarget, Target, TargetKind, TargetUpdate, parse_origin
from secscan.targets.models import TargetModel
from secscan.targets.repository import TargetRepository
from tests.integration.sql_support import insert_key

pytestmark = pytest.mark.integration

ORIGIN = "http://vampi-vuln:5000"


def _project(session: Session) -> UUID:
    return ProjectRepository(session).create(NewProject(name=f"lab-{uuid4().hex[:8]}")).id


def _target(session: Session, project_id: UUID, origin: str = ORIGIN) -> Target:
    return TargetRepository(session).create(
        NewTarget(
            project_id=project_id,
            name="VAmPI",
            kind=TargetKind.API,
            origin=parse_origin(origin),
        )
    )


def _new_grant(target: Target, requester: UUID, **scope: Any) -> NewScopeGrant:
    now = datetime.now(UTC)
    fields: dict[str, Any] = {
        "target_origin": target.origin,
        "origins": [str(target.origin)],
        "ips": ["10.89.7.20"],
        "paths": ["/users/v1", "/books/v1/{book_title}"],
        "allow_all_paths": False,
        "excluded_paths": ["/users/v1/_debug"],
        "methods": ["GET", "HEAD"],
    }
    fields.update(scope)
    return NewScopeGrant(
        target_id=target.id,
        scope=build_scope(**fields),
        budget=resolve_budget(max_requests=1_000),
        window=resolve_window(None, now + timedelta(days=7), now=now),
        authorization_reference="LAB-ASSET-001",
        requested_by_key_id=requester,
    )


def _grant(session: Session, target: Target, requester: UUID, **scope: Any) -> ScopeGrant:
    grants = ScopeGrantRepository(session)
    return grants.create(
        _new_grant(target, requester, **scope), version=grants.next_version(target.id)
    )


@contextmanager
def _statements(session: Session) -> Iterator[list[str]]:
    """記下這段期間送到 DB 的 SQL（用來確認鎖的模式）。"""
    seen: list[str] = []

    def record(_conn: object, _cursor: object, statement: str, *_args: object) -> None:
        seen.append(statement)

    engine = session.get_bind()
    event.listen(engine, "before_cursor_execute", record)
    try:
        yield seen
    finally:
        event.remove(engine, "before_cursor_execute", record)


# --- targets --------------------------------------------------------------------------------


def test_create_target_returns_a_domain_model(db_session: Session) -> None:
    project_id = _project(db_session)

    target = _target(db_session, project_id)

    assert target.project_id == project_id
    assert str(target.origin) == ORIGIN
    assert target.kind is TargetKind.API
    assert target.enabled is True
    assert target.created_at.utcoffset() == timedelta(0)
    assert TargetRepository(db_session).get(target.id) == target


def test_origin_is_unique_within_a_project(db_session: Session) -> None:
    project_id = _project(db_session)
    _target(db_session, project_id)

    with pytest.raises(ConstraintViolationError) as caught, db_session.begin_nested():
        _target(db_session, project_id)

    assert caught.value.constraint == "uq_targets_project_id_canonical_origin"
    assert _target(db_session, _project(db_session))


def test_missing_target_is_none(db_session: Session) -> None:
    targets = TargetRepository(db_session)

    assert targets.get(uuid4()) is None
    assert targets.lock(uuid4()) is None
    assert targets.update(uuid4(), TargetUpdate(enabled=False)) is None


def test_targets_are_listed_per_project_in_creation_order(db_session: Session) -> None:
    project_id = _project(db_session)
    created = [_target(db_session, project_id, f"http://lab-{index}:8000") for index in range(3)]
    _target(db_session, _project(db_session))

    first = TargetRepository(db_session).list_by_project(project_id, PageRequest(page=1, limit=2))
    second = TargetRepository(db_session).list_by_project(project_id, PageRequest(page=2, limit=2))

    assert first.total == 3
    assert [target.id for target in first.items + second.items] == [
        target.id for target in sorted(created, key=lambda t: (t.created_at, t.id))
    ]


def test_update_returns_the_values_before_and_after(db_session: Session) -> None:
    target = _target(db_session, _project(db_session))

    change = TargetRepository(db_session).update(target.id, TargetUpdate(enabled=False))

    assert change is not None
    assert change.before == target
    assert change.after.enabled is False
    assert change.after.name == target.name


def test_target_lock_reads_the_latest_row(db_session: Session) -> None:
    """同一個 session 已載入這個 target，而且還有地方引用它：上鎖時仍要讀到 DB 的最新值。

    identity map 只弱參照 ORM 物件；沒有人引用時物件會被回收，下次查詢自然是新值。
    所以這裡刻意保留參照，模擬同一個請求中其他程式碼仍持有它的情況。
    """
    targets = TargetRepository(db_session)
    target = _target(db_session, _project(db_session))
    cached = db_session.get(TargetModel, target.id)
    assert cached is not None
    assert cached.enabled is True
    db_session.execute(text("UPDATE targets SET enabled = false WHERE id = :id"), {"id": target.id})

    with _statements(db_session) as statements:
        shared = targets.lock(target.id, shared=True)
        exclusive = targets.lock(target.id)

    assert shared is not None
    assert shared.enabled is False
    assert exclusive is not None
    assert "FOR SHARE" in statements[0]
    assert "FOR UPDATE" in statements[1]


# --- scope_grants ---------------------------------------------------------------------------


def test_grant_round_trips_through_the_database(db_session: Session) -> None:
    project_id = _project(db_session)
    target = _target(db_session, project_id)
    requester = insert_key(db_session)

    grant = _grant(db_session, target, requester)

    assert (grant.version, grant.status, grant.project_id) == (1, GrantStatus.PENDING, project_id)
    assert grant.scope.origins == (target.origin,)
    assert grant.scope.ips == (IPv4Address("10.89.7.20"),)
    assert grant.scope.paths == ("/users/v1", "/books/v1/{book_title}")
    assert grant.scope.excluded_paths == ("/users/v1/_debug",)
    assert grant.scope.methods == (HttpMethod.GET, HttpMethod.HEAD)
    assert grant.budget.max_requests == 1_000
    assert grant.window.valid_until.utcoffset() == timedelta(0)
    assert grant.requested_by_key_id == requester
    assert ScopeGrantRepository(db_session).get(grant.id) == grant


def test_versions_count_up_per_target(db_session: Session) -> None:
    project_id = _project(db_session)
    target, other = _target(db_session, project_id), _target(db_session, project_id, "http://b")
    requester = insert_key(db_session)

    versions = [_grant(db_session, target, requester).version for _ in range(3)]

    assert versions == [1, 2, 3]
    assert _grant(db_session, other, requester).version == 1


def test_duplicate_version_is_a_constraint_violation(db_session: Session) -> None:
    target = _target(db_session, _project(db_session))
    requester = insert_key(db_session)
    grants = ScopeGrantRepository(db_session)
    grants.create(_new_grant(target, requester), version=1)

    with pytest.raises(ConstraintViolationError) as caught, db_session.begin_nested():
        grants.create(_new_grant(target, requester), version=1)

    assert caught.value.constraint == "uq_scope_grants_target_id_version"


def test_grants_are_listed_per_target_newest_version_first(db_session: Session) -> None:
    project_id = _project(db_session)
    target, other = _target(db_session, project_id), _target(db_session, project_id, "http://b")
    requester = insert_key(db_session)
    for _ in range(3):
        _grant(db_session, target, requester)
    _grant(db_session, other, requester)
    grants = ScopeGrantRepository(db_session)

    first = grants.list_by_target(target.id, PageRequest(page=1, limit=2))
    second = grants.list_by_target(target.id, PageRequest(page=2, limit=2))

    assert first.total == 3
    assert [grant.version for grant in first.items + second.items] == [3, 2, 1]


def test_approval_and_revocation_are_recorded_by_the_database_clock(db_session: Session) -> None:
    target = _target(db_session, _project(db_session))
    requester, admin = insert_key(db_session), insert_key(db_session)
    grants = ScopeGrantRepository(db_session)
    grant = _grant(db_session, target, requester)
    db_now = db_session.execute(text("SELECT now()")).scalar()

    approved = grants.record_approval(grant.id, key_id=admin, note="已核對 compose.lab.yaml")
    revoked = grants.record_revocation(grant.id, key_id=admin, reason="實驗結束")

    assert (approved.status, approved.approved_by_key_id, approved.approved_at) == (
        GrantStatus.APPROVED,
        admin,
        db_now,
    )
    assert approved.approval_note == "已核對 compose.lab.yaml"
    assert (revoked.status, revoked.revoked_by_key_id, revoked.revocation_reason) == (
        GrantStatus.REVOKED,
        admin,
        "實驗結束",
    )
    assert revoked.approved_at == approved.approved_at


def test_missing_grant_is_none(db_session: Session) -> None:
    grants = ScopeGrantRepository(db_session)

    assert grants.get(uuid4()) is None
    assert grants.lock(uuid4()) is None
    with pytest.raises(LookupError):
        grants.record_approval(uuid4(), key_id=uuid4(), note="x")


def test_grant_lock_reads_the_latest_row_and_locks_only_the_grant(db_session: Session) -> None:
    """與 target 的情況相同：刻意保留已載入的 ORM 物件，上鎖時仍要讀到 DB 的最新狀態。"""
    target = _target(db_session, _project(db_session))
    requester, admin = insert_key(db_session), insert_key(db_session)
    grants = ScopeGrantRepository(db_session)
    grant = _grant(db_session, target, requester)
    cached = db_session.get(ScopeGrantModel, grant.id)
    assert cached is not None
    assert cached.status == "pending"
    db_session.execute(
        text(
            "UPDATE scope_grants SET status = 'revoked', revoked_by_key_id = :key, "
            "revoked_at = now(), revocation_reason = 'elsewhere' WHERE id = :id"
        ),
        {"id": grant.id, "key": admin},
    )

    with _statements(db_session) as statements:
        shared = grants.lock(grant.id, shared=True)
        exclusive = grants.lock(grant.id)

    assert shared is not None
    assert shared.status is GrantStatus.REVOKED
    assert exclusive is not None
    assert "FOR SHARE OF scope_grants" in statements[0]
    assert "FOR UPDATE OF scope_grants" in statements[1]


def test_stored_network_is_never_read_as_a_single_host(db_session: Session) -> None:
    """DB 中若出現網段（只可能直接寫 SQL），讀取時失敗，不會被當成單一主機位址（fail closed）。"""
    target = _target(db_session, _project(db_session))
    grant = _grant(db_session, target, insert_key(db_session))
    db_session.execute(text("ALTER TABLE scope_grants DISABLE TRIGGER scope_grants_guard_rows"))
    db_session.execute(
        text("UPDATE scope_grants SET allowed_ips = '{10.89.7.0/24}' WHERE id = :id"),
        {"id": grant.id},
    )
    db_session.expire_all()

    with pytest.raises(ValueError, match="IPv4"):
        ScopeGrantRepository(db_session).get(grant.id)
