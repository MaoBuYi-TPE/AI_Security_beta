"""ApiKeyService：驗證、建立、撤銷與 audit（docs/DECISIONS.md §9）。在交易內執行，結束時回滾。"""

from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from secscan.api_keys.domain import (
    KEY_HASH_BYTES,
    ApiKeyRejectedError,
    IssuedApiKey,
    Principal,
    RejectionReason,
    Role,
)
from secscan.api_keys.repository import ApiKeyRepository
from secscan.api_keys.service import KEY_CREATE_ATTEMPTS, ApiKeyService
from secscan.audit.repository import AuditEventRepository
from secscan.core.db import ConstraintViolationError
from secscan.core.errors import AppError, ErrorCode
from secscan.core.pagination import PageRequest
from secscan.projects.domain import NewProject
from secscan.projects.repository import ProjectRepository
from secscan.security.api_key_tokens import GeneratedKey, generate_key, hash_key
from secscan.security.redaction import REDACTED

pytestmark = pytest.mark.integration

NOW = datetime.now(UTC)


def _project(session: Session) -> UUID:
    return ProjectRepository(session).create(NewProject(name=f"lab-{uuid4().hex[:8]}")).id


def _admin(session: Session) -> IssuedApiKey:
    return ApiKeyService(session).issue_admin_key(name="admin", expires_at=None, now=NOW)


def _member(session: Session, role: Role, project_id: UUID, **overrides: object) -> IssuedApiKey:
    admin = Principal.of(_admin(session).key)
    fields: dict[str, object] = {"name": "member", "role": role, "expires_at": None, **overrides}
    return ApiKeyService(session).issue_project_key(
        admin,
        project_id,
        now=NOW,
        request_id="0" * 32,
        **fields,  # type: ignore[arg-type]
    )


def _rejection(session: Session, value: str, *, now: datetime = NOW) -> ApiKeyRejectedError:
    with pytest.raises(ApiKeyRejectedError) as caught:
        ApiKeyService(session).authenticate(value, now=now)
    return caught.value


def _events(session: Session, project_id: UUID) -> list[dict[str, object]]:
    page = AuditEventRepository(session).list_by_project(project_id, PageRequest(limit=100))
    return [
        {"action": event.action, "actor": event.actor_key_id, "changes": event.redacted_changes}
        for event in page.items
    ]


# --- authenticate ---------------------------------------------------------------------------


def test_valid_keys_authenticate_as_their_principal(db_session: Session) -> None:
    project_id = _project(db_session)
    admin = _admin(db_session)
    viewer = _member(db_session, Role.VIEWER, project_id)
    service = ApiKeyService(db_session)

    assert service.authenticate(admin.value, now=NOW) == Principal.of(admin.key)
    assert service.authenticate(viewer.value, now=NOW) == Principal(
        key_id=viewer.key.id, role=Role.VIEWER, project_id=project_id
    )


def test_malformed_and_unknown_keys_are_rejected_without_identifying_a_key(
    db_session: Session,
) -> None:
    malformed = _rejection(db_session, "not-a-platform-key")
    unknown = _rejection(db_session, generate_key().value)

    assert (malformed.reason, malformed.key_id) == (RejectionReason.MALFORMED, None)
    assert (unknown.reason, unknown.key_id) == (RejectionReason.UNKNOWN_KEY, None)


def test_known_prefix_with_wrong_secret_is_rejected(db_session: Session) -> None:
    issued = _admin(db_session)
    forged = f"{issued.value[:-64]}{'0' * 64}"

    rejected = _rejection(db_session, forged)

    assert (rejected.reason, rejected.key_id) == (RejectionReason.HASH_MISMATCH, issued.key.id)


def test_revoked_key_is_rejected(db_session: Session) -> None:
    issued = _admin(db_session)
    ApiKeyService(db_session).revoke(Principal.of(issued.key), issued.key.id, request_id=None)

    assert _rejection(db_session, issued.value).reason is RejectionReason.REVOKED


def test_key_expires_exactly_at_expires_at(db_session: Session) -> None:
    project_id = _project(db_session)
    expires_at = NOW + timedelta(days=1)
    issued = _member(db_session, Role.OPERATOR, project_id, expires_at=expires_at)
    service = ApiKeyService(db_session)

    principal = service.authenticate(issued.value, now=expires_at - timedelta(microseconds=1))
    expired = _rejection(db_session, issued.value, now=expires_at)

    assert principal.key_id == issued.key.id
    assert (expired.reason, expired.key_id) == (RejectionReason.EXPIRED, issued.key.id)


def test_secret_is_checked_before_expiry(db_session: Session) -> None:
    """只知道公開 prefix 的人，不能藉 API_KEY_EXPIRED 探測某把 key 是否已過期。"""
    issued = _admin(db_session)
    forged = f"{issued.value[:-64]}{'0' * 64}"

    rejected = _rejection(db_session, forged, now=NOW + timedelta(days=91))

    assert rejected.reason is RejectionReason.HASH_MISMATCH


def test_key_without_expiry_is_treated_as_expired(db_session: Session) -> None:
    """沒有到期時間的 key 只可能經由直接寫 DB 產生；一律拒絕（fail closed）。"""
    issued = _admin(db_session)
    db_session.execute(
        text("UPDATE api_keys SET expires_at = NULL WHERE id = :id"), {"id": issued.key.id}
    )
    db_session.expire_all()

    assert _rejection(db_session, issued.value).reason is RejectionReason.EXPIRED


def test_revocation_is_reported_before_expiry(db_session: Session) -> None:
    issued = _admin(db_session)
    ApiKeyService(db_session).revoke(Principal.of(issued.key), issued.key.id, request_id=None)

    after_expiry = NOW + timedelta(days=91)

    assert _rejection(db_session, issued.value, now=after_expiry).reason is RejectionReason.REVOKED


# --- 建立 -----------------------------------------------------------------------------------


def test_issued_key_is_stored_only_as_hash_and_audited(db_session: Session) -> None:
    project_id = _project(db_session)

    issued = _member(db_session, Role.VIEWER, project_id, name="ci-reader")

    stored = db_session.execute(
        text(
            "SELECT prefix, key_hash, row_to_json(api_keys)::text AS row "
            "FROM api_keys WHERE id = :id"
        ),
        {"id": issued.key.id},
    ).one()
    assert stored.key_hash == hash_key(issued.value)
    assert len(stored.key_hash) == KEY_HASH_BYTES
    assert issued.value not in stored.row
    assert issued.value[-64:] not in stored.row
    assert stored.prefix == issued.key.prefix
    [event] = _events(db_session, project_id)
    assert event["action"] == "api_key.create"
    assert event["changes"] == {
        "role": "viewer",
        "name": "ci-reader",
        "prefix": issued.key.prefix,
        "expires_at": issued.key.expires_at.isoformat() if issued.key.expires_at else None,
    }
    assert issued.value[-64:] not in str(event)


def test_issued_key_defaults_to_ninety_days(db_session: Session) -> None:
    issued = _member(db_session, Role.VIEWER, _project(db_session))

    assert issued.key.expires_at == NOW + timedelta(days=90)


@pytest.mark.parametrize(
    "expires_at",
    [NOW - timedelta(minutes=1), NOW + timedelta(days=366)],
    ids=["past", "beyond-max"],
)
def test_expiry_outside_the_policy_is_an_invalid_request(
    db_session: Session, expires_at: datetime
) -> None:
    with pytest.raises(AppError) as caught:
        _member(db_session, Role.VIEWER, _project(db_session), expires_at=expires_at)

    assert (caught.value.status_code, caught.value.code) == (422, ErrorCode.INVALID_REQUEST)
    assert "expires_at" in caught.value.message


def test_key_for_missing_project_is_not_found_and_transaction_stays_usable(
    db_session: Session,
) -> None:
    with pytest.raises(AppError) as caught:
        _member(db_session, Role.VIEWER, uuid4())

    assert (caught.value.status_code, caught.value.code) == (404, ErrorCode.RESOURCE_NOT_FOUND)
    assert "fk_" not in caught.value.message
    # FK 錯誤發生在 savepoint 內：外層 transaction 仍然可以繼續使用。
    assert db_session.execute(text("SELECT 1")).scalar() == 1


def test_app_clock_behind_db_clock_is_an_invalid_request(db_session: Session) -> None:
    """應用程式時鐘落後 DB：期限通過 resolve_expiry，卻早於 DB 的建立時間（CHECK 擋下）。"""
    project_id = _project(db_session)
    admin = Principal.of(_admin(db_session).key)
    lagging_now = NOW - timedelta(days=10)

    with pytest.raises(AppError) as caught:
        ApiKeyService(db_session).issue_project_key(
            admin,
            project_id,
            name="lagging",
            role=Role.VIEWER,
            expires_at=lagging_now + timedelta(days=5),
            now=lagging_now,
            request_id=None,
        )

    assert (caught.value.status_code, caught.value.code) == (422, ErrorCode.INVALID_REQUEST)
    assert "ck_" not in caught.value.message
    assert db_session.execute(text("SELECT 1")).scalar() == 1


def test_unknown_constraint_violation_is_not_mapped(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """不認得的約束不猜測錯誤碼，原樣拋出（API 回通用的 500）。"""

    def violate(_self: ApiKeyRepository, _new_key: object) -> None:
        raise ConstraintViolationError("ck_api_keys_future_rule", "23514")

    monkeypatch.setattr(ApiKeyRepository, "create", violate)

    with pytest.raises(ConstraintViolationError) as caught:
        _admin(db_session)

    assert caught.value.constraint == "ck_api_keys_future_rule"


@pytest.mark.parametrize(
    ("role", "target", "status"),
    [(Role.OPERATOR, "own", 403), (Role.VIEWER, "own", 403), (Role.OPERATOR, "other", 404)],
)
def test_only_platform_admin_issues_keys(
    db_session: Session, role: Role, target: str, status: int
) -> None:
    own, other = _project(db_session), _project(db_session)
    caller = Principal.of(_member(db_session, role, own).key)

    with pytest.raises(AppError) as caught:
        ApiKeyService(db_session).issue_project_key(
            caller,
            own if target == "own" else other,
            name="escalate",
            role=Role.OPERATOR,
            expires_at=None,
            now=NOW,
            request_id=None,
        )

    assert caught.value.status_code == status


def _generator(*keys: GeneratedKey) -> tuple[Callable[[], GeneratedKey], list[int]]:
    calls: list[int] = []
    queue: Iterator[GeneratedKey] = iter(keys)

    def generate() -> GeneratedKey:
        calls.append(1)
        return next(queue, None) or generate_key()

    return generate, calls


def test_prefix_collision_is_retried_inside_a_savepoint(db_session: Session) -> None:
    existing = _admin(db_session)
    colliding = GeneratedKey(
        prefix=existing.key.prefix, value=f"secscan_{existing.key.prefix}_{'f' * 64}"
    )
    generate, calls = _generator(colliding)

    issued = ApiKeyService(db_session, generate=generate).issue_admin_key(
        name="second", expires_at=None, now=NOW
    )

    assert len(calls) == 2
    assert issued.key.prefix != existing.key.prefix
    assert ApiKeyService(db_session).authenticate(issued.value, now=NOW).key_id == issued.key.id


def test_repeated_collisions_give_up(db_session: Session) -> None:
    existing = _admin(db_session)
    colliding = GeneratedKey(
        prefix=existing.key.prefix, value=f"secscan_{existing.key.prefix}_{'f' * 64}"
    )
    generate, calls = _generator(*[colliding] * KEY_CREATE_ATTEMPTS)

    with pytest.raises(RuntimeError, match="重複"):
        ApiKeyService(db_session, generate=generate).issue_admin_key(
            name="never", expires_at=None, now=NOW
        )

    assert len(calls) == KEY_CREATE_ATTEMPTS


def test_admin_key_from_cli_is_audited_without_actor(db_session: Session) -> None:
    issued = _admin(db_session)

    row = db_session.execute(
        text(
            "SELECT actor_key_id, project_id, object_id, redacted_changes FROM audit_events "
            "WHERE object_id = :id"
        ),
        {"id": issued.key.id},
    ).one()

    assert issued.key.role is Role.PLATFORM_ADMIN
    assert (row.actor_key_id, row.project_id, row.object_id) == (None, None, issued.key.id)
    assert row.redacted_changes["source"] == "cli"
    assert row.redacted_changes["role"] == "platform_admin"


# --- 撤銷 -----------------------------------------------------------------------------------


def test_revoke_is_idempotent_and_audited_once(db_session: Session) -> None:
    project_id = _project(db_session)
    admin = Principal.of(_admin(db_session).key)
    viewer = _member(db_session, Role.VIEWER, project_id)
    service = ApiKeyService(db_session)

    service.revoke(admin, viewer.key.id, request_id="1" * 32)
    service.revoke(admin, viewer.key.id, request_id="2" * 32)

    revocations = [e for e in _events(db_session, project_id) if e["action"] == "api_key.revoke"]
    assert revocations == [
        {
            "action": "api_key.revoke",
            "actor": admin.key_id,
            "changes": {"role": "viewer", "prefix": viewer.key.prefix},
        }
    ]


def test_revoking_a_missing_key_is_not_found(db_session: Session) -> None:
    admin = Principal.of(_admin(db_session).key)

    with pytest.raises(AppError) as caught:
        ApiKeyService(db_session).revoke(admin, uuid4(), request_id=None)

    assert caught.value.status_code == 404


def test_only_platform_admin_revokes_keys(db_session: Session) -> None:
    project_id = _project(db_session)
    operator = Principal.of(_member(db_session, Role.OPERATOR, project_id).key)
    victim = _member(db_session, Role.VIEWER, project_id)

    with pytest.raises(AppError) as caught:
        ApiKeyService(db_session).revoke(operator, victim.key.id, request_id=None)

    assert (caught.value.status_code, caught.value.code) == (403, ErrorCode.ROLE_NOT_ALLOWED)


def test_audit_changes_are_masked_before_they_are_stored(db_session: Session) -> None:
    """名稱剛好貼上了一把 key：audit 裡只會看到遮罩後的值。"""
    project_id = _project(db_session)
    pasted = generate_key().value

    _member(db_session, Role.VIEWER, project_id, name=f"oops {pasted}")

    [event] = _events(db_session, project_id)
    changes = event["changes"]
    assert isinstance(changes, dict)
    assert changes["name"] == f"oops {REDACTED}"
