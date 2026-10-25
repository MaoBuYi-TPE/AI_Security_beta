"""AuthProfileService：建立、新版本、查詢、權限與金鑰換版（docs/DECISIONS.md §12）。

在交易內執行，結束時回滾。權限先於驗證；service 只加密、不解密（測試以共用的金鑰解開確認）。
"""

import json
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text
from sqlalchemy.orm import Session

from secscan.api_keys.domain import Principal
from secscan.auth_profiles.domain.credentials import AuthType, Credential, SecretValue
from secscan.auth_profiles.domain.model import (
    AuthProfile,
    ChangeInput,
    NewAuthProfile,
    PreflightInput,
    ProfileInput,
    secret_context,
)
from secscan.auth_profiles.repository import AuthProfileRepository
from secscan.auth_profiles.service import (
    MAX_PROFILES_PER_TARGET,
    MAX_VERSIONS_PER_PROFILE,
    AuthProfileService,
    SecretRotationError,
)
from secscan.core.db import ConstraintViolationError
from secscan.core.errors import ErrorCode
from secscan.core.pagination import PageRequest
from secscan.security.secret_cipher import SecretCipher, SecretUnreadableError
from secscan.targets.domain import Target, TargetKind, TargetUpdate
from secscan.targets.repository import TargetRepository
from secscan.targets.service import TargetService
from tests.integration.scope_support import LAB, VAMPI, Members, app_error, members, same_response
from tests.secret_support import bearer_context, shared_cipher

pytestmark = pytest.mark.integration

NOW = datetime.now(UTC)
ALL = PageRequest(limit=100)
REQUEST_ID = "a" * 32
CANARY = "canary-t08-service-7f3a"
ME = PreflightInput(
    method="GET",
    path="/me",
    expected_status=200,
    expected_json={"/data/username": "name1", "/status": "success"},
)


@pytest.fixture
def team(db_session: Session) -> Members:
    return members(db_session, NOW)


@pytest.fixture
def target(db_session: Session, team: Members) -> Target:
    return _target(db_session, team.operator_a, team.project_a)


def _target(
    session: Session, principal: Principal, project_id: UUID, base_url: str = VAMPI
) -> Target:
    return TargetService(session, lab=LAB).create(
        principal, project_id, name="VAmPI", kind=TargetKind.API, base_url=base_url, request_id=None
    )


def _service(session: Session, cipher: SecretCipher | None = None) -> AuthProfileService:
    return AuthProfileService(session, cipher=cipher if cipher is not None else shared_cipher())


def _input(**overrides: object) -> ProfileInput:
    params: dict[str, object] = {
        "name": "VAmPI 一般使用者",
        "role_label": "standard_user",
        "type": AuthType.BEARER,
        "header_name": None,
        "secret": SecretValue(CANARY),
        "preflight": ME,
    }
    params.update(overrides)
    return ProfileInput(**params)  # type: ignore[arg-type]


def _create(
    session: Session, principal: Principal, target_id: UUID, **overrides: object
) -> AuthProfile:
    return _service(session).create(
        principal, target_id, _input(**overrides), request_id=REQUEST_ID
    )


def _update(
    session: Session, principal: Principal, profile_id: UUID, change: ChangeInput
) -> AuthProfile:
    return _service(session).update(principal, profile_id, change, request_id=REQUEST_ID)


def _ciphertext(session: Session, profile_id: UUID, version: int) -> bytes | None:
    value = session.execute(
        text(
            "SELECT encrypted_secret FROM auth_profile_versions "
            "WHERE profile_id = :id AND version = :version"
        ),
        {"id": profile_id, "version": version},
    ).scalar()
    assert value is None or isinstance(value, bytes)
    return value


def _audit(session: Session, object_id: UUID) -> list[tuple[str, dict[str, object]]]:
    rows = session.execute(
        text(
            "SELECT action, redacted_changes FROM audit_events "
            "WHERE object_id = :id ORDER BY created_at"
        ),
        {"id": object_id},
    )
    return [(row.action, row.redacted_changes) for row in rows]


def _profile_count(session: Session, target_id: UUID) -> int:
    count = session.execute(
        text("SELECT count(*) FROM auth_profiles WHERE target_id = :id"), {"id": target_id}
    ).scalar()
    assert isinstance(count, int)
    return count


# --- 建立 -----------------------------------------------------------------------------------


def test_create_encrypts_the_secret_bound_to_the_profile(
    db_session: Session, team: Members, target: Target
) -> None:
    profile = _create(db_session, team.operator_a, target.id)

    assert (profile.target_id, profile.project_id, profile.role_label) == (
        target.id,
        team.project_a,
        "standard_user",
    )
    assert (profile.current.version, profile.current.secret_configured) == (1, True)
    assert profile.current.definition.preflight.path == "/me"
    token = _ciphertext(db_session, profile.id, 1)
    assert token is not None
    assert CANARY.encode() not in token
    assert shared_cipher().reveal(token, context=bearer_context(profile.id)) == CANARY
    with pytest.raises(SecretUnreadableError):
        shared_cipher().reveal(token, context=bearer_context(uuid4()))


def test_create_records_an_audit_event_without_secrets_or_expected_values(
    db_session: Session, team: Members, target: Target
) -> None:
    profile = _create(db_session, team.operator_a, target.id)

    [(action, changes)] = _audit(db_session, profile.id)

    assert action == "auth_profile.create"
    assert changes == {
        "target_id": str(target.id),
        "name": "VAmPI 一般使用者",
        "role_label": "standard_user",
        "version": 1,
        "type": "bearer",
        "header_name": None,
        "preflight": {
            "method": "GET",
            "path": "/me",
            "expected_status": 200,
            "pointers": ["/data/username", "/status"],
        },
    }
    assert CANARY not in json.dumps(changes)
    assert "name1" not in json.dumps(changes)


def test_api_key_header_profiles_keep_the_header_name(
    db_session: Session, team: Members, target: Target
) -> None:
    profile = _create(
        db_session,
        team.operator_a,
        target.id,
        type=AuthType.API_KEY_HEADER,
        header_name="X-API-Key",
        secret=SecretValue("Token abc"),
    )

    assert profile.current.definition.credential.header_name == "X-API-Key"


def test_only_writers_of_the_project_can_create(
    db_session: Session, team: Members, target: Target
) -> None:
    viewer = app_error(lambda: _create(db_session, team.viewer_a, target.id))
    other = app_error(lambda: _create(db_session, team.operator_b, target.id))
    unknown = app_error(lambda: _create(db_session, team.operator_a, uuid4()))

    assert (viewer.status_code, viewer.code) == (403, ErrorCode.ROLE_NOT_ALLOWED)
    assert (other.status_code, other.code) == (404, ErrorCode.RESOURCE_NOT_FOUND)
    assert same_response(other, unknown)
    assert (
        _create(db_session, team.admin, target.id, role_label="admin").project_id == team.project_a
    )


def test_validation_happens_after_the_permission_check(
    db_session: Session, team: Members, target: Target
) -> None:
    invalid = {"secret": SecretValue(f"Bearer {CANARY}")}

    assert (
        app_error(lambda: _create(db_session, team.viewer_a, target.id, **invalid)).status_code
        == 403
    )
    assert (
        app_error(lambda: _create(db_session, team.operator_b, target.id, **invalid)).status_code
        == 404
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"secret": SecretValue(f"Bearer {CANARY}")},
        {"secret": SecretValue(f"{CANARY}\r\nX-Injected: 1")},
        {"type": AuthType.API_KEY_HEADER, "header_name": "Host"},
        {"type": AuthType.COOKIE, "secret": SecretValue(f"a={CANARY}; a=2")},
        {"role_label": "anonymous"},
        {
            "preflight": PreflightInput(
                method="POST", path="/me", expected_status=200, expected_json={"/a": 1}
            )
        },
        {
            "preflight": PreflightInput(
                method="GET", path="/me", expected_status=200, expected_json={}
            )
        },
        {
            "preflight": PreflightInput(
                method="GET", path="/u/{id}", expected_status=200, expected_json={"/a": 1}
            )
        },
    ],
)
def test_invalid_input_is_rejected_without_writing_or_echoing(
    db_session: Session, team: Members, target: Target, overrides: dict[str, object]
) -> None:
    error = app_error(lambda: _create(db_session, team.operator_a, target.id, **overrides))

    assert (error.status_code, error.code) == (422, ErrorCode.INVALID_REQUEST)
    assert CANARY not in error.message
    assert _profile_count(db_session, target.id) == 0


def test_role_labels_are_unique_per_target(
    db_session: Session, team: Members, target: Target
) -> None:
    _create(db_session, team.operator_a, target.id)
    other_target = _target(db_session, team.operator_a, team.project_a, "http://vampi-secure:5000")

    # 實際的請求遇到錯誤會整個 rollback；這裡以 savepoint 隔離，之後還要用同一個 session。
    with db_session.begin_nested():
        error = app_error(lambda: _create(db_session, team.operator_a, target.id))

    assert (error.status_code, error.code) == (409, ErrorCode.AUTH_ROLE_CONFLICT)
    assert "uq_" not in error.message
    assert _create(db_session, team.operator_a, other_target.id).target_id == other_target.id


def test_profiles_per_target_are_limited(
    db_session: Session, team: Members, target: Target
) -> None:
    for index in range(MAX_PROFILES_PER_TARGET):
        _create(db_session, team.operator_a, target.id, role_label=f"user_{index}")

    error = app_error(lambda: _create(db_session, team.operator_a, target.id, role_label="extra"))

    assert (error.status_code, error.code) == (409, ErrorCode.QUOTA_EXCEEDED)
    assert _profile_count(db_session, target.id) == MAX_PROFILES_PER_TARGET


def test_disabled_targets_can_still_be_configured(
    db_session: Session, team: Members, target: Target
) -> None:
    """設定不會送出任何流量；能不能掃描由掃描 gate 判斷。"""
    TargetService(db_session, lab=LAB).update(
        team.operator_a, target.id, TargetUpdate(enabled=False), request_id=None
    )

    assert _create(db_session, team.operator_a, target.id).current.version == 1


# --- 新版本 ---------------------------------------------------------------------------------


def test_a_new_secret_erases_the_previous_one(
    db_session: Session, team: Members, target: Target
) -> None:
    profile = _create(db_session, team.operator_a, target.id)

    updated = _update(
        db_session, team.operator_a, profile.id, ChangeInput(secret=SecretValue("t2"))
    )

    assert (updated.current.version, updated.current.secret_configured) == (2, True)
    assert _ciphertext(db_session, profile.id, 1) is None
    token = _ciphertext(db_session, profile.id, 2)
    assert token is not None
    assert shared_cipher().reveal(token, context=bearer_context(profile.id)) == "t2"
    [_, (action, changes)] = _audit(db_session, profile.id)
    assert action == "auth_profile.update"
    assert changes == {"version": 2, "erased_version": 1, "changed": ["secret"]}


def test_a_new_preflight_copies_the_ciphertext(
    db_session: Session, team: Members, target: Target
) -> None:
    """沿用 secret 時直接複製密文（逐 byte 相同），service 不解密。"""
    profile = _create(db_session, team.operator_a, target.id)
    original = _ciphertext(db_session, profile.id, 1)
    preflight = PreflightInput(
        method="GET",
        path="/users/v1/name1",
        expected_status=200,
        expected_json={"/username": "name1"},
    )

    updated = _update(db_session, team.operator_a, profile.id, ChangeInput(preflight=preflight))

    assert updated.current.definition.preflight.path == "/users/v1/name1"
    assert _ciphertext(db_session, profile.id, 2) == original
    assert _ciphertext(db_session, profile.id, 1) is None
    [_, (_, changes)] = _audit(db_session, profile.id)
    assert changes == {
        "version": 2,
        "erased_version": 1,
        "changed": ["preflight"],
        "preflight": {
            "method": "GET",
            "path": "/users/v1/name1",
            "expected_status": 200,
            "pointers": ["/username"],
        },
    }


def test_changing_the_type_records_the_new_credential(
    db_session: Session, team: Members, target: Target
) -> None:
    profile = _create(db_session, team.operator_a, target.id)
    change = ChangeInput(
        type=AuthType.API_KEY_HEADER, header_name="X-Token", secret=SecretValue("k")
    )

    updated = _update(db_session, team.operator_a, profile.id, change)

    assert updated.current.definition.credential.header_name == "X-Token"
    [_, (_, changes)] = _audit(db_session, profile.id)
    assert changes == {
        "version": 2,
        "erased_version": 1,
        "changed": ["type", "header_name", "secret"],
        "type": "api_key_header",
        "header_name": "X-Token",
    }


@pytest.mark.parametrize(
    ("change", "fragment"),
    [
        (ChangeInput(), "至少"),
        (ChangeInput(preflight=ME), "沒有任何變更"),
        (ChangeInput(type=AuthType.COOKIE), "新的 secret"),
        (ChangeInput(secret=SecretValue(f"Bearer {CANARY}")), "secret"),
    ],
)
def test_patch_rules_are_enforced(
    db_session: Session, team: Members, target: Target, change: ChangeInput, fragment: str
) -> None:
    profile = _create(db_session, team.operator_a, target.id)

    error = app_error(lambda: _update(db_session, team.operator_a, profile.id, change))

    assert (error.status_code, error.code) == (422, ErrorCode.INVALID_REQUEST)
    assert fragment in error.message
    assert CANARY not in error.message
    assert _ciphertext(db_session, profile.id, 1) is not None


def test_only_writers_of_the_project_can_make_new_versions(
    db_session: Session, team: Members, target: Target
) -> None:
    profile = _create(db_session, team.operator_a, target.id)
    change = ChangeInput(secret=SecretValue("t2"))

    viewer = app_error(lambda: _update(db_session, team.viewer_a, profile.id, change))
    other = app_error(lambda: _update(db_session, team.operator_b, profile.id, change))
    unknown = app_error(lambda: _update(db_session, team.operator_a, uuid4(), change))
    invalid = ChangeInput(secret=SecretValue(f"Bearer {CANARY}"))

    assert (viewer.status_code, viewer.code) == (403, ErrorCode.ROLE_NOT_ALLOWED)
    assert same_response(other, unknown)
    assert (
        app_error(lambda: _update(db_session, team.viewer_a, profile.id, invalid)).status_code
        == 403
    )
    assert _update(db_session, team.admin, profile.id, change).current.version == 2


def test_versions_per_profile_are_limited(
    db_session: Session, team: Members, target: Target
) -> None:
    profile = _create(db_session, team.operator_a, target.id)
    for index in range(2, MAX_VERSIONS_PER_PROFILE + 1):
        _update(
            db_session, team.operator_a, profile.id, ChangeInput(secret=SecretValue(f"t{index}"))
        )

    error = app_error(
        lambda: _update(
            db_session, team.operator_a, profile.id, ChangeInput(secret=SecretValue("x"))
        )
    )

    assert (error.status_code, error.code) == (409, ErrorCode.QUOTA_EXCEEDED)
    latest = _service(db_session).get(team.operator_a, profile.id)
    assert latest.current.version == MAX_VERSIONS_PER_PROFILE


def test_a_missing_current_secret_needs_a_new_one(
    db_session: Session, team: Members, target: Target
) -> None:
    """只有直接改 DB 才會發生（trigger 允許清除）：沿用不到 secret，就要附上新的。"""
    profile = _create(db_session, team.operator_a, target.id)
    db_session.execute(
        text(
            "UPDATE auth_profile_versions SET encrypted_secret = NULL, secret_erased_at = now() "
            "WHERE profile_id = :id"
        ),
        {"id": profile.id},
    )
    preflight = PreflightInput(
        method="GET", path="/me", expected_status=201, expected_json={"/a": 1}
    )

    error = app_error(
        lambda: _update(db_session, team.operator_a, profile.id, ChangeInput(preflight=preflight))
    )

    assert (error.status_code, error.code) == (409, ErrorCode.INVALID_STATE_TRANSITION)
    assert _update(
        db_session, team.operator_a, profile.id, ChangeInput(secret=SecretValue("t2"))
    ).current.secret_configured


def test_an_invalid_preflight_in_a_change_is_rejected(
    db_session: Session, team: Members, target: Target
) -> None:
    profile = _create(db_session, team.operator_a, target.id)
    preflight = PreflightInput(
        method="GET", path="me", expected_status=200, expected_json={"/a": 1}
    )

    error = app_error(
        lambda: _update(db_session, team.operator_a, profile.id, ChangeInput(preflight=preflight))
    )

    assert (error.status_code, error.code) == (422, ErrorCode.INVALID_REQUEST)
    assert "preflight.path" in error.message


def test_a_target_vanishing_before_the_lock_looks_missing(
    db_session: Session, team: Members, target: Target, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(TargetRepository, "lock", lambda *_args, **_kwargs: None)

    error = app_error(lambda: _create(db_session, team.operator_a, target.id))

    assert (error.status_code, error.code) == (404, ErrorCode.RESOURCE_NOT_FOUND)


def test_a_profile_vanishing_before_the_lock_looks_missing(
    db_session: Session, team: Members, target: Target, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _create(db_session, team.operator_a, target.id)
    monkeypatch.setattr(AuthProfileRepository, "lock", lambda *_args, **_kwargs: None)

    error = app_error(
        lambda: _update(
            db_session, team.operator_a, profile.id, ChangeInput(secret=SecretValue("t"))
        )
    )

    assert (error.status_code, error.code) == (404, ErrorCode.RESOURCE_NOT_FOUND)


def test_unknown_constraint_violations_are_not_mapped(
    db_session: Session, team: Members, target: Target, monkeypatch: pytest.MonkeyPatch
) -> None:
    def violate(_self: AuthProfileRepository, _profile: NewAuthProfile) -> UUID:
        raise ConstraintViolationError("ck_auth_profiles_something_new", "23514")

    monkeypatch.setattr(AuthProfileRepository, "create", violate)

    with pytest.raises(ConstraintViolationError):
        _create(db_session, team.operator_a, target.id)


def test_a_profile_that_cannot_be_read_back_is_an_error(
    db_session: Session, team: Members, target: Target, monkeypatch: pytest.MonkeyPatch
) -> None:
    """剛寫入卻讀不到只可能是程式錯誤：回 500，不回一個空的成功回應。"""
    monkeypatch.setattr(AuthProfileRepository, "get", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(AuthProfileService, "_target", lambda *_args, **_kwargs: target)

    with pytest.raises(RuntimeError):
        _create(db_session, team.operator_a, target.id)


# --- 查詢 -----------------------------------------------------------------------------------


def test_profiles_and_versions_can_be_read_by_the_project(
    db_session: Session, team: Members, target: Target
) -> None:
    first = _create(db_session, team.operator_a, target.id, role_label="user_a")
    second = _create(db_session, team.operator_a, target.id, role_label="user_b")
    _update(db_session, team.operator_a, second.id, ChangeInput(secret=SecretValue("t2")))
    service = _service(db_session)

    listed = service.list_for_target(team.viewer_a, target.id, ALL)
    versions = service.versions(team.viewer_a, second.id, ALL)

    assert {profile.id for profile in listed.items} == {first.id, second.id}
    assert listed.total == 2
    assert service.get(team.viewer_a, second.id).current.version == 2
    assert [version.version for version in versions.items] == [2, 1]
    assert [version.secret_configured for version in versions.items] == [True, False]


def test_other_projects_cannot_read_profiles(
    db_session: Session, team: Members, target: Target
) -> None:
    profile = _create(db_session, team.operator_a, target.id)
    service = _service(db_session)
    unknown = app_error(lambda: service.get(team.operator_b, uuid4()))

    for call in (
        lambda: service.get(team.operator_b, profile.id),
        lambda: service.versions(team.operator_b, profile.id, ALL),
        lambda: service.list_for_target(team.operator_b, target.id, ALL),
        lambda: service.versions(team.operator_a, uuid4(), ALL),
        lambda: service.list_for_target(team.operator_a, uuid4(), ALL),
    ):
        assert same_response(app_error(call), unknown)


# --- 金鑰換版 -------------------------------------------------------------------------------


def _key() -> str:
    return Fernet.generate_key().decode()


def test_reencrypt_moves_every_live_secret_to_the_first_key(
    db_session: Session, team: Members, target: Target
) -> None:
    old, new = _key(), _key()
    old_cipher = SecretCipher.from_setting(old)
    first = _service(db_session, old_cipher).create(
        team.operator_a, target.id, _input(role_label="user_a"), request_id=None
    )
    second = _service(db_session, old_cipher).create(
        team.operator_a, target.id, _input(role_label="user_b"), request_id=None
    )
    _service(db_session, old_cipher).update(
        team.operator_a, second.id, ChangeInput(secret=SecretValue("t2")), request_id=None
    )

    count = _service(db_session, SecretCipher.from_setting(f"{new},{old}")).reencrypt_secrets()

    assert count == 2
    only_new = SecretCipher.from_setting(new)
    for profile_id, version, value in ((first.id, 1, CANARY), (second.id, 2, "t2")):
        token = _ciphertext(db_session, profile_id, version)
        assert token is not None
        assert only_new.reveal(token, context=bearer_context(profile_id)) == value
    assert _ciphertext(db_session, second.id, 1) is None
    [event] = db_session.execute(
        text(
            "SELECT action, object_type, project_id, actor_key_id, redacted_changes "
            "FROM audit_events WHERE action = 'auth_secrets.reencrypt'"
        )
    ).all()
    assert (event.object_type, event.project_id, event.actor_key_id) == (
        "auth_profile_version",
        None,
        None,
    )
    assert event.redacted_changes == {"reencrypted": 2}


def test_reencrypt_writes_nothing_when_a_secret_cannot_be_read(
    db_session: Session, team: Members, target: Target
) -> None:
    old = SecretCipher.from_setting(_key())
    profile = _service(db_session, old).create(
        team.operator_a, target.id, _input(), request_id=None
    )
    before = _ciphertext(db_session, profile.id, 1)

    with pytest.raises(SecretRotationError) as raised:
        _service(db_session, SecretCipher.from_setting(_key())).reencrypt_secrets()

    assert raised.value.profile_ids == (profile.id,)
    assert _ciphertext(db_session, profile.id, 1) == before


def test_reencrypt_detects_a_ciphertext_moved_to_another_profile(
    db_session: Session, team: Members, target: Target
) -> None:
    """trigger 允許「換成另一份密文」：能寫 DB 的人把 A 的密文搬到 B，換版時就會發現。"""
    first = _create(db_session, team.operator_a, target.id, role_label="user_a")
    second = _create(db_session, team.operator_a, target.id, role_label="user_b")
    db_session.execute(
        text(
            "UPDATE auth_profile_versions SET encrypted_secret = "
            "(SELECT encrypted_secret FROM auth_profile_versions WHERE profile_id = :source) "
            "WHERE profile_id = :victim"
        ),
        {"source": first.id, "victim": second.id},
    )

    with pytest.raises(SecretRotationError) as raised:
        _service(db_session).reencrypt_secrets()

    assert raised.value.profile_ids == (second.id,)


def test_reencrypt_detects_a_ciphertext_moved_to_another_credential(
    db_session: Session, team: Members, target: Target
) -> None:
    """審查發現：能寫 DB 的人可以清除 v1、再插入沿用 v1 密文的 v2，改成另一個 header 送出。
    context 綁定送出方式之後，這份密文在新的送出方式下解不開，換版時就會發現。"""
    profile = _create(db_session, team.operator_a, target.id)
    token = _ciphertext(db_session, profile.id, 1)
    db_session.execute(
        text(
            "UPDATE auth_profile_versions SET encrypted_secret = NULL, secret_erased_at = now() "
            "WHERE profile_id = :id AND version = 1"
        ),
        {"id": profile.id},
    )
    db_session.execute(
        text(
            "INSERT INTO auth_profile_versions (profile_id, version, type, header_name, "
            "preflight_method, preflight_path, preflight_expected_status, "
            "preflight_expected_json, encrypted_secret, created_by_key_id) "
            "VALUES (:id, 2, 'api_key_header', 'X-Echo-Me', 'GET', '/debug/headers', 200, "
            "'{\"/a\": 1}', :token, :key)"
        ),
        {"id": profile.id, "token": token, "key": team.operator_a.key_id},
    )
    moved = _ciphertext(db_session, profile.id, 2)
    assert moved is not None
    echo = Credential(AuthType.API_KEY_HEADER, header_name="X-Echo-Me")

    with pytest.raises(SecretUnreadableError):
        shared_cipher().reveal(moved, context=secret_context(profile.id, echo))
    with pytest.raises(SecretRotationError) as raised:
        _service(db_session).reencrypt_secrets()

    assert raised.value.profile_ids == (profile.id,)


def test_a_read_only_service_cannot_write(
    db_session: Session, team: Members, target: Target
) -> None:
    """查詢的端點不拿 cipher（最小權限）；誤用它來寫入時，在動到 DB 之前就失敗。"""
    profile = _create(db_session, team.operator_a, target.id)
    read_only = AuthProfileService(db_session)

    with pytest.raises(RuntimeError, match="cipher"):
        read_only.create(team.operator_a, target.id, _input(role_label="other"), request_id=None)
    with pytest.raises(RuntimeError, match="cipher"):
        read_only.update(
            team.operator_a, profile.id, ChangeInput(secret=SecretValue("t")), request_id=None
        )
    with pytest.raises(RuntimeError, match="cipher"):
        read_only.reencrypt_secrets()

    assert _profile_count(db_session, target.id) == 1
    assert read_only.get(team.viewer_a, profile.id).current.version == 1
