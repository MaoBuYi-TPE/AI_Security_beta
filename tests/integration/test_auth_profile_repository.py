"""auth profile 的 repository：回傳 frozen domain model；版本的密文只在需要時讀出。"""

from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from secscan.auth_profiles.domain.credentials import AuthType, Credential
from secscan.auth_profiles.domain.errors import InvalidAuthProfileError
from secscan.auth_profiles.domain.model import (
    NewAuthProfile,
    NewProfileVersion,
    ProfileDefinition,
    secret_context,
)
from secscan.auth_profiles.domain.preflight import Preflight
from secscan.auth_profiles.repository import AuthProfileRepository
from secscan.core.db import ConstraintViolationError
from secscan.core.pagination import PageRequest
from secscan.projects.domain import NewProject
from secscan.projects.repository import ProjectRepository
from secscan.targets.domain import NewTarget, Target, TargetKind, parse_origin
from secscan.targets.repository import TargetRepository
from tests.integration.sql_support import insert_key
from tests.secret_support import shared_cipher

pytestmark = pytest.mark.integration

ORIGIN = parse_origin("http://vampi-vuln:5000")
ME = Preflight(
    method="GET",
    path="/me",
    expected_status=200,
    expected_json={"/data/username": "name1", "/data/admin": False, "/status": "success"},
)
BEARER = ProfileDefinition(credential=Credential(AuthType.BEARER), preflight=ME)
API_KEY = ProfileDefinition(
    credential=Credential(AuthType.API_KEY_HEADER, header_name="X-API-Key"), preflight=ME
)


def _target(session: Session) -> Target:
    project = ProjectRepository(session).create(NewProject(name=f"lab-{uuid4().hex[:8]}"))
    return TargetRepository(session).create(
        NewTarget(project_id=project.id, name="VAmPI", kind=TargetKind.API, origin=ORIGIN)
    )


def _version(
    profile_id: UUID, key_id: UUID, definition: ProfileDefinition = BEARER, value: str = "t1"
) -> NewProfileVersion:
    token = shared_cipher().seal(value, context=secret_context(profile_id, definition.credential))
    return NewProfileVersion(
        definition=definition, encrypted_secret=token, created_by_key_id=key_id
    )


def _create(
    repository: AuthProfileRepository, target: Target, key_id: UUID, role: str = "standard_user"
) -> UUID:
    profile_id = repository.create(
        NewAuthProfile(
            target_id=target.id, name="一般使用者", role_label=role, created_by_key_id=key_id
        )
    )
    repository.add_version(profile_id, version=1, new_version=_version(profile_id, key_id))
    return profile_id


def _stored_secret(session: Session, profile_id: UUID, version: int) -> bytes | None:
    value = session.execute(
        text(
            "SELECT encrypted_secret FROM auth_profile_versions "
            "WHERE profile_id = :id AND version = :version"
        ),
        {"id": profile_id, "version": version},
    ).scalar()
    assert value is None or isinstance(value, bytes)
    return value


def test_create_and_read_a_profile_with_its_first_version(db_session: Session) -> None:
    target, key_id = _target(db_session), insert_key(db_session)
    repository = AuthProfileRepository(db_session)

    profile_id = _create(repository, target, key_id)
    profile = repository.get(profile_id)

    assert profile is not None
    assert (profile.id, profile.target_id, profile.project_id) == (
        profile_id,
        target.id,
        target.project_id,
    )
    assert (profile.name, profile.role_label, profile.created_by_key_id) == (
        "一般使用者",
        "standard_user",
        key_id,
    )
    assert profile.created_at.tzinfo is not None
    current = profile.current
    assert (current.profile_id, current.version, current.definition) == (profile_id, 1, BEARER)
    assert (current.secret_configured, current.secret_erased_at) == (True, None)
    assert current.created_by_key_id == key_id
    token = _stored_secret(db_session, profile_id, 1)
    assert token is not None
    assert (
        shared_cipher().reveal(token, context=secret_context(profile_id, BEARER.credential)) == "t1"
    )


def test_expected_values_keep_their_json_types(db_session: Session) -> None:
    """jsonb 讀回來仍是 false（不是 0）：比對語意要求型別相同。"""
    target, key_id = _target(db_session), insert_key(db_session)
    repository = AuthProfileRepository(db_session)

    profile = repository.get(_create(repository, target, key_id))

    assert profile is not None
    assert profile.current.definition.preflight.expected_json["/data/admin"] is False


def test_unknown_profiles_are_not_found(db_session: Session) -> None:
    repository = AuthProfileRepository(db_session)

    assert repository.get(uuid4()) is None
    assert repository.lock(uuid4()) is None


def test_role_labels_are_unique_per_target(db_session: Session) -> None:
    target, key_id = _target(db_session), insert_key(db_session)
    repository = AuthProfileRepository(db_session)
    _create(repository, target, key_id)

    with pytest.raises(ConstraintViolationError) as raised, db_session.begin_nested():
        repository.create(
            NewAuthProfile(
                target_id=target.id,
                name="又一個",
                role_label="standard_user",
                created_by_key_id=key_id,
            )
        )

    assert raised.value.constraint == "uq_auth_profiles_target_id_role_label"


def test_a_new_version_after_erasing_the_previous_secret(db_session: Session) -> None:
    target, key_id = _target(db_session), insert_key(db_session)
    repository = AuthProfileRepository(db_session)
    profile_id = _create(repository, target, key_id)

    repository.erase_secret(profile_id, version=1)
    repository.add_version(
        profile_id, version=2, new_version=_version(profile_id, key_id, API_KEY, "t2")
    )

    profile = repository.get(profile_id)
    assert profile is not None
    assert (profile.current.version, profile.current.definition) == (2, API_KEY)
    page = repository.list_versions(profile_id, PageRequest(page=1, limit=10))
    assert [version.version for version in page.items] == [2, 1]
    assert [version.secret_configured for version in page.items] == [True, False]
    assert page.items[1].secret_erased_at is not None
    assert page.total == 2
    assert _stored_secret(db_session, profile_id, 1) is None


def test_the_previous_secret_must_be_erased_first(db_session: Session) -> None:
    target, key_id = _target(db_session), insert_key(db_session)
    repository = AuthProfileRepository(db_session)
    profile_id = _create(repository, target, key_id)

    with pytest.raises(ConstraintViolationError) as raised, db_session.begin_nested():
        repository.add_version(profile_id, version=2, new_version=_version(profile_id, key_id))

    assert raised.value.constraint == "uq_auth_profile_versions_live_secret"


def test_current_secret_is_read_under_a_row_lock(db_session: Session) -> None:
    target, key_id = _target(db_session), insert_key(db_session)
    repository = AuthProfileRepository(db_session)
    profile_id = _create(repository, target, key_id)

    token = repository.current_secret_for_update(profile_id, version=1)

    assert token == _stored_secret(db_session, profile_id, 1)
    repository.erase_secret(profile_id, version=1)
    assert repository.current_secret_for_update(profile_id, version=1) is None


def test_lock_reads_the_profile_with_its_current_version(db_session: Session) -> None:
    target, key_id = _target(db_session), insert_key(db_session)
    repository = AuthProfileRepository(db_session)
    profile_id = _create(repository, target, key_id)

    assert repository.lock(profile_id) == repository.get(profile_id)


def test_profiles_are_listed_in_creation_order_with_their_current_version(
    db_session: Session,
) -> None:
    target, key_id = _target(db_session), insert_key(db_session)
    other = _target(db_session)
    repository = AuthProfileRepository(db_session)
    first = _create(repository, target, key_id, "user_a")
    second = _create(repository, target, key_id, "user_b")
    third = _create(repository, target, key_id, "admin")
    _create(repository, other, key_id, "user_a")
    repository.erase_secret(second, version=1)
    repository.add_version(second, version=2, new_version=_version(second, key_id, API_KEY))

    pages = [repository.list_by_target(target.id, PageRequest(page=n, limit=2)) for n in (1, 2)]

    listed = [profile for page in pages for profile in page.items]
    # 同一個 transaction 建立的時間相同（now() 是 transaction 開始的時間），再依 id 排序。
    assert listed == sorted(listed, key=lambda profile: (profile.created_at, profile.id))
    assert {profile.id for profile in listed} == {first, second, third}
    versions = {profile.id: profile.current for profile in listed}
    assert [versions[profile_id].version for profile_id in (first, second, third)] == [1, 2, 1]
    assert versions[second].definition == API_KEY
    assert [page.total for page in pages] == [3, 3]
    assert repository.count_for_target(target.id) == 3


def test_live_secrets_are_listed_for_reencryption(db_session: Session) -> None:
    target, key_id = _target(db_session), insert_key(db_session)
    repository = AuthProfileRepository(db_session)
    profile_id = _create(repository, target, key_id)
    repository.erase_secret(profile_id, version=1)
    repository.add_version(profile_id, version=2, new_version=_version(profile_id, key_id))

    mine = [stored for stored in repository.secrets_for_update() if stored.profile_id == profile_id]

    assert [(stored.profile_id, stored.version) for stored in mine] == [(profile_id, 2)]
    assert mine[0].token == _stored_secret(db_session, profile_id, 2)
    assert mine[0].token.decode() not in repr(mine[0])


def test_replace_secret_stores_the_new_token(db_session: Session) -> None:
    target, key_id = _target(db_session), insert_key(db_session)
    repository = AuthProfileRepository(db_session)
    profile_id = _create(repository, target, key_id)
    new_token = shared_cipher().seal("t1", context=secret_context(profile_id, BEARER.credential))

    repository.replace_secret(profile_id, version=1, token=new_token)

    assert _stored_secret(db_session, profile_id, 1) == new_token


def test_rows_that_break_the_domain_rules_fail_closed(db_session: Session) -> None:
    """DB 的 CHECK 只檢查 header 名稱的字元；拒絕清單在 domain，讀出時再檢查一次。"""
    target, key_id = _target(db_session), insert_key(db_session)
    repository = AuthProfileRepository(db_session)
    profile_id = repository.create(
        NewAuthProfile(target_id=target.id, name="x", role_label="x", created_by_key_id=key_id)
    )
    db_session.execute(
        text(
            "INSERT INTO auth_profile_versions (profile_id, version, type, header_name, "
            "preflight_method, preflight_path, preflight_expected_status, "
            "preflight_expected_json, encrypted_secret, created_by_key_id) VALUES "
            "(:id, 1, 'api_key_header', 'Host', 'GET', '/me', 200, '{\"/a\": 1}', :token, :key)"
        ),
        {"id": profile_id, "token": _version(profile_id, key_id).encrypted_secret, "key": key_id},
    )

    with pytest.raises(InvalidAuthProfileError):
        repository.get(profile_id)
