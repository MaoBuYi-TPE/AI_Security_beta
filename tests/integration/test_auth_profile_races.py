"""併發：新版本連號、每個 profile 最多一份密文、PATCH 與金鑰換版互斥（docs/DECISIONS.md §12.3）。

互斥要兩個方向都成立：換版先拿到鎖時，PATCH 等它；PATCH 先拿到鎖時，換版等 PATCH commit，
再處理 PATCH 新增的版本。

做法同 test_spec_races.py：先到的在 transaction 中持有鎖，後到的在背景執行；以 pg_stat_activity 確認
後到的正在等列鎖，再讓先到的 commit。資料要真正 commit，所以使用 api_database。

金鑰換版會重新加密資料庫中所有的密文；api_database 由所有 API 測試共用，所以這裡用同一把測試金鑰
換版（其他測試的密文仍解得開），以「複製到的是換版後的那一份密文」確認 PATCH 有等換版。
"""

from collections.abc import Callable, Iterator
from uuid import UUID

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from secscan.auth_profiles.domain.credentials import AuthType, SecretValue
from secscan.auth_profiles.domain.model import (
    AuthProfile,
    ChangeInput,
    PreflightInput,
    ProfileInput,
)
from secscan.auth_profiles.service import MAX_PROFILES_PER_TARGET, AuthProfileService
from secscan.core.errors import AppError, ErrorCode
from tests.integration.api_support import VAMPI_ME, Seeder, World
from tests.integration.conftest import app_engine
from tests.integration.database import ProvisionedDatabase
from tests.integration.locks import Race, wait_until_waiting_for_a_lock
from tests.secret_support import bearer_context, shared_cipher

pytestmark = pytest.mark.integration

RACER = "secscan-auth-profile-racer"
OTHER_PREFLIGHT = PreflightInput(
    method="GET", path="/users/v1/name1", expected_status=200, expected_json={"/username": "name1"}
)


@pytest.fixture
def engine(api_database: ProvisionedDatabase) -> Iterator[Engine]:
    engine = app_engine(api_database)
    yield engine
    engine.dispose()


def _service(session: Session) -> AuthProfileService:
    return AuthProfileService(session, cipher=shared_cipher())


def _patch(world: World, profile_id: UUID, change: ChangeInput) -> Callable[[Session], AuthProfile]:
    def work(session: Session) -> AuthProfile:
        return _service(session).update(
            world.operator_a.principal, profile_id, change, request_id=None
        )

    return work


def _versions(seed: Seeder, profile_id: UUID) -> list[tuple[int, bytes | None]]:
    rows = seed.query(
        "SELECT version, encrypted_secret FROM auth_profile_versions "
        "WHERE profile_id = :id ORDER BY version",
        id=profile_id,
    )
    return [(row.version, row.encrypted_secret) for row in rows]


def test_concurrent_patches_get_consecutive_versions_and_one_secret(
    engine: Engine, api_database: ProvisionedDatabase, seed: Seeder, world: World
) -> None:
    target = seed.target(world.operator_a, world.project_a.id)
    profile = seed.auth_profile(world.operator_a, target)
    race = Race(
        api_database, RACER, _patch(world, profile.id, ChangeInput(secret=SecretValue("t3")))
    )

    with Session(engine, expire_on_commit=False) as holder, holder.begin():
        first = _patch(world, profile.id, ChangeInput(secret=SecretValue("t2")))(holder)
        race.start()
        wait_until_waiting_for_a_lock(seed, RACER)
    race.join()

    assert race.errors == []
    [second] = race.results
    assert (first.current.version, second.current.version) == (2, 3)
    versions = _versions(seed, profile.id)
    assert [(version, token is not None) for version, token in versions] == [
        (1, False),
        (2, False),
        (3, True),
    ]
    token = versions[2][1]
    assert token is not None
    assert shared_cipher().reveal(token, context=bearer_context(profile.id)) == "t3"


def test_a_patch_copying_the_secret_waits_for_key_rotation(
    engine: Engine, api_database: ProvisionedDatabase, seed: Seeder, world: World
) -> None:
    """沿用 secret 的 PATCH 先鎖住目前的版本列才讀密文；沒等換版的話，複製到的是換版前的密文，
    移除舊金鑰之後就解不開。"""
    target = seed.target(world.operator_a, world.project_a.id)
    profile = seed.auth_profile(world.operator_a, target)
    [(_, original)] = _versions(seed, profile.id)
    race = Race(
        api_database, RACER, _patch(world, profile.id, ChangeInput(preflight=OTHER_PREFLIGHT))
    )

    with Session(engine, expire_on_commit=False) as holder, holder.begin():
        _service(holder).reencrypt_secrets()
        rotated = holder.execute(
            text(
                "SELECT encrypted_secret FROM auth_profile_versions "
                "WHERE profile_id = :id AND version = 1"
            ),
            {"id": profile.id},
        ).scalar()
        race.start()
        wait_until_waiting_for_a_lock(seed, RACER)
    race.join()

    assert race.errors == []
    assert rotated not in (None, original)
    assert _versions(seed, profile.id) == [(1, None), (2, rotated)]


def test_key_rotation_waits_for_a_patch_copying_the_secret(
    engine: Engine, api_database: ProvisionedDatabase, seed: Seeder, world: World
) -> None:
    """審查發現：PATCH 先拿到鎖時，換版原本會略過已被清除的舊版本、又看不到 PATCH 新增的版本，
    卻回報成功；移除舊金鑰之後，新版本就解不開。換版必須等 PATCH commit，再處理新的版本。"""
    target = seed.target(world.operator_a, world.project_a.id)
    profile = seed.auth_profile(world.operator_a, target)
    [(_, original)] = _versions(seed, profile.id)

    def rotate(session: Session) -> int:
        return _service(session).reencrypt_secrets()

    race = Race(api_database, RACER, rotate)
    with Session(engine, expire_on_commit=False) as holder, holder.begin():
        _patch(world, profile.id, ChangeInput(preflight=OTHER_PREFLIGHT))(holder)
        race.start()
        wait_until_waiting_for_a_lock(seed, RACER)
    race.join()

    assert race.errors == []
    [(_, erased), (_, copied)] = _versions(seed, profile.id)
    assert erased is None
    # PATCH 複製進去的是 original；換版處理過的話，新版本的密文已經換掉。
    assert copied not in (None, original)
    assert shared_cipher().reveal(copied, context=bearer_context(profile.id)) == "t1"


def test_a_patch_copying_the_secret_waits_for_a_writer_of_the_version_row(
    engine: Engine, api_database: ProvisionedDatabase, seed: Seeder, world: World
) -> None:
    """換版已先鎖 profile，PATCH 在鎖 profile 時就會等它；版本列的鎖是第二道防線（突變檢查找到）：
    沒有先鎖 profile、只改版本列的寫入（例如直接以 SQL 重新加密），PATCH 也要等它，
    否則複製到的是舊的密文。"""
    target = seed.target(world.operator_a, world.project_a.id)
    profile = seed.auth_profile(world.operator_a, target)
    [(_, original)] = _versions(seed, profile.id)
    resealed = shared_cipher().seal("t1", context=bearer_context(profile.id))
    race = Race(
        api_database, RACER, _patch(world, profile.id, ChangeInput(preflight=OTHER_PREFLIGHT))
    )

    with Session(engine, expire_on_commit=False) as holder, holder.begin():
        holder.execute(
            text(
                "UPDATE auth_profile_versions SET encrypted_secret = :token "
                "WHERE profile_id = :id AND version = 1"
            ),
            {"token": resealed, "id": profile.id},
        )
        race.start()
        wait_until_waiting_for_a_lock(seed, RACER)
    race.join()

    assert race.errors == []
    assert resealed != original
    assert _versions(seed, profile.id) == [(1, None), (2, resealed)]


def test_an_erased_version_is_never_erased_before_it_was_created(
    engine: Engine, seed: Seeder, world: World
) -> None:
    """審查發現：清除時間原本是 transaction 開始的時間（now()）。先開始、後拿到鎖的 PATCH 清除
    別人剛建立的版本時，清除時間會早於建立時間。清除時間改成 UPDATE 實際執行的時間。"""
    target = seed.target(world.operator_a, world.project_a.id)
    profile = seed.auth_profile(world.operator_a, target)

    with Session(engine, expire_on_commit=False) as early, early.begin():
        early.execute(text("SELECT 1"))  # transaction 從這裡開始：now() 固定在這個時間
        with Session(engine, expire_on_commit=False) as late, late.begin():
            _patch(world, profile.id, ChangeInput(secret=SecretValue("t2")))(late)
        _patch(world, profile.id, ChangeInput(secret=SecretValue("t3")))(early)

    [row] = seed.query(
        "SELECT created_at, secret_erased_at FROM auth_profile_versions "
        "WHERE profile_id = :id AND version = 2",
        id=profile.id,
    )
    assert row.secret_erased_at >= row.created_at


def test_quota_holds_under_concurrent_creates(
    engine: Engine, api_database: ProvisionedDatabase, seed: Seeder, world: World
) -> None:
    """數量的計數在鎖住 target 之後：同時建立最後一個名額時，後到的看到已滿。"""
    target = seed.target(world.operator_a, world.project_a.id)
    for index in range(MAX_PROFILES_PER_TARGET - 1):
        seed.auth_profile(world.operator_a, target, role_label=f"user_{index}")

    def create(role_label: str) -> Callable[[Session], AuthProfile]:
        def work(session: Session) -> AuthProfile:
            return _service(session).create(
                world.operator_a.principal, target.id, _input(role_label), request_id=None
            )

        return work

    race = Race(api_database, RACER, create("late"))
    with Session(engine, expire_on_commit=False) as holder, holder.begin():
        create("first")(holder)
        race.start()
        wait_until_waiting_for_a_lock(seed, RACER)
    race.join()

    assert race.results == []
    [error] = race.errors
    assert isinstance(error, AppError)
    assert (error.status_code, error.code) == (409, ErrorCode.QUOTA_EXCEEDED)


def test_concurrent_creates_of_the_same_role_conflict(
    engine: Engine, api_database: ProvisionedDatabase, seed: Seeder, world: World
) -> None:
    target = seed.target(world.operator_a, world.project_a.id)

    def create(session: Session) -> AuthProfile:
        return _service(session).create(
            world.operator_a.principal, target.id, _input("standard_user"), request_id=None
        )

    race = Race(api_database, RACER, create)
    with Session(engine, expire_on_commit=False) as holder, holder.begin():
        create(holder)
        race.start()
        wait_until_waiting_for_a_lock(seed, RACER)
    race.join()

    [error] = race.errors
    assert isinstance(error, AppError)
    assert (error.status_code, error.code) == (409, ErrorCode.AUTH_ROLE_CONFLICT)


def _input(role_label: str) -> ProfileInput:
    return ProfileInput(
        name=f"profile {role_label}",
        role_label=role_label,
        type=AuthType.BEARER,
        header_name=None,
        secret=SecretValue("token"),
        preflight=VAMPI_ME,
    )
