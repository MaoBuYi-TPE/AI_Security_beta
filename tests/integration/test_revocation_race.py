"""撤銷時鎖住資料列，並以 DB 的最新值判斷是不是「這次撤銷」（docs/DECISIONS.md §9）。

用兩個獨立的連線：一個測同一個 session 先前已載入這把 key（populate_existing），
一個測兩個請求同時撤銷（SELECT … FOR UPDATE）。資料要真正 commit 才看得到，所以用 api_database。
"""

import threading
from collections.abc import Iterator

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from secscan.api_keys.domain import Revocation, Role
from secscan.api_keys.models import ApiKeyModel
from secscan.api_keys.repository import ApiKeyRepository
from secscan.core.db import create_db_engine
from tests.integration.api_support import Seeder, World
from tests.integration.conftest import app_engine
from tests.integration.database import ProvisionedDatabase
from tests.integration.locks import LOCK_WAIT_TIMEOUT_SECONDS, wait_until_waiting_for_a_lock

pytestmark = pytest.mark.integration

RACER_APPLICATION = "secscan-revoke-racer"


@pytest.fixture
def engine(api_database: ProvisionedDatabase) -> Iterator[Engine]:
    engine = app_engine(api_database)
    yield engine
    engine.dispose()


def test_revoke_reads_the_latest_row_even_if_the_key_is_already_loaded(
    engine: Engine, seed: Seeder, world: World
) -> None:
    """同一個 session 已載入這把 key，而且還有地方引用它：撤銷仍要以 DB 的最新值判斷。

    identity map 只弱參照 ORM 物件；沒有人引用時物件會被回收，下次查詢自然是新值。所以這裡
    刻意保留參照，模擬同一個請求中其他程式碼仍持有它的情況。
    """
    key_id = seed.member(world.admin, world.project_a.id, Role.VIEWER).principal.key_id

    with Session(engine) as stale, stale.begin():
        cached = stale.get(ApiKeyModel, key_id)
        assert cached is not None
        assert cached.revoked_at is None
        with Session(engine) as other, other.begin():
            first = ApiKeyRepository(other).revoke(key_id)
        again = ApiKeyRepository(stale).revoke(key_id)

    assert first is not None
    assert first.newly_revoked is True
    assert again is not None
    assert again.newly_revoked is False
    assert again.key.revoked_at == first.key.revoked_at


def test_concurrent_revocations_are_counted_once(
    engine: Engine, api_database: ProvisionedDatabase, seed: Seeder, world: World
) -> None:
    """第二個請求要等第一個 commit，然後看到已撤銷；不能兩個都算「這次撤銷」（audit 會重複）。"""
    key_id = seed.member(world.admin, world.project_a.id, Role.VIEWER).principal.key_id
    racer_engine = create_db_engine(
        api_database.app_settings(), application_name=RACER_APPLICATION, pooled=False
    )
    racer_results: list[Revocation | None] = []

    def race() -> None:
        with Session(racer_engine) as session, session.begin():
            racer_results.append(ApiKeyRepository(session).revoke(key_id))

    racer = threading.Thread(target=race)
    try:
        with Session(engine) as holder, holder.begin():
            first = ApiKeyRepository(holder).revoke(key_id)
            racer.start()
            wait_until_waiting_for_a_lock(seed, RACER_APPLICATION)
        racer.join(timeout=LOCK_WAIT_TIMEOUT_SECONDS)
    finally:
        racer_engine.dispose()

    assert not racer.is_alive()
    assert first is not None
    assert first.newly_revoked is True
    [second] = racer_results
    assert second is not None
    assert second.newly_revoked is False
    assert second.key.revoked_at == first.key.revoked_at
