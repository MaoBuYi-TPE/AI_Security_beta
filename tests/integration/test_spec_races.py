"""併發的上傳：version 連號、配額精確（docs/DECISIONS.md §11.5）。

做法同 test_grant_races.py：先到的在 transaction 中持有 target 的鎖，後到的在背景執行；
以 pg_stat_activity 確認後到的正在等列鎖，再讓先到的 commit。
"""

from collections.abc import Iterator
from uuid import UUID

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from secscan.core.errors import AppError, ErrorCode
from secscan.specs.domain.documents import SpecFormat
from secscan.specs.domain.model import ApiSpec, SpecUpload
from secscan.specs.service import MAX_SPECS_PER_TARGET, ApiSpecService
from tests.integration.api_support import MINIMAL_SPEC, Seeder, World
from tests.integration.conftest import app_engine
from tests.integration.database import ProvisionedDatabase
from tests.integration.locks import Race, wait_until_waiting_for_a_lock

pytestmark = pytest.mark.integration

RACER = "secscan-spec-racer"
UPLOAD = SpecUpload(spec_format=SpecFormat.JSON, content=MINIMAL_SPEC)


@pytest.fixture
def engine(api_database: ProvisionedDatabase) -> Iterator[Engine]:
    engine = app_engine(api_database)
    yield engine
    engine.dispose()


def _race(
    engine: Engine, api_database: ProvisionedDatabase, seed: Seeder, world: World, target_id: UUID
) -> tuple[ApiSpec, Race[ApiSpec]]:
    def upload(session: Session) -> ApiSpec:
        return ApiSpecService(session).upload(
            world.operator_a.principal,
            target_id,
            UPLOAD,
            request_id=None,
        )

    race = Race(api_database, RACER, upload)
    with Session(engine, expire_on_commit=False) as holder, holder.begin():
        first = upload(holder)
        race.start()
        wait_until_waiting_for_a_lock(seed, RACER)
    race.join()
    return first, race


def test_concurrent_uploads_get_consecutive_versions(
    engine: Engine, api_database: ProvisionedDatabase, seed: Seeder, world: World
) -> None:
    target = seed.target(world.operator_a, world.project_a.id)

    first, race = _race(engine, api_database, seed, world, target.id)

    assert race.errors == []
    [second] = race.results
    assert (first.version, second.version) == (1, 2)


def test_quota_holds_under_concurrent_uploads(
    engine: Engine, api_database: ProvisionedDatabase, seed: Seeder, world: World
) -> None:
    """配額的計數在鎖住 target 之後：同時上傳最後一個名額時，後到的看到已滿。"""
    target = seed.target(world.operator_a, world.project_a.id)
    for _ in range(MAX_SPECS_PER_TARGET - 1):
        seed.spec(world.operator_a, target)

    first, race = _race(engine, api_database, seed, world, target.id)

    assert first.version == MAX_SPECS_PER_TARGET
    assert race.results == []
    [error] = race.errors
    assert isinstance(error, AppError)
    assert error.code == ErrorCode.QUOTA_EXCEEDED
    [row] = seed.query("SELECT count(*) AS n FROM api_specs WHERE target_id = :t", t=target.id)
    assert row.n == MAX_SPECS_PER_TARGET
