"""T33：降級與寫入實驗政策併發時，也不能刪去已提交的版本證據。"""

import pytest
from alembic import command
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from secscan.migrations import alembic_config
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.queue import ScanQueue
from tests.integration.api_support import Seeder, World
from tests.integration.database import ProvisionedDatabase
from tests.integration.locks import Race, wait_until_waiting_for_a_lock
from tests.integration.test_run_provenance import SHA, _running
from tests.integration.test_run_provenance import queue as queue
from tests.integration.test_run_provenance import world as world

pytestmark = pytest.mark.integration
RACER = "secscan-policy-downgrade"


def _downgrade(session: Session) -> None:
    command.downgrade(alembic_config(connection=session.connection()), "0011")


def test_downgrade_waits_for_writers_before_checking_policy_evidence(
    queue: ScanQueue,
    queue_engine: Engine,
    queue_database: ProvisionedDatabase,
    queue_seed: Seeder,
    world: World,
) -> None:
    run_id = _running(queue, queue_seed, world, ScanEngine.ZAP)
    race = Race(queue_database, RACER, _downgrade)
    with Session(queue_engine) as writer, writer.begin():
        writer.execute(
            text(
                "UPDATE scanner_runs SET plan_hash = :plan, "
                "guard_policy_version = 'encoded-params-1' WHERE id = :id"
            ),
            {"plan": SHA, "id": run_id},
        )
        race.start()
        wait_until_waiting_for_a_lock(queue_seed, RACER)
    race.join()

    assert race.results == []
    [error] = race.errors
    assert isinstance(error, RuntimeError)
    assert "拒絕移除版本證據" in str(error)
    [row] = queue_seed.query(
        "SELECT guard_policy_version FROM scanner_runs WHERE id = :id", id=run_id
    )
    assert row.guard_policy_version == "encoded-params-1"
    [revision] = queue_seed.query("SELECT version_num FROM alembic_version")
    assert revision.version_num == "0012"
