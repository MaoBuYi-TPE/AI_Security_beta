"""rule set 與執行計畫必須同時記錄，舊計畫不能事後補出規則證據。"""

from datetime import UTC, datetime

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.queue import ScanQueue
from tests.integration.api_support import LAB, Seeder, World
from tests.integration.sql_support import CHECK_VIOLATION, INTEGRITY_CONSTRAINT_VIOLATION, violation
from tests.integration.test_run_provenance import SHA, _running

pytestmark = pytest.mark.integration


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


@pytest.fixture
def queue(queue_engine: Engine) -> ScanQueue:
    return ScanQueue(
        sessionmaker(queue_engine, expire_on_commit=False), lab=LAB, clock=lambda: datetime.now(UTC)
    )


WRITE_PLAN = (
    "UPDATE scanner_runs SET plan_hash = :sha, rule_set = CAST(:rules AS jsonb), "
    "rule_set_sha256 = :sha WHERE id = :run"
)


def test_rules_are_written_with_plan_and_cannot_be_rewritten(
    queue: ScanQueue, queue_seed: Seeder, world: World, queue_engine: Engine
) -> None:
    run_id = _running(queue, queue_seed, world, ScanEngine.ZAP)
    with Session(queue_engine) as session, session.begin():
        session.execute(text(WRITE_PLAN), {"sha": SHA, "rules": '["40018"]', "run": run_id})
        error = violation(
            session,
            "UPDATE scanner_runs SET rule_set = '[\"40019\"]'::jsonb WHERE id = :run",
            {"run": run_id},
        )
        assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION
        error = violation(
            session,
            "UPDATE scanner_runs SET rule_set_sha256 = :sha WHERE id = :run",
            {"sha": "cd" * 32, "run": run_id},
        )
        assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION


def test_legacy_plan_cannot_be_backfilled_with_a_rule_set(
    queue: ScanQueue, queue_seed: Seeder, world: World, queue_engine: Engine
) -> None:
    run_id = _running(queue, queue_seed, world, ScanEngine.ZAP)
    with Session(queue_engine) as session, session.begin():
        session.execute(
            text("UPDATE scanner_runs SET plan_hash = :sha WHERE id = :run"),
            {"sha": SHA, "run": run_id},
        )
        error = violation(session, WRITE_PLAN, {"sha": SHA, "rules": '["40018"]', "run": run_id})
        assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION


@pytest.mark.parametrize("rules", ["{}", "null", "42", '"invalid"'])
def test_rule_set_must_be_a_json_array(
    queue: ScanQueue, queue_seed: Seeder, world: World, queue_engine: Engine, rules: str
) -> None:
    run_id = _running(queue, queue_seed, world, ScanEngine.ZAP)
    with Session(queue_engine) as session:
        error = violation(session, WRITE_PLAN, {"sha": SHA, "rules": rules, "run": run_id})
        assert error.sqlstate == CHECK_VIOLATION
        assert error.diag.constraint_name == "ck_scanner_runs_rule_set_valid"
