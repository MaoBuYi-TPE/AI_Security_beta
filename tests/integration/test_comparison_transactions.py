"""T22：真實 commit／rollback 與兩個連線爭用唯一鍵，不用固定 sleep 猜併發順序。"""

from collections.abc import Iterator
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from secscan.audit.service import AuditTrail
from secscan.comparisons.service import ComparisonService
from secscan.main import create_app
from tests.integration.api_support import Seeder, World
from tests.integration.database import ProvisionedDatabase
from tests.integration.locks import Race, wait_until_waiting_for_a_lock
from tests.integration.sql_support import INTEGRITY_CONSTRAINT_VIOLATION, violation
from tests.integration.test_comparisons_api import URL, pair

pytestmark = pytest.mark.integration
RACER = "secscan-comparison-racer"


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


@pytest.fixture
def client(queue_database: ProvisionedDatabase) -> Iterator[TestClient]:
    with TestClient(create_app(queue_database.app_settings())) as opened:
        yield opened


def _unsealed(session: Session, body: dict[str, str]) -> UUID:
    comparison = session.execute(
        text(
            "INSERT INTO scan_comparisons (project_id, target_id, baseline_scan_id, "
            "current_scan_id, algorithm_version, comparability, reasons, manual_review_required) "
            "SELECT project_id, target_id, id, :current, 1, 'different', '[]', false "
            "FROM scans WHERE id = :baseline RETURNING id"
        ),
        {"baseline": UUID(body["baseline_scan_id"]), "current": UUID(body["current_scan_id"])},
    ).scalar_one()
    assert isinstance(comparison, UUID)
    return comparison


def _counts(seed: Seeder) -> tuple[int, int, int]:
    [row] = seed.query(
        "SELECT (SELECT count(*) FROM scan_comparisons) AS snapshots, "
        "(SELECT count(*) FROM scan_comparison_findings) AS findings, "
        "(SELECT count(*) FROM audit_events WHERE action = 'scan_comparison.create') AS audits"
    )
    return row.snapshots, row.findings, row.audits


@pytest.mark.parametrize("commit", [True, False])
def test_concurrent_create_waits_for_commit_or_takes_over_after_rollback(
    queue_engine: Engine,
    queue_database: ProvisionedDatabase,
    queue_seed: Seeder,
    world: World,
    commit: bool,
) -> None:
    body = pair(queue_engine, queue_seed, world)
    baseline, current = UUID(body["baseline_scan_id"]), UUID(body["current_scan_id"])
    race = Race(
        queue_database,
        RACER,
        lambda session: ComparisonService(session).create(
            world.operator_a.principal,
            baseline,
            current,
            request_id="second",
        ),
    )
    with Session(queue_engine, expire_on_commit=False) as holder:
        first, created = ComparisonService(holder).create(
            world.operator_a.principal,
            baseline,
            current,
            request_id="first",
        )
        assert created
        try:
            race.start()
            wait_until_waiting_for_a_lock(queue_seed, RACER)
            if commit:
                holder.commit()
            else:
                holder.rollback()
        finally:
            holder.rollback()
            race.join()
    assert race.errors == []
    [(second, created)] = race.results
    assert created is not commit
    assert (first.id == second.id) is commit
    assert _counts(queue_seed) == (1, 2, 1)
    [audit] = queue_seed.query(
        "SELECT request_id FROM audit_events WHERE action = 'scan_comparison.create'"
    )
    assert audit.request_id == ("first" if commit else "second")


def test_unsealed_snapshot_fails_at_real_commit_and_rolls_back(
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
) -> None:
    body = pair(queue_engine, queue_seed, world)
    with Session(queue_engine) as session:
        _unsealed(session, body)
        with pytest.raises(IntegrityError) as caught:
            session.commit()
        assert getattr(caught.value.orig, "sqlstate", None) == INTEGRITY_CONSTRAINT_VIOLATION
        session.rollback()
    assert _counts(queue_seed) == (0, 0, 0)


def test_uncommitted_parent_cannot_accept_a_row_from_another_transaction(
    queue_engine: Engine,
    queue_database: ProvisionedDatabase,
    queue_seed: Seeder,
    world: World,
) -> None:
    body = pair(queue_engine, queue_seed, world)
    [finding] = queue_seed.query("SELECT id, target_id FROM findings LIMIT 1")
    with Session(queue_engine) as holder:
        comparison = _unsealed(holder, body)

        def append(session: Session) -> None:
            session.execute(
                text(
                    "INSERT INTO scan_comparison_findings (comparison_id, finding_id, target_id, "
                    "classification, reasons, evidence, manual_review_required) "
                    "VALUES (:comparison, :finding, :target, 'inconclusive', '[]', '{}', false)"
                ),
                {"comparison": comparison, "finding": finding.id, "target": finding.target_id},
            )

        race = Race(queue_database, RACER, append)
        try:
            race.start()
            race.join()
            [error] = race.errors
            assert isinstance(error, IntegrityError)
            assert getattr(error.orig, "sqlstate", None) == INTEGRITY_CONSTRAINT_VIOLATION
            assert "parent must be visible" in str(error.orig)
            holder.execute(
                text("UPDATE scan_comparisons SET sealed = true WHERE id = :id"), {"id": comparison}
            )
            holder.commit()
        finally:
            holder.rollback()
    assert _counts(queue_seed) == (1, 0, 0)


def test_audit_failure_rolls_back_the_header_and_all_finding_rows(
    client: TestClient,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = pair(queue_engine, queue_seed, world)

    def failed_audit(*args: object, **kwargs: object) -> None:
        raise RuntimeError("audit unavailable")

    with monkeypatch.context() as patch:
        patch.setattr(AuditTrail, "record", failed_audit)
        with pytest.raises(RuntimeError, match="audit unavailable"):
            client.post(URL, json=body, headers=world.operator_a.headers)
    assert _counts(queue_seed) == (0, 0, 0)
    assert client.post(URL, json=body, headers=world.operator_a.headers).status_code == 201
    assert _counts(queue_seed) == (1, 2, 1)


def test_committed_snapshot_and_rows_reject_truncate(
    client: TestClient,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
) -> None:
    body = pair(queue_engine, queue_seed, world)
    assert client.post(URL, json=body, headers=world.operator_a.headers).status_code == 201
    with Session(queue_engine) as session:
        # T21 的 triage 事件以 FK 引用 scan_comparison_findings：不加 CASCADE 時 PostgreSQL 在
        # trigger 之前就拒絕；加 CASCADE 時由各表的 no-truncate trigger 拒絕。
        for statement in (
            "TRUNCATE scan_comparison_findings CASCADE",
            "TRUNCATE scan_comparisons CASCADE",
        ):
            assert violation(session, statement, {}).sqlstate == INTEGRITY_CONSTRAINT_VIOLATION
    assert _counts(queue_seed) == (1, 2, 1)


@pytest.mark.parametrize("side", ["baseline", "current"])
@pytest.mark.parametrize("cross_project", [False, True])
def test_each_scan_foreign_key_rejects_an_existing_foreign_target(
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    side: str,
    cross_project: bool,
) -> None:
    from tests.integration.sql_support import FOREIGN_KEY_VIOLATION
    from tests.integration.test_comparison_snapshot_schema import INSERT

    body = pair(queue_engine, queue_seed, world)
    other = pair(queue_engine, queue_seed, queue_seed.world() if cross_project else world)
    [scan] = queue_seed.query(
        "SELECT project_id, target_id FROM scans WHERE id = :id", id=UUID(body["baseline_scan_id"])
    )
    values = {
        "project": scan.project_id,
        "target": scan.target_id,
        "baseline": UUID(body["baseline_scan_id"]),
        "current": UUID(body["current_scan_id"]),
        "version": 1,
        "comparability": "different",
        "reasons": "[]",
        side: UUID(other[f"{side}_scan_id"]),
    }
    with Session(queue_engine) as session:
        assert violation(session, INSERT, values).sqlstate == FOREIGN_KEY_VIOLATION
    assert _counts(queue_seed) == (0, 0, 0)


@pytest.mark.parametrize("claim_other_target", [True, False])
def test_each_finding_foreign_key_rejects_an_existing_foreign_target(
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    claim_other_target: bool,
) -> None:
    from tests.integration.sql_support import FOREIGN_KEY_VIOLATION
    from tests.integration.test_comparison_snapshot_findings_schema import ROW, _values

    body = pair(queue_engine, queue_seed, world)
    other = pair(queue_engine, queue_seed, world)
    [other_finding] = queue_seed.query(
        "SELECT id, target_id FROM findings WHERE target_id = "
        "(SELECT target_id FROM scans WHERE id = :id) LIMIT 1",
        id=UUID(other["baseline_scan_id"]),
    )
    [scan] = queue_seed.query(
        "SELECT target_id FROM scans WHERE id = :id", id=UUID(body["baseline_scan_id"])
    )
    with Session(queue_engine) as session:
        comparison = _unsealed(session, body)
        target = other_finding.target_id if claim_other_target else scan.target_id
        values = _values(comparison, other_finding.id, target)
        assert violation(session, ROW, values).sqlstate == FOREIGN_KEY_VIOLATION
    assert _counts(queue_seed) == (0, 0, 0)
