"""T21 報告佇列：SKIP LOCKED、lease fencing、重試上限與故障注入（G1、G2）。

另外驗證快照與同時發生的 PATCH 互相隔離（REPEATABLE READ）。
"""

import hashlib
import json
from datetime import datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from secscan.findings.domain.model import TriageState
from secscan.grants.repository import ScopeGrantRepository
from secscan.reports.domain.model import ReportFormat
from secscan.reports.domain.render import Rendered
from secscan.reports.queue import LeaseLostError, ReportQueue
from secscan.reports.service import ReportService
from secscan.triage.service import TriageCommand, TriageService
from secscan.worker.reports import ReportWorker
from tests.integration.api_support import LAB, Seeder, World
from tests.integration.database import ProvisionedDatabase
from tests.integration.locks import Race, wait_until_waiting_for_a_lock
from tests.integration.triage_support import Scenario, scenario

pytestmark = pytest.mark.integration
CONTENT = Rendered(b'{"x":1}', truncated=False, omitted_findings=0)


class InjectedError(RuntimeError):
    """故障注入。"""


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


@pytest.fixture
def item(queue_engine: Engine, queue_seed: Seeder, world: World) -> Scenario:
    return scenario(queue_engine, queue_seed, world)


@pytest.fixture
def sessions(queue_engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(queue_engine, expire_on_commit=False)


def enqueue(sessions: sessionmaker[Session], world: World, scan: UUID) -> UUID:
    with sessions.begin() as session:
        report, _ = ReportService(session, lab=LAB).create(
            world.operator_a.principal,
            scan,
            ReportFormat.JSON,
            idempotency_key=uuid4().hex,
            request_id=None,
        )
        return report.id


def expire(seed: Seeder, report: UUID) -> None:
    seed.execute(
        "UPDATE reports SET lease_expires_at = clock_timestamp() - interval '1 second' "
        "WHERE id = :id",
        id=report,
    )


def status(seed: Seeder, report: UUID) -> tuple[str, int, str | None]:
    [row] = seed.query("SELECT status, attempts, error_code FROM reports WHERE id = :id", id=report)
    return row.status, row.attempts, row.error_code


def test_claims_are_fifo_and_skip_locked_rows(
    queue_database: ProvisionedDatabase,
    sessions: sessionmaker[Session],
    queue_seed: Seeder,
    world: World,
    item: Scenario,
) -> None:
    first, second = enqueue(sessions, world, item.baseline), enqueue(sessions, world, item.current)
    queue = ReportQueue(sessions)
    lease = queue.claim("worker-a")
    assert lease is not None
    assert lease.report_id == first
    rival = queue.claim("worker-b")
    assert rival is not None
    assert rival.report_id == second
    assert queue.claim("worker-c") is None


def test_a_stale_worker_cannot_complete_after_reclaim(
    sessions: sessionmaker[Session], queue_seed: Seeder, world: World, item: Scenario
) -> None:
    report = enqueue(sessions, world, item.baseline)
    queue = ReportQueue(sessions)
    stale = queue.claim("worker-a")
    assert stale is not None
    expire(queue_seed, report)
    assert queue.reconcile_expired() == 1
    assert status(queue_seed, report) == ("queued", 1, None)
    fresh = queue.claim("worker-b")
    assert fresh is not None
    with pytest.raises(LeaseLostError):
        queue.complete(stale, CONTENT, data_as_of=_now(queue_seed), generated_at=_now(queue_seed))
    with pytest.raises(LeaseLostError):
        queue.heartbeat(stale)
    queue.complete(fresh, CONTENT, data_as_of=_now(queue_seed), generated_at=_now(queue_seed))
    assert status(queue_seed, report) == ("succeeded", 2, None)
    [row] = queue_seed.query("SELECT sha256 FROM reports WHERE id = :id", id=report)
    assert row.sha256 == hashlib.sha256(CONTENT.content).hexdigest()


def _now(seed: Seeder) -> datetime:
    value: datetime = seed.query("SELECT now() AS now")[0].now
    return value


def test_attempts_are_capped_at_three(
    sessions: sessionmaker[Session], queue_seed: Seeder, world: World, item: Scenario
) -> None:
    report = enqueue(sessions, world, item.baseline)
    queue = ReportQueue(sessions)
    for attempt in (1, 2, 3):
        assert queue.claim("worker-a") is not None
        expire(queue_seed, report)
        queue.reconcile_expired()
        assert status(queue_seed, report)[1] == attempt
    assert status(queue_seed, report) == ("failed", 3, "REPORT_ATTEMPTS_EXHAUSTED")
    assert queue.claim("worker-a") is None


def test_a_failure_after_writing_content_rolls_back(
    sessions: sessionmaker[Session],
    queue_seed: Seeder,
    world: World,
    item: Scenario,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = enqueue(sessions, world, item.baseline)
    queue = ReportQueue(sessions)
    lease = queue.claim("worker-a")
    assert lease is not None

    def failing(*args: object, **kwargs: object) -> object:
        raise InjectedError

    # 寫入內容之後、轉成 succeeded 之前失敗（complete 中第一個 update 就是狀態轉換）。
    monkeypatch.setattr("secscan.reports.queue.update", failing)
    with pytest.raises(InjectedError):
        queue.complete(lease, CONTENT, data_as_of=_now(queue_seed), generated_at=_now(queue_seed))
    monkeypatch.undo()
    assert status(queue_seed, report) == ("generating", 1, None)
    [row] = queue_seed.query(
        "SELECT count(*) AS n FROM report_contents WHERE report_id = :id", id=report
    )
    assert row.n == 0
    queue.complete(lease, CONTENT, data_as_of=_now(queue_seed), generated_at=_now(queue_seed))
    assert status(queue_seed, report)[0] == "succeeded"


def test_the_snapshot_is_consistent_while_triage_changes(
    sessions: sessionmaker[Session],
    queue_seed: Seeder,
    world: World,
    item: Scenario,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """快照開始之後才提交的 PATCH 不會出現在這份報告中（REPEATABLE READ），下一份才會。"""
    enqueue(sessions, world, item.baseline)
    real_get = ScopeGrantRepository.get
    changed: list[bool] = []

    def get_then_patch(self: ScopeGrantRepository, grant_id: UUID) -> object:
        result = real_get(self, grant_id)
        if not changed:
            command = TriageCommand(expected_version=0, reason="確認", triage=TriageState.CONFIRMED)
            with sessions.begin() as other:
                TriageService(other).change(
                    world.operator_a.principal, item.sqli, command, request_id=None
                )
            changed.append(True)
        return result

    monkeypatch.setattr(ScopeGrantRepository, "get", get_then_patch)
    worker = ReportWorker(sessions, owner="worker-r")
    assert worker.drain() == 1
    monkeypatch.undo()
    enqueue(sessions, world, item.baseline)
    assert worker.drain() == 1
    documents = [
        json.loads(bytes(row.content))
        for row in queue_seed.query(
            "SELECT c.content FROM report_contents c JOIN reports r ON r.id = c.report_id "
            "ORDER BY r.queue_position"
        )
    ]
    states = [
        {finding["id"]: finding["triage_state"] for finding in document["findings"]}
        for document in documents
    ]
    assert states[0][str(item.sqli)] == "unreviewed"
    assert states[1][str(item.sqli)] == "confirmed"


def test_concurrent_creation_respects_the_project_quota(
    queue_database: ProvisionedDatabase,
    sessions: sessionmaker[Session],
    queue_seed: Seeder,
    world: World,
    item: Scenario,
) -> None:
    for _ in range(4):
        enqueue(sessions, world, item.baseline)

    def create(session: Session) -> object:
        return ReportService(session, lab=LAB).create(
            world.operator_a.principal,
            item.current,
            ReportFormat.JSON,
            idempotency_key=uuid4().hex,
            request_id=None,
        )

    rival = Race(queue_database, "report-rival", create)
    with sessions.begin() as session:
        create(session)
        rival.start()
        wait_until_waiting_for_a_lock(queue_seed, "report-rival")
    rival.join()
    assert len(rival.errors) == 1
    [row] = queue_seed.query("SELECT count(*) AS n FROM reports WHERE status = 'queued'")
    assert row.n == 5
