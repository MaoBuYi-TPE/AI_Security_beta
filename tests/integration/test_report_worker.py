"""報告 worker 的錯誤分支與 WorkerLoop 的整合（T21；docs/DECISIONS.md §28.5、§28.12）。

- 只屬於這份報告的 DB 錯誤（IntegrityError、快照查詢逾時 57014）：立即釋放這一次嘗試。
- 其他 DB 錯誤（例如連線中斷）：讓程序結束（§17.6），報告留在 generating 等對帳。
- lease 已失效：不算完成，也不釋放（留給對帳）。
- WorkerLoop 每圈先處理 run，再處理一份報告。
"""

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine
from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError
from sqlalchemy.orm import Session, sessionmaker

from secscan.core.errors import AppError
from secscan.reports.domain.model import ReportFormat
from secscan.reports.queue import LeaseLostError, ReportQueue
from secscan.reports.service import ReportService
from secscan.reports.snapshot import SnapshotReader
from secscan.scanners.domain.instances import InstanceRole
from secscan.scanners.service import Fleet
from secscan.scans.queue import ScanQueue
from secscan.worker.loop import WorkerLoop
from secscan.worker.retention import ContentRetention, PurgeReport
from secscan.worker.service import Worker
from tests.integration.api_support import LAB, Seeder, World
from tests.integration.report_support import report_worker
from tests.integration.triage_support import Scenario, scenario
from tests.runner_fakes import FakeClock

pytestmark = pytest.mark.integration


class _OrigError(Exception):
    """DBAPI 例外的替身：只帶 sqlstate。"""

    def __init__(self, sqlstate: str) -> None:
        super().__init__(sqlstate)
        self.sqlstate = sqlstate


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
            ReportFormat.MARKDOWN,
            idempotency_key=uuid4().hex,
            request_id=None,
        )
        return report.id


def status(seed: Seeder, report: UUID) -> tuple[str, int]:
    [row] = seed.query("SELECT status, attempts FROM reports WHERE id = :id", id=report)
    return row.status, row.attempts


def _raise(exc: BaseException) -> object:
    def failing(*_: object, **__: object) -> object:
        raise exc

    return failing


@pytest.mark.parametrize(
    "error",
    [
        IntegrityError("INSERT", {}, _OrigError("23514")),
        DBAPIError("SELECT", {}, _OrigError("57014")),
    ],
    ids=["integrity", "query-canceled"],
)
def test_report_specific_db_errors_release_the_attempt(
    sessions: sessionmaker[Session],
    queue_seed: Seeder,
    world: World,
    item: Scenario,
    monkeypatch: pytest.MonkeyPatch,
    error: DBAPIError,
) -> None:
    report = enqueue(sessions, world, item.baseline)
    monkeypatch.setattr(SnapshotReader, "read", _raise(error))

    assert report_worker(sessions, owner="worker-r").drain(limit=1) == 0

    assert status(queue_seed, report) == ("queued", 1)


def test_other_db_errors_stop_the_worker(
    sessions: sessionmaker[Session],
    queue_seed: Seeder,
    world: World,
    item: Scenario,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = enqueue(sessions, world, item.baseline)
    monkeypatch.setattr(
        SnapshotReader, "read", _raise(OperationalError("SELECT", {}, _OrigError("08006")))
    )

    with pytest.raises(OperationalError):
        report_worker(sessions, owner="worker-r").drain(limit=1)

    # 不釋放：lease 到期之後由對帳退回 queued 或標成 failed。
    assert status(queue_seed, report) == ("generating", 1)


def test_a_lost_lease_is_left_to_reconcile(
    sessions: sessionmaker[Session],
    queue_seed: Seeder,
    world: World,
    item: Scenario,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = enqueue(sessions, world, item.baseline)
    monkeypatch.setattr(ReportQueue, "complete", _raise(LeaseLostError("lost")))

    assert report_worker(sessions, owner="worker-r").drain() == 0

    assert status(queue_seed, report) == ("generating", 1)


def _worker_loop(engine: Engine, sessions: sessionmaker[Session], clock: FakeClock) -> WorkerLoop:
    queue = ScanQueue(sessions, lab=LAB, clock=lambda: datetime.now(UTC))
    fleet = Fleet(sessions, owner="worker:loop", role=InstanceRole.WORKER, software_version="0.1.0")
    return WorkerLoop(
        Worker(queue, owner="worker:loop", findings=None),
        fleet,
        stop_requested=lambda: clock.now >= 10,
        sleep=clock.sleep,
        poll_seconds=2,
        reports=report_worker(sessions, owner="worker:loop"),
    )


def test_the_worker_loop_generates_one_report_per_round(
    queue_engine: Engine,
    sessions: sessionmaker[Session],
    queue_seed: Seeder,
    world: World,
    item: Scenario,
) -> None:
    first = enqueue(sessions, world, item.baseline)
    second = enqueue(sessions, world, item.current)
    clock = FakeClock()
    loop = _worker_loop(queue_engine, sessions, clock)

    assert loop.run(once=True) == []
    assert status(queue_seed, first) == ("succeeded", 1)
    assert status(queue_seed, second) == ("queued", 0)
    assert clock.now == 0

    loop.run()
    assert status(queue_seed, second) == ("succeeded", 1)
    # 有報告產生的那一圈不睡；之後沒有工作才依 poll_seconds 等待到停止條件。
    assert clock.now == 10


def test_failed_reports_do_not_count_toward_the_per_scan_quota(
    sessions: sessionmaker[Session],
    queue_seed: Seeder,
    world: World,
    item: Scenario,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("secscan.reports.service.MAX_PER_SCAN", 2)
    failing = enqueue(sessions, world, item.baseline)
    queue = ReportQueue(sessions)
    for _ in range(3):
        lease = queue.claim("worker-q")
        assert lease is not None
        assert queue.release(lease)
    assert status(queue_seed, failing) == ("failed", 3)
    enqueue(sessions, world, item.baseline)
    # 失敗的那份不算：這是第 2 份未失敗的報告，仍可建立；第 3 份才超過上限。
    enqueue(sessions, world, item.baseline)
    with pytest.raises(AppError) as caught:
        enqueue(sessions, world, item.baseline)
    assert caught.value.code == "QUOTA_EXCEEDED"


class CountingRetention(ContentRetention):
    """記下清除的次數（實際的清除照常執行）。"""

    def __init__(self, sessions: sessionmaker[Session]) -> None:
        super().__init__(sessions)
        self.calls = 0

    def purge(self) -> PurgeReport:
        self.calls += 1
        return super().purge()


def test_the_worker_purges_expired_content_at_start_and_every_ten_minutes(
    sessions: sessionmaker[Session],
) -> None:
    """docs/DECISIONS.md §30.5：開始時清除一次，之後每 10 分鐘一次（不是每一圈）。"""
    clock = FakeClock()
    queue = ScanQueue(sessions, lab=LAB, clock=lambda: datetime.now(UTC))
    fleet = Fleet(sessions, owner="worker:loop", role=InstanceRole.WORKER, software_version="0.1.0")
    retention = CountingRetention(sessions)
    loop = WorkerLoop(
        Worker(queue, owner="worker:loop", findings=None),
        fleet,
        stop_requested=lambda: clock.now >= 1_500,
        sleep=clock.sleep,
        poll_seconds=100,
        retention=retention,
        monotonic=clock.monotonic,
    )

    loop.run()

    assert retention.calls == 3
