"""報告建立的 project 鎖（T23b-b1；docs/DECISIONS.md §31.6；ROLE-04 的 L1 至 L8）。

原本以 FOR NO KEY UPDATE 鎖住 projects 的列（需要 projects 的 UPDATE），改成交易層級的 advisory lock
(REPORT_CREATE_LOCK_CLASS, hashtext(project_id))。這裡驗證語意不變：

- L1 同一個 project 序列化（配額見 test_report_queue 的並行測試；這裡加上 idempotency）；
- L2 不同的 project 不阻塞；L3 雜湊碰撞只會排隊；L4 commit 與 rollback 都釋放；
- L5 等鎖逾時是 55P03（可重試，和改動之前相同）；
- L6 和 evidence 的鎖、v0023 的 23012 不在同一個鍵空間；
- L8 應用程式角色沒有 projects 的 UPDATE：原本的列鎖現在是 42501。
L7（既有的配額、idempotency 與並行測試照常通過）由整個整合測試涵蓋。
"""

from collections.abc import Iterator
from contextlib import contextmanager
from uuid import UUID, uuid4

import psycopg
import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError, OperationalError
from sqlalchemy.orm import Session, sessionmaker

from secscan.core.errors import RETRYABLE_SQLSTATES, AppError
from secscan.reports.domain.model import ReportFormat
from secscan.reports.service import (
    MAX_ACTIVE_PER_PROJECT,
    REPORT_CREATE_LOCK_CLASS,
    ReportService,
    lock_project_reports,
)
from secscan.scans.evidence_records import EVIDENCE_LOCK_KEY
from tests.integration.api_support import LAB, Seeder, World
from tests.integration.database import ProvisionedDatabase
from tests.integration.locks import Race, wait_until_waiting_for_a_lock
from tests.integration.triage_support import Scenario, scenario

pytestmark = pytest.mark.integration

LOCK_NOT_AVAILABLE = "55P03"
INSUFFICIENT_PRIVILEGE = "42501"
# 300,000 個隨機 UUID 至少有一組 hashtext 碰撞的機率約 1 - e^(-n²/2³³) ≈ 1 - e^(-10)。
COLLISION_CANDIDATES = 300_000
EVIDENCE_HOLD_LOCK_CLASS = 23012


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


@pytest.fixture
def item(queue_engine: Engine, queue_seed: Seeder, world: World) -> Scenario:
    return scenario(queue_engine, queue_seed, world)


@pytest.fixture
def sessions(queue_engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(queue_engine, expire_on_commit=False)


@contextmanager
def _holding(sessions: sessionmaker[Session], project_id: UUID) -> Iterator[Session]:
    """在一個還沒結束的 transaction 中持有 project 的報告鎖。"""
    with sessions.begin() as session:
        lock_project_reports(session, project_id)
        yield session


def _lock_without_waiting(engine: Engine, project_id: UUID) -> None:
    """以很短的 lock_timeout 取得鎖：需要等待就會得到 55P03。"""
    with Session(engine) as session, session.begin():
        session.execute(text("SET LOCAL lock_timeout = '200ms'"))
        lock_project_reports(session, project_id)


def _report_locks(seed: Seeder) -> int:
    [row] = seed.query(
        "SELECT count(*) AS n FROM pg_locks WHERE locktype = 'advisory' "
        "AND classid = :class AND objsubid = 2 "
        "AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
        **{"class": REPORT_CREATE_LOCK_CLASS},
    )
    return int(row.n)


def _hash(seed: Seeder, project_id: UUID) -> int:
    [row] = seed.query("SELECT hashtext(CAST(:id AS uuid)::text) AS h", id=project_id)
    return int(row.h)


def test_l1_the_same_idempotency_key_waits_and_replays_the_first_report(
    queue_database: ProvisionedDatabase,
    sessions: sessionmaker[Session],
    queue_seed: Seeder,
    world: World,
    item: Scenario,
) -> None:
    key = uuid4().hex

    def create(session: Session) -> tuple[UUID, bool]:
        report, created = ReportService(session, lab=LAB).create(
            world.operator_a.principal,
            item.current,
            ReportFormat.JSON,
            idempotency_key=key,
            request_id=None,
        )
        return report.id, created

    rival = Race(queue_database, "report-replay", create)
    with sessions.begin() as session:
        first, created = create(session)
        rival.start()
        wait_until_waiting_for_a_lock(queue_seed, "report-replay")
    rival.join()

    assert created is True
    assert (rival.errors, rival.results) == ([], [(first, False)])


def test_l2_different_projects_do_not_block_each_other(
    sessions: sessionmaker[Session], queue_engine: Engine, queue_seed: Seeder, world: World
) -> None:
    a, b = world.project_a.id, world.project_b.id
    assert _hash(queue_seed, a) != _hash(queue_seed, b)

    with _holding(sessions, a):
        _lock_without_waiting(queue_engine, b)


def _colliding_projects(seed: Seeder) -> tuple[UUID, UUID]:
    # 依雜湊排序之後比較相鄰的兩列（自我 join 在 db-test 的 work_mem 下太慢）。
    rows = seed.query(
        "SELECT first, second FROM (SELECT lag(id) OVER (ORDER BY h) AS first, id AS second, "
        "h, lag(h) OVER (ORDER BY h) AS previous FROM (SELECT id, hashtext(id::text) AS h FROM "
        "(SELECT gen_random_uuid() AS id FROM generate_series(1, :n)) AS candidate) AS hashed) "
        "AS ordered WHERE h = previous LIMIT 1",
        n=COLLISION_CANDIDATES,
    )
    # 找不到的機率約 e^(-10)：重跑即可，不是程式的問題。
    assert rows, f"{COLLISION_CANDIDATES} 個隨機 UUID 中沒有 hashtext 碰撞（機率約 e^-10），請重跑"
    return rows[0].first, rows[0].second


def test_l3_a_hash_collision_only_queues(
    queue_database: ProvisionedDatabase,
    sessions: sessionmaker[Session],
    queue_engine: Engine,
    queue_seed: Seeder,
) -> None:
    """兩個 project 的雜湊相同時，報告建立互相排隊；兩個 transaction 都正常完成。"""
    first, second = _colliding_projects(queue_seed)
    assert first != second
    assert _hash(queue_seed, first) == _hash(queue_seed, second)

    rival = Race(queue_database, "report-collision", lambda s: lock_project_reports(s, second))
    with _holding(sessions, first):
        rival.start()
        wait_until_waiting_for_a_lock(queue_seed, "report-collision")
    rival.join()

    assert rival.errors == []
    assert _report_locks(queue_seed) == 0


def test_l4_commit_and_rollback_release_the_lock(
    queue_engine: Engine, queue_seed: Seeder, world: World, item: Scenario
) -> None:
    """在 commit 或 rollback 之後、連線還開著的時候檢查：正式的 api 用連線池，session 層級的鎖會
    跟著連線留下（這裡的 engine 是 NullPool，關閉連線就會釋放，看不出差別）。"""
    project = world.project_a.id

    with queue_engine.connect() as connection:
        session = Session(bind=connection, join_transaction_mode="conditional_savepoint")
        with connection.begin():
            lock_project_reports(session, project)
            assert _report_locks(queue_seed) == 1
        assert _report_locks(queue_seed) == 0

        # rollback：超過配額時 create 失敗，transaction 回滾，鎖也釋放。
        with connection.begin():
            for _ in range(MAX_ACTIVE_PER_PROJECT):
                _create(session, world, item.baseline)
        with pytest.raises(AppError), connection.begin():
            _create(session, world, item.current)
        assert _report_locks(queue_seed) == 0
        session.close()
    _lock_without_waiting(queue_engine, project)


def _create(session: Session, world: World, scan: UUID) -> None:
    ReportService(session, lab=LAB).create(
        world.operator_a.principal,
        scan,
        ReportFormat.JSON,
        idempotency_key=uuid4().hex,
        request_id=None,
    )


def test_l5_a_lock_timeout_is_retryable_like_before(
    sessions: sessionmaker[Session], queue_engine: Engine, world: World
) -> None:
    project = world.project_a.id

    with _holding(sessions, project), pytest.raises(OperationalError) as caught:
        _lock_without_waiting(queue_engine, project)

    origin = caught.value.orig
    assert isinstance(origin, psycopg.Error)
    assert origin.sqlstate == LOCK_NOT_AVAILABLE
    assert origin.sqlstate in RETRYABLE_SQLSTATES


def test_l6_other_advisory_locks_use_different_key_spaces(
    sessions: sessionmaker[Session], queue_engine: Engine, queue_seed: Seeder, world: World
) -> None:
    """keeper 的 bigint 鍵、v0023 的 (23012, hashtext(run))，以及位元相同的 bigint，
    都不影響報告的鎖。"""
    project = world.project_a.id
    hashed = _hash(queue_seed, project)
    same_bits = (REPORT_CREATE_LOCK_CLASS << 32) | (hashed & 0xFFFFFFFF)

    with sessions.begin() as session:
        session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": EVIDENCE_LOCK_KEY})
        session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": same_bits})
        session.execute(
            text("SELECT pg_advisory_xact_lock(CAST(:class AS integer), CAST(:key AS integer))"),
            {"class": EVIDENCE_HOLD_LOCK_CLASS, "key": hashed},
        )
        _lock_without_waiting(queue_engine, project)


def test_l8_the_app_role_cannot_lock_project_rows(queue_engine: Engine, world: World) -> None:
    """原本的列鎖需要 projects 的 UPDATE。

    之後若有程式再鎖 projects，這裡與整合測試都會得到 42501。
    """
    with Session(queue_engine) as session, session.begin(), pytest.raises(DBAPIError) as caught:
        session.execute(
            text("SELECT id FROM projects WHERE id = :id FOR NO KEY UPDATE"),
            {"id": world.project_a.id},
        )

    origin = caught.value.orig
    assert isinstance(origin, psycopg.Error)
    assert origin.sqlstate == INSUFFICIENT_PRIVILEGE
