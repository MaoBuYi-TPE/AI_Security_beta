"""T21 reports 的 DB 層強制（G3）：狀態轉換、終止不可修改、內容只寫一次與 commit 時的雙向核對。

T23a（v0022）之後內容是密文：DB 核對內容存在、是 Fernet token 的形狀；明文的 sha256 與大小改由
worker 寫入、下載時解密之後核對（tests/integration/test_reports_api.py）。到期清除與換版的路徑見
tests/integration/test_sealed_content_schema.py。
"""

import hashlib
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from secscan.reports.domain.model import MAX_REPORT_BYTES, report_context
from tests.integration.api_support import Seeder, World
from tests.integration.sql_support import INTEGRITY_CONSTRAINT_VIOLATION, violation
from tests.integration.triage_support import Scenario, scenario
from tests.secret_support import shared_content_cipher

pytestmark = pytest.mark.integration

INSERT = (
    "INSERT INTO reports (project_id, target_id, scan_id, format, schema_version, status, "
    "idempotency_key, request_sha256, requested_by_key_id, attempts) VALUES (:project, :target, "
    ":scan, 'json', 1, :status, :key, :sha, :actor, :attempts) RETURNING id"
)
CLAIM = (
    "UPDATE reports SET status = 'generating', attempts = attempts + 1, lease_owner = 'w', "
    "lease_expires_at = now() + interval '30 seconds' WHERE id = :id"
)
CONTENT = b"report-content"
SQL_CHECK_VIOLATION = "23514"


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


@pytest.fixture
def item(queue_engine: Engine, queue_seed: Seeder, world: World) -> Scenario:
    return scenario(queue_engine, queue_seed, world)


def values(item: Scenario, world: World, **changes: object) -> dict[str, object]:
    base: dict[str, object] = {
        "project": item.target.project_id,
        "target": item.target.id,
        "scan": item.baseline,
        "status": "queued",
        "key": uuid4().hex,
        "sha": b"\x00" * 32,
        "actor": world.operator_a.principal.key_id,
        "attempts": 0,
    }
    return {**base, **changes}


def queued(session: Session, item: Scenario, world: World) -> UUID:
    report = session.execute(text(INSERT), values(item, world)).scalar_one()
    assert isinstance(report, UUID)
    return report


def sealed(report: UUID, content: bytes = CONTENT) -> bytes:
    return shared_content_cipher().seal(
        content, context=report_context(report), max_bytes=MAX_REPORT_BYTES
    )


def succeed(
    session: Session, report: UUID, content: bytes = CONTENT, *, expires: str = "30 days"
) -> None:
    session.execute(text(CLAIM), {"id": report})
    session.execute(
        text(
            "INSERT INTO report_contents (report_id, attempt, lease_owner, content) "
            "VALUES (:id, 1, 'w', :content)"
        ),
        {"id": report, "content": sealed(report, content)},
    )
    session.execute(
        text(
            "UPDATE reports SET status = 'succeeded', lease_owner = NULL, lease_expires_at = NULL, "
            "data_as_of = now(), generated_at = now(), size_bytes = :size, sha256 = :sha, "
            "truncated = false, omitted_findings = 0, finished_at = now(), "
            "expires_at = clock_timestamp() + CAST(:expires AS interval) WHERE id = :id"
        ),
        {
            "id": report,
            "size": len(content),
            "sha": hashlib.sha256(content).hexdigest(),
            "expires": expires,
        },
    )


def test_new_reports_start_queued(queue_engine: Engine, item: Scenario, world: World) -> None:
    with sessionmaker(queue_engine)() as session:
        for changes in ({"status": "generating"}, {"attempts": 1}):
            error = violation(session, INSERT, values(item, world, **changes))
            assert error.sqlstate in {INTEGRITY_CONSTRAINT_VIOLATION, "23514"}


def test_only_allowed_transitions_and_columns(
    queue_engine: Engine, item: Scenario, world: World
) -> None:
    with sessionmaker(queue_engine)() as session:
        report = queued(session, item, world)
        for statement in (
            "UPDATE reports SET status = 'succeeded' WHERE id = :id",
            "UPDATE reports SET format = 'markdown' WHERE id = :id",
            "UPDATE reports SET status = 'generating', attempts = 2, lease_owner = 'w', "
            "lease_expires_at = now() WHERE id = :id",
            "DELETE FROM reports WHERE id = :id",
            "TRUNCATE reports CASCADE",
        ):
            error = violation(session, statement, {"id": report})
            assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION, statement
        error = violation(
            session,
            "INSERT INTO report_contents (report_id, attempt, lease_owner, content) "
            "VALUES (:id, 1, 'w', 'x')",
            {"id": report},
        )
        assert "current lease holder" in str(error)
        session.execute(text(CLAIM), {"id": report})
        error = violation(session, "UPDATE reports SET attempts = 3 WHERE id = :id", {"id": report})
        assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION


def test_finished_reports_and_contents_are_immutable(
    queue_engine: Engine, item: Scenario, world: World
) -> None:
    sessions = sessionmaker(queue_engine)
    with sessions() as session:
        report = queued(session, item, world)
        succeed(session, report)
        session.commit()
        for statement in (
            "UPDATE reports SET status = 'failed', error_code = 'X1', size_bytes = NULL, "
            "sha256 = NULL, expires_at = NULL WHERE id = :id",
            "UPDATE reports SET expires_at = expires_at + interval '1 day' WHERE id = :id",
            "UPDATE reports SET content_purged_at = clock_timestamp() WHERE id = :id",
            "UPDATE report_contents SET attempt = 2 WHERE report_id = :id",
            "DELETE FROM report_contents WHERE report_id = :id",
            "TRUNCATE report_contents",
        ):
            error = violation(session, statement, {"id": report})
            assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION, statement
        error = violation(
            session,
            "UPDATE report_contents SET content = 'x' WHERE report_id = :id",
            {"id": report},
        )
        assert error.sqlstate == SQL_CHECK_VIOLATION


def test_content_and_success_are_checked_together_at_commit(
    queue_engine: Engine, item: Scenario, world: World
) -> None:
    sessions = sessionmaker(queue_engine)
    with sessions() as session:
        report = queued(session, item, world)
        session.execute(text(CLAIM), {"id": report})
        session.execute(
            text(
                "INSERT INTO report_contents (report_id, attempt, lease_owner, content) "
                "VALUES (:id, 1, 'w', :content)"
            ),
            {"id": report, "content": sealed(report)},
        )
        with pytest.raises(IntegrityError, match="succeeded report"):
            session.commit()
    with sessions() as session:
        report = queued(session, item, world)
        session.execute(text(CLAIM), {"id": report})
        session.execute(
            text(
                "UPDATE reports SET status = 'succeeded', lease_owner = NULL, "
                "lease_expires_at = NULL, data_as_of = now(), generated_at = now(), "
                "size_bytes = 1, sha256 = :sha, truncated = false, omitted_findings = 0, "
                "finished_at = now(), expires_at = now() + interval '30 days' WHERE id = :id"
            ),
            {"id": report, "sha": "0" * 64},
        )
        with pytest.raises(IntegrityError, match="need content from the same attempt"):
            session.commit()


def test_shapes_are_null_safe_and_queued_rows_have_attempts_left(
    queue_engine: Engine, item: Scenario, world: World
) -> None:
    with sessionmaker(queue_engine)() as session:
        report = queued(session, item, world)
        session.execute(text(CLAIM), {"id": report})
        failed_without_code = (
            "UPDATE reports SET status = 'failed', lease_owner = NULL, lease_expires_at = NULL, "
            "heartbeat_at = NULL, finished_at = now() WHERE id = :id"
        )
        error = violation(session, failed_without_code, {"id": report})
        assert error.diag.constraint_name == "ck_reports_failed_shape"
        session.rollback()
    with sessionmaker(queue_engine)() as session:
        report = queued(session, item, world)
        for _ in range(3):
            session.execute(text(CLAIM), {"id": report})
            requeue = (
                "UPDATE reports SET status = 'queued', lease_owner = NULL, "
                "lease_expires_at = NULL, heartbeat_at = NULL WHERE id = :id"
            )
            if _ < 2:
                session.execute(text(requeue), {"id": report})
        error = violation(session, requeue, {"id": report})
        assert error.diag.constraint_name == "ck_reports_queued_shape"


def test_content_needs_the_current_lease_token(
    queue_engine: Engine, item: Scenario, world: World
) -> None:
    with sessionmaker(queue_engine)() as session:
        report = queued(session, item, world)
        session.execute(text(CLAIM), {"id": report})
        insert = (
            "INSERT INTO report_contents (report_id, attempt, lease_owner, content) "
            "VALUES (:id, :attempt, :owner, 'x')"
        )
        for attempt, owner in ((2, "w"), (1, "other")):
            error = violation(session, insert, {"id": report, "attempt": attempt, "owner": owner})
            assert "current lease holder" in str(error)
        error = violation(
            session, "UPDATE reports SET lease_owner = 'other' WHERE id = :id", {"id": report}
        )
        assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION
        session.execute(
            text(
                "UPDATE reports SET lease_expires_at = clock_timestamp() - interval '1 second' "
                "WHERE id = :id"
            ),
            {"id": report},
        )
        error = violation(session, insert, {"id": report, "attempt": 1, "owner": "w"})
        assert "current lease holder" in str(error)
