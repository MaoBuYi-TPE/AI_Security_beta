"""T21 reports 的 DB 層強制（G3）：狀態轉換、終止不可修改、內容只寫一次與 commit 時的雙向核對。"""

import hashlib
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from tests.integration.api_support import Seeder, World
from tests.integration.sql_support import INTEGRITY_CONSTRAINT_VIOLATION, violation
from tests.integration.triage_support import Scenario, scenario

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


def succeed(session: Session, report: UUID, content: bytes = CONTENT, sha: bytes = CONTENT) -> None:
    session.execute(text(CLAIM), {"id": report})
    session.execute(
        text("INSERT INTO report_contents (report_id, content) VALUES (:id, :content)"),
        {"id": report, "content": content},
    )
    session.execute(
        text(
            "UPDATE reports SET status = 'succeeded', lease_owner = NULL, lease_expires_at = NULL, "
            "data_as_of = now(), generated_at = now(), size_bytes = :size, sha256 = :sha, "
            "truncated = false, omitted_findings = 0, finished_at = now() WHERE id = :id"
        ),
        {"id": report, "size": len(content), "sha": hashlib.sha256(sha).hexdigest()},
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
            "INSERT INTO report_contents (report_id, content) VALUES (:id, 'x')",
            {"id": report},
        )
        assert "while generating" in str(error)
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
            "sha256 = NULL WHERE id = :id",
            "UPDATE report_contents SET content = 'x' WHERE report_id = :id",
            "DELETE FROM report_contents WHERE report_id = :id",
            "TRUNCATE report_contents",
        ):
            error = violation(session, statement, {"id": report})
            assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION, statement


def test_content_and_success_are_checked_together_at_commit(
    queue_engine: Engine, item: Scenario, world: World
) -> None:
    sessions = sessionmaker(queue_engine)
    with sessions() as session:
        report = queued(session, item, world)
        succeed(session, report, sha=b"different")
        with pytest.raises(IntegrityError, match="matching sha256"):
            session.commit()
    with sessions() as session:
        report = queued(session, item, world)
        session.execute(text(CLAIM), {"id": report})
        session.execute(
            text("INSERT INTO report_contents (report_id, content) VALUES (:id, 'x')"),
            {"id": report},
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
                "finished_at = now() WHERE id = :id"
            ),
            {"id": report, "sha": "0" * 64},
        )
        with pytest.raises(IntegrityError, match="need content"):
            session.commit()
