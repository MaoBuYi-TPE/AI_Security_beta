"""migration 0022：報告內容與摘錄只能換版或到期清除（RET-02；docs/DECISIONS.md §30.4、§30.5）。

- reports：content_purged_at 只能寫一次，必須已到期，其他欄位都不變。
- report_contents：只能換 content（密文換密文），報告還沒清除；刪除只在報告寫入 content_purged_at
  之後（同一個 transaction）。
- finding_triage_excerpts：只能換 sealed_content；清除只能一次、必須已到期，留下 tombstone。
"""

import hashlib
import json
from uuid import UUID

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from tests.integration.api_support import Seeder, World
from tests.integration.sql_support import INTEGRITY_CONSTRAINT_VIOLATION, violation
from tests.integration.test_reports_schema import queued, sealed, succeed
from tests.integration.test_triage_schema import EVENT, SEALED_EXCERPT, _sealed, confirm, params
from tests.integration.triage_support import Scenario, eligible, scenario

pytestmark = pytest.mark.integration

PURGE = "UPDATE reports SET content_purged_at = clock_timestamp() WHERE id = :id"
DELETE = "DELETE FROM report_contents WHERE report_id = :id"
REQUEST, RESPONSE = "GET / HTTP/1.1", "HTTP/1.1 200"
ATTESTED = json.dumps(
    {
        "attestation": {
            "provenance": "operator_supplied",
            "request_excerpt_sha256": hashlib.sha256(REQUEST.encode()).hexdigest(),
            "request_excerpt_bytes": len(REQUEST),
            "response_excerpt_sha256": hashlib.sha256(RESPONSE.encode()).hexdigest(),
            "response_excerpt_bytes": len(RESPONSE),
        }
    }
)


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


@pytest.fixture
def item(queue_engine: Engine, queue_seed: Seeder, world: World) -> Scenario:
    return scenario(queue_engine, queue_seed, world)


def _report(engine: Engine, item: Scenario, world: World, *, expires: str) -> UUID:
    with sessionmaker(engine)() as session:
        report = queued(session, item, world)
        succeed(session, report, expires=expires)
        session.commit()
    return report


def _code(session: Session, statement: str, report: UUID, **params: object) -> str | None:
    return violation(session, statement, {"id": report, **params}).sqlstate


def test_an_unexpired_report_cannot_be_purged_or_lose_its_content(
    queue_engine: Engine, item: Scenario, world: World
) -> None:
    report = _report(queue_engine, item, world, expires="1 day")

    with sessionmaker(queue_engine)() as session:
        assert _code(session, PURGE, report) == INTEGRITY_CONSTRAINT_VIOLATION
        assert _code(session, DELETE, report) == INTEGRITY_CONSTRAINT_VIOLATION


def test_an_expired_report_is_purged_once_and_then_frozen(
    queue_engine: Engine, item: Scenario, world: World
) -> None:
    report = _report(queue_engine, item, world, expires="-1 second")

    with sessionmaker(queue_engine)() as session:
        assert _code(session, DELETE, report) == INTEGRITY_CONSTRAINT_VIOLATION
        session.execute(text(PURGE), {"id": report})
        session.execute(text(DELETE), {"id": report})
        session.commit()
        for statement in (
            PURGE,
            "UPDATE reports SET content_purged_at = NULL WHERE id = :id",
            "UPDATE reports SET sha256 = NULL WHERE id = :id",
        ):
            assert _code(session, statement, report) == INTEGRITY_CONSTRAINT_VIOLATION, statement


def test_purging_must_not_change_anything_else(
    queue_engine: Engine, item: Scenario, world: World
) -> None:
    report = _report(queue_engine, item, world, expires="-1 second")

    with sessionmaker(queue_engine)() as session:
        statement = (
            "UPDATE reports SET content_purged_at = clock_timestamp(), omitted_findings = 1, "
            "truncated = true WHERE id = :id"
        )
        assert _code(session, statement, report) == INTEGRITY_CONSTRAINT_VIOLATION


def test_report_content_can_only_be_rotated_while_kept(
    queue_engine: Engine, item: Scenario, world: World
) -> None:
    report = _report(queue_engine, item, world, expires="-1 second")
    rotate = "UPDATE report_contents SET content = :token WHERE report_id = :id"

    with sessionmaker(queue_engine)() as session:
        session.execute(text(rotate), {"id": report, "token": sealed(report, b"rotated")})
        session.commit()
        session.execute(text(PURGE), {"id": report})
        assert (
            _code(session, rotate, report, token=sealed(report, b"after purge"))
            == INTEGRITY_CONSTRAINT_VIOLATION
        )


EXCERPT_PURGE = (
    "UPDATE finding_triage_excerpts SET sealed_content = NULL, purged_at = clock_timestamp() "
    "WHERE finding_id = :id AND kind = 'request'"
)
EXCERPT_ROTATE = (
    "UPDATE finding_triage_excerpts SET sealed_content = :token "
    "WHERE finding_id = :id AND kind = 'request'"
)
EXPIRED_EXCERPT = SEALED_EXCERPT.replace(
    "now() + interval '30 days'", "now() - interval '1 second'"
)


def _expired_excerpts(engine: Engine, item: Scenario, world: World) -> None:
    """以 SQL 寫入一個人工複測事件與兩段已到期的密文。"""
    comparison = eligible(engine, item)
    values = params(
        item,
        world,
        sequence=2,
        previous_triage="confirmed",
        lifecycle="resolved",
        comparison=comparison,
        basis="manual_retest",
        evidence=ATTESTED,
    )
    with sessionmaker(engine)() as session:
        confirm(session, item, world)
        session.execute(
            text(
                "UPDATE findings SET lifecycle_state = 'resolved', triage_version = 2 "
                "WHERE id = :id"
            ),
            values,
        )
        session.execute(text(EVENT), values)
        for kind, content in (("request", REQUEST), ("response", RESPONSE)):
            session.execute(
                text(EXPIRED_EXCERPT),
                {"id": item.sqli, "kind": kind, "content": _sealed(item, kind, content)},
            )
        session.commit()


def test_excerpts_rotate_while_kept_and_are_purged_once(
    queue_owner_engine: Engine, item: Scenario, world: World
) -> None:
    _expired_excerpts(queue_owner_engine, item, world)

    with sessionmaker(queue_owner_engine)() as session:
        session.execute(
            text(EXCERPT_ROTATE), {"id": item.sqli, "token": _sealed(item, "request", REQUEST)}
        )
        session.execute(text(EXCERPT_PURGE), {"id": item.sqli})
        session.commit()
        for statement, extra in (
            (EXCERPT_PURGE, {}),
            (EXCERPT_ROTATE, {"token": _sealed(item, "request", REQUEST)}),
            ("DELETE FROM finding_triage_excerpts WHERE finding_id = :id", {}),
        ):
            error = violation(session, statement, {"id": item.sqli, **extra})
            assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION, statement
    [count] = (
        sessionmaker(queue_owner_engine)()
        .execute(
            text("SELECT count(*) FROM finding_triage_excerpts WHERE finding_id = :id"),
            {"id": item.sqli},
        )
        .one()
    )
    assert count == 2


# --- 審查之後（docs/DECISIONS.md §30.11）--------------------------------------------------------


def test_a_purge_must_delete_the_content_in_the_same_transaction(
    queue_engine: Engine, item: Scenario, world: World
) -> None:
    """只寫入 content_purged_at、沒有刪除內容就 commit：API 會回 410 而密文永遠留著
    （資料庫審查 M2）。"""
    report = _report(queue_engine, item, world, expires="-1 second")

    with sessionmaker(queue_engine)() as session:
        session.execute(text(PURGE), {"id": report})
        with pytest.raises(IntegrityError) as caught:
            session.commit()
    assert getattr(caught.value.orig, "sqlstate", None) == INTEGRITY_CONSTRAINT_VIOLATION
    with sessionmaker(queue_engine)() as session:
        purged, contents = session.execute(
            text(
                "SELECT r.content_purged_at, count(c.report_id) FROM reports AS r "
                "LEFT JOIN report_contents AS c ON c.report_id = r.id WHERE r.id = :id "
                "GROUP BY r.content_purged_at"
            ),
            {"id": report},
        ).one()
    assert (purged, contents) == (None, 1)


def test_purge_times_cannot_be_in_the_future(
    queue_engine: Engine, item: Scenario, world: World
) -> None:
    report = _report(queue_engine, item, world, expires="-1 second")
    _expired_excerpts(queue_engine, item, world)
    later = "clock_timestamp() + interval '1 day'"

    with sessionmaker(queue_engine)() as session:
        assert (
            _code(session, PURGE.replace("clock_timestamp()", later), report)
            == INTEGRITY_CONSTRAINT_VIOLATION
        )
        error = violation(
            session, EXCERPT_PURGE.replace("clock_timestamp()", later), {"id": item.sqli}
        )
        assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION
