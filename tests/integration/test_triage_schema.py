"""T21 的 DB 層強制（G3）：繞過 app、直接以 SQL 寫入的 triage 變更都被 trigger 或 CHECK 擋下。

每個 finding 的 triage 欄位只能在版本恰好 +1 時改、每次升版都要有恰好一筆事件；事件、摘錄不可
修改；resolve 時 watermark 由 trigger 寫入，target 有進行中的 scan 時拒絕。
"""

import hashlib
import json
from collections.abc import Iterator
from uuid import UUID

import psycopg
import pytest
from alembic import command
from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from secscan.findings.domain.triage import EXCERPT_MAX_BYTES, ExcerptKind, excerpt_context
from secscan.findings.models import FindingModel
from secscan.migrations import alembic_config
from secscan.scans.domain.catalog import Engine as ScanEngine
from tests.integration.api_support import Seeder, World
from tests.integration.finding_support import web_scan
from tests.integration.sql_support import (
    CHECK_VIOLATION,
    INTEGRITY_CONSTRAINT_VIOLATION,
    violation,
)
from tests.integration.triage_support import Scenario, eligible, scenario
from tests.secret_support import shared_content_cipher

pytestmark = pytest.mark.integration

BUMP = (
    "UPDATE findings SET triage_state = :triage, lifecycle_state = :lifecycle, "
    "triage_version = triage_version + 1 WHERE id = :id"
)
EVENT = (
    "INSERT INTO finding_triage_events (finding_id, target_id, sequence, actor_kind, "
    "actor_key_id, previous_triage_state, triage_state, previous_lifecycle_state, "
    "lifecycle_state, reason_code, reason, comparison_id, resolution_basis, evidence) "
    "VALUES (:id, :target, :sequence, 'key', :actor, :previous_triage, :triage, "
    ":previous_lifecycle, :lifecycle, 'manual', 'sql', :comparison, :basis, "
    "CAST(:evidence AS jsonb))"
)


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


@pytest.fixture
def item(queue_engine: Engine, queue_seed: Seeder, world: World) -> Scenario:
    return scenario(queue_engine, queue_seed, world)


@pytest.fixture
def session(queue_engine: Engine) -> Iterator[Session]:
    with sessionmaker(queue_engine)() as opened:
        yield opened
        opened.rollback()


def params(item: Scenario, world: World, **changes: object) -> dict[str, object]:
    values: dict[str, object] = {
        "id": item.sqli,
        "target": item.target.id,
        "sequence": 1,
        "actor": world.operator_a.principal.key_id,
        "previous_triage": "unreviewed",
        "triage": "confirmed",
        "previous_lifecycle": "open",
        "lifecycle": "open",
        "comparison": None,
        "basis": None,
        "evidence": "{}",
        "run": None,
        "scan": None,
    }
    return {**values, **changes}


def confirm(session: Session, item: Scenario, world: World) -> None:
    values = params(item, world)
    session.execute(text(BUMP), values)
    session.execute(text(EVENT), values)


def code_of(error: psycopg.Error) -> str | None:
    return error.sqlstate


def test_triage_columns_only_change_with_an_exact_version_bump(
    session: Session, item: Scenario, world: World
) -> None:
    cases = (
        "UPDATE findings SET triage_state = 'confirmed' WHERE id = :id",
        "UPDATE findings SET triage_state = 'confirmed', triage_version = 2 WHERE id = :id",
        "UPDATE findings SET triage_version = 1 WHERE id = :id",
        "UPDATE findings SET triage_state = 'confirmed', lifecycle_state = 'resolved', "
        "triage_version = 1 WHERE id = :id",
        "UPDATE findings SET lifecycle_state = 'reopened', triage_version = 1 WHERE id = :id",
        "UPDATE findings SET resolved_scan_position = 1 WHERE id = :id",
    )
    for statement in cases:
        error = violation(session, statement, {"id": item.sqli})
        assert code_of(error) == INTEGRITY_CONSTRAINT_VIOLATION, statement


def test_every_version_needs_exactly_one_event_at_commit(
    queue_engine: Engine, item: Scenario, world: World
) -> None:
    sessions = sessionmaker(queue_engine)
    second = (
        "UPDATE findings SET triage_state = 'false_positive', "
        "triage_version = triage_version + 1 WHERE id = :id"
    )
    for statements in ([BUMP], [BUMP, EVENT, second]):
        with sessions() as opened:
            for statement in statements:
                opened.execute(text(statement), params(item, world))
            with pytest.raises(IntegrityError, match="triage event"):
                opened.commit()
    with sessions() as opened:
        opened.execute(text(BUMP), params(item, world))
        with pytest.raises(IntegrityError, match="triage event"):
            opened.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))


def test_events_must_follow_the_chain(session: Session, item: Scenario, world: World) -> None:
    session.execute(text(BUMP), params(item, world))
    for changes in (
        {"sequence": 2},
        {"previous_triage": "false_positive"},
        {"triage": "accepted_risk"},
    ):
        error = violation(session, EVENT, params(item, world, **changes))
        assert code_of(error) in {INTEGRITY_CONSTRAINT_VIOLATION, CHECK_VIOLATION}, changes
    session.execute(text(EVENT), params(item, world))
    session.flush()


def test_event_checks_reject_inconsistent_rows(
    queue_engine: Engine, session: Session, item: Scenario, world: World
) -> None:
    comparison = eligible(queue_engine, item)
    session.execute(text(BUMP), params(item, world))
    for changes in (
        {"comparison": comparison, "basis": "manual_retest"},
        {"evidence": '{"excerpt": "x"}'},
        {"evidence": '{"attestation": {"provenance": "operator_supplied"}}'},
    ):
        error = violation(session, EVENT, params(item, world, **changes))
        assert code_of(error) == CHECK_VIOLATION, changes
    system = (
        "INSERT INTO finding_triage_events (finding_id, target_id, sequence, actor_kind, "
        "previous_triage_state, triage_state, previous_lifecycle_state, lifecycle_state, "
        "reason_code, reason) VALUES (:id, :target, 1, 'system', 'unreviewed', 'confirmed', "
        "'open', 'open', 'auto_reopen_new_observation', 'sql')"
    )
    assert code_of(violation(session, system, params(item, world))) == CHECK_VIOLATION


def test_resolved_requires_confirmed_and_an_idle_target(
    queue_engine: Engine, queue_seed: Seeder, session: Session, item: Scenario, world: World
) -> None:
    resolve = (
        "UPDATE findings SET lifecycle_state = 'resolved', triage_version = triage_version + 1, "
        "resolved_scan_position = 999999 WHERE id = :id"
    )
    assert code_of(violation(session, resolve, {"id": item.sqli})) == CHECK_VIOLATION
    session.commit()
    confirm(session, item, world)
    session.commit()
    queued = web_scan(queue_seed, world, item.target, item.grant_id, (ScanEngine.ZAP,))
    error = violation(session, resolve, {"id": item.sqli})
    assert error.diag.constraint_name == "findings_resolve_target_busy"
    assert queued is not None


def test_the_trigger_writes_the_watermark_not_the_application(
    queue_engine: Engine, queue_seed: Seeder, session: Session, item: Scenario, world: World
) -> None:
    comparison = eligible(queue_engine, item)
    confirm(session, item, world)
    session.execute(
        text(
            "UPDATE findings SET lifecycle_state = 'resolved', triage_version = 2, "
            "resolved_scan_position = 999999, resolved_link_count = 0 WHERE id = :id"
        ),
        {"id": item.sqli},
    )
    session.execute(
        text(EVENT),
        params(
            item,
            world,
            sequence=2,
            previous_triage="confirmed",
            previous_lifecycle="open",
            lifecycle="resolved",
            comparison=comparison,
            basis="rescan_not_observed",
        ),
    )
    session.commit()
    [row] = queue_seed.query(
        "SELECT f.resolved_scan_position, f.resolved_link_count, f.observations_linked, "
        "(SELECT max(queue_position) FROM scans WHERE target_id = f.target_id) AS watermark "
        "FROM findings f WHERE f.id = :id",
        id=item.sqli,
    )
    assert row.resolved_scan_position == row.watermark
    assert row.resolved_link_count == row.observations_linked


def test_events_and_excerpts_are_append_only(
    queue_engine: Engine, queue_seed: Seeder, session: Session, item: Scenario, world: World
) -> None:
    confirm(session, item, world)
    session.commit()
    for statement in (
        "UPDATE finding_triage_events SET reason = 'changed' WHERE finding_id = :id",
        "DELETE FROM finding_triage_events WHERE finding_id = :id",
        "TRUNCATE finding_triage_events CASCADE",
    ):
        error = violation(session, statement, {"id": item.sqli})
        assert code_of(error) == INTEGRITY_CONSTRAINT_VIOLATION, statement


def _sealed(item: Scenario, kind: str, content: str) -> bytes:
    finding_kind = ExcerptKind(kind)
    return shared_content_cipher().seal(
        content.encode(),
        context=excerpt_context(item.sqli, 2, finding_kind),
        max_bytes=EXCERPT_MAX_BYTES[finding_kind],
    )


SEALED_EXCERPT = (
    "INSERT INTO finding_triage_excerpts (finding_id, sequence, kind, sealed_content, expires_at) "
    "VALUES (:id, 2, :kind, :content, now() + interval '30 days')"
)


def test_excerpts_are_sealed_complete_and_immutable(
    queue_engine: Engine, item: Scenario, world: World
) -> None:
    """TRIAGE-06（v0022 修訂）：摘錄必須是密文（Fernet token 的形狀）、每個人工複測事件恰好兩段，
    之後只能換版或到期清除（見 test_sealed_content_schema.py）。明文的雜湊與長度改由 api 核對。"""
    comparison = eligible(queue_engine, item)
    sessions = sessionmaker(queue_engine)
    request, response = "GET / HTTP/1.1", "HTTP/1.1 200"
    valid = json.dumps(
        {
            "attestation": {
                "provenance": "operator_supplied",
                "request_excerpt_sha256": hashlib.sha256(request.encode()).hexdigest(),
                "request_excerpt_bytes": len(request),
                "response_excerpt_sha256": hashlib.sha256(response.encode()).hexdigest(),
                "response_excerpt_bytes": len(response),
            }
        }
    )
    resolve_values = params(
        item,
        world,
        sequence=2,
        previous_triage="confirmed",
        lifecycle="resolved",
        comparison=comparison,
        basis="manual_retest",
        evidence=valid,
    )
    resolve = "UPDATE findings SET lifecycle_state = 'resolved', triage_version = 2 WHERE id = :id"
    with sessions() as opened:
        confirm(opened, item, world)
        opened.execute(text(resolve), resolve_values)
        opened.execute(text(EVENT), resolve_values)
        plaintext = {"id": item.sqli, "kind": "request", "content": request.encode()}
        assert code_of(violation(opened, SEALED_EXCERPT, plaintext)) == "23514"
        empty = {"id": item.sqli, "kind": "request", "content": None}
        error = violation(opened, SEALED_EXCERPT, empty)
        assert "must be sealed" in str(error)
        opened.execute(
            text(SEALED_EXCERPT),
            {"id": item.sqli, "kind": "request", "content": _sealed(item, "request", request)},
        )
        with pytest.raises(IntegrityError, match="both excerpts"):
            opened.commit()
    with sessions() as opened:
        confirm(opened, item, world)
        opened.execute(text(resolve), resolve_values)
        opened.execute(text(EVENT), resolve_values)
        for kind, content in (("request", request), ("response", response)):
            opened.execute(
                text(SEALED_EXCERPT),
                {"id": item.sqli, "kind": kind, "content": _sealed(item, kind, content)},
            )
        opened.commit()
        error = violation(
            opened,
            "UPDATE finding_triage_excerpts SET sealed_content = 'x' WHERE finding_id = :id",
            {"id": item.sqli},
        )
        assert code_of(error) == "23514"
        for statement in (
            "UPDATE finding_triage_excerpts SET expires_at = now() WHERE finding_id = :id",
            "UPDATE finding_triage_excerpts SET sealed_content = NULL, purged_at = now() "
            "WHERE finding_id = :id",
            "DELETE FROM finding_triage_excerpts WHERE finding_id = :id",
            "TRUNCATE finding_triage_excerpts",
        ):
            error = violation(opened, statement, {"id": item.sqli})
            assert code_of(error) == INTEGRITY_CONSTRAINT_VIOLATION, statement


def test_new_findings_start_at_version_zero(session: Session, item: Scenario) -> None:
    columns = [column.name for column in FindingModel.__table__.columns if column.name != "id"]
    selected = [
        "repeat('9', 64)" if name == "fingerprint" else ("1" if name == "triage_version" else name)
        for name in columns
    ]
    statement = (
        f"INSERT INTO findings ({', '.join(columns)}) "  # noqa: S608 - 欄位名稱來自 ORM model
        f"SELECT {', '.join(selected)} FROM findings WHERE id = :id"
    )
    error = violation(session, statement, {"id": item.sqli})
    assert code_of(error) == INTEGRITY_CONSTRAINT_VIOLATION
    assert isinstance(item.sqli, UUID)


def test_manual_retest_events_need_an_operator_supplied_attestation_object(
    queue_engine: Engine, session: Session, item: Scenario, world: World
) -> None:
    comparison = eligible(queue_engine, item)
    confirm(session, item, world)
    session.execute(
        text("UPDATE findings SET lifecycle_state = 'resolved', triage_version = 2 WHERE id = :id"),
        {"id": item.sqli},
    )
    for attestation in ('{"attestation": {}}', '{"attestation": null}', '{"attestation": "x"}'):
        values = params(
            item,
            world,
            sequence=2,
            previous_triage="confirmed",
            lifecycle="resolved",
            comparison=comparison,
            basis="manual_retest",
            evidence=attestation,
        )
        error = violation(session, EVENT, values)
        assert error.diag.constraint_name == "ck_finding_triage_events_attestation_valid"


def test_system_events_cannot_cite_a_run_of_another_target(
    queue_engine: Engine, queue_seed: Seeder, session: Session, item: Scenario, world: World
) -> None:
    other = scenario(queue_engine, queue_seed, queue_seed.world())
    [run] = queue_seed.query(
        "SELECT id, scan_id FROM scanner_runs WHERE scan_id = :scan", scan=other.baseline
    )
    session.execute(text(BUMP), params(item, world))
    system = (
        "INSERT INTO finding_triage_events (finding_id, target_id, sequence, actor_kind, "
        "previous_triage_state, triage_state, previous_lifecycle_state, lifecycle_state, "
        "reason_code, reason, run_id, scan_id) VALUES (:id, :target, 1, 'system', "
        "'unreviewed', 'confirmed', 'open', 'open', 'auto_reopen_new_observation', 'sql', "
        ":run, :scan)"
    )
    error = violation(session, system, params(item, world, run=run.id, scan=run.scan_id))
    assert "another target" in str(error)


def test_downgrade_with_resolved_findings_succeeds(
    queue_engine: Engine, queue_seed: Seeder, item: Scenario, world: World
) -> None:
    comparison = eligible(queue_engine, item)
    with sessionmaker(queue_engine)() as opened:
        confirm(opened, item, world)
        opened.execute(
            text(
                "UPDATE findings SET lifecycle_state = 'resolved', triage_version = 2 "
                "WHERE id = :id"
            ),
            {"id": item.sqli},
        )
        opened.execute(
            text(EVENT),
            params(
                item,
                world,
                sequence=2,
                previous_triage="confirmed",
                lifecycle="resolved",
                comparison=comparison,
                basis="rescan_not_observed",
            ),
        )
        opened.commit()
    with queue_engine.begin() as connection:
        command.downgrade(alembic_config(connection=connection), "0016")
    [row] = queue_seed.query(
        "SELECT triage_state, lifecycle_state FROM findings WHERE id = :id", id=item.sqli
    )
    assert (row.triage_state, row.lifecycle_state) == ("unreviewed", "open")
    with queue_engine.begin() as connection:
        command.upgrade(alembic_config(connection=connection), "head")
