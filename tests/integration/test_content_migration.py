"""migration 0022 對既有資料的處理（CONT-02；docs/DECISIONS.md §30.4）。

在 0021 的 schema 以 SQL 寫入舊格式的資料（明文的報告內容與兩段人工複測摘錄），再升級：
- 有金鑰：明文核對之後加密（context 和 app 相同，API 解得開）、期限是升級時間加 30 天；
- 有舊資料而缺少金鑰、或舊內容和 sha256 不符：整個升級回滾，資料不變；
- 離線模式（--sql）的 SQL 先確認沒有舊資料；有密文之後拒絕 downgrade。
每個測試用全新的資料庫。
"""

import hashlib
import io
import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from secscan.findings.domain.triage import EXCERPT_MAX_BYTES, ExcerptKind, excerpt_context
from secscan.main import create_app
from secscan.migrations import alembic_config, head_revision
from secscan.reports.domain.model import MAX_REPORT_BYTES, report_context
from tests.integration.api_support import Seeder, World
from tests.integration.conftest import app_engine
from tests.integration.database import ProvisionedDatabase
from tests.integration.test_triage_schema import EVENT, confirm, params
from tests.integration.triage_support import Scenario, db_now, eligible, scenario
from tests.secret_support import TEST_CONTENT_ENCRYPTION_KEYS, shared_content_cipher

pytestmark = pytest.mark.integration

LEGACY_REPORT = b'{"legacy": "canary-legacy-report-2c9e"}'
REQUEST, RESPONSE = "GET / HTTP/1.1", "HTTP/1.1 200 canary-legacy-excerpt"


@pytest.fixture
def engine(fresh_database: ProvisionedDatabase) -> Iterator[Engine]:
    opened = app_engine(fresh_database)
    _migrate(opened, "up", "0021")
    yield opened
    opened.dispose()


def _migrate(engine: Engine, direction: str, target: str, keys: str | None = None) -> None:
    with engine.begin() as connection:
        config = alembic_config(connection=connection, content_encryption_keys=keys)
        if direction == "up":
            command.upgrade(config, target)
        else:
            command.downgrade(config, target)


def _revision(engine: Engine) -> str:
    with engine.connect() as connection:
        return str(connection.execute(text("SELECT version_num FROM alembic_version")).scalar())


@contextmanager
def _holds_table_for_the_orm(engine: Engine) -> Iterator[None]:
    """建立 scan 的程式碼會讀 evidence_holds（0023 才建立，docs/DECISIONS.md §30.12），而這裡在
    0021 的 schema 上寫入舊資料：期間暫時建立一張空的同名資料表，升級之前刪除。"""
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE evidence_holds (directory uuid PRIMARY KEY, scanner_run_id uuid, "
                "scan_id uuid, error_code varchar(32), attempts integer, held_at timestamptz, "
                "resolved_at timestamptz)"
            )
        )
    try:
        yield
    finally:
        with engine.begin() as connection:
            connection.execute(text("DROP TABLE evidence_holds"))


def _legacy(engine: Engine) -> tuple[World, Scenario, UUID]:
    """0021 的 schema 上：一份 succeeded 的明文報告與一個附兩段明文摘錄的人工複測事件。"""
    with _holds_table_for_the_orm(engine):
        return _legacy_rows(engine)


def _legacy_rows(engine: Engine) -> tuple[World, Scenario, UUID]:
    seed = Seeder(engine)
    world = seed.world()
    item = scenario(engine, seed, world)
    comparison = eligible(engine, item)
    report = _legacy_report(engine, item, world)
    evidence = json.dumps(
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
    values = params(
        item,
        world,
        sequence=2,
        previous_triage="confirmed",
        lifecycle="resolved",
        comparison=comparison,
        basis="manual_retest",
        evidence=evidence,
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
                text(
                    "INSERT INTO finding_triage_excerpts (finding_id, sequence, kind, content) "
                    "VALUES (:id, 2, :kind, :content)"
                ),
                {"id": item.sqli, "kind": kind, "content": content},
            )
        session.commit()
    return world, item, report


def _legacy_report(engine: Engine, item: Scenario, world: World) -> UUID:
    with sessionmaker(engine)() as session:
        report = session.execute(
            text(
                "INSERT INTO reports (project_id, target_id, scan_id, format, schema_version, "
                "status, idempotency_key, request_sha256, requested_by_key_id, attempts) "
                "VALUES (:project, :target, :scan, 'json', 1, 'queued', :key, :sha, :actor, 0) "
                "RETURNING id"
            ),
            {
                "project": item.target.project_id,
                "target": item.target.id,
                "scan": item.baseline,
                "key": uuid4().hex,
                "sha": b"\x00" * 32,
                "actor": world.operator_a.principal.key_id,
            },
        ).scalar_one()
        session.execute(
            text(
                "UPDATE reports SET status = 'generating', attempts = 1, lease_owner = 'w', "
                "lease_expires_at = now() + interval '30 seconds' WHERE id = :id"
            ),
            {"id": report},
        )
        session.execute(
            text(
                "INSERT INTO report_contents (report_id, attempt, lease_owner, content) "
                "VALUES (:id, 1, 'w', :content)"
            ),
            {"id": report, "content": LEGACY_REPORT},
        )
        session.execute(
            text(
                "UPDATE reports SET status = 'succeeded', lease_owner = NULL, "
                "lease_expires_at = NULL, data_as_of = now(), generated_at = now(), "
                "size_bytes = :size, sha256 = :sha, truncated = false, omitted_findings = 0, "
                "finished_at = now() WHERE id = :id"
            ),
            {
                "id": report,
                "size": len(LEGACY_REPORT),
                "sha": hashlib.sha256(LEGACY_REPORT).hexdigest(),
            },
        )
        session.commit()
    assert isinstance(report, UUID)
    return report


def test_existing_content_is_encrypted_and_gets_thirty_days(
    engine: Engine, fresh_database: ProvisionedDatabase
) -> None:
    world, item, report = _legacy(engine)

    _migrate(engine, "up", "head", TEST_CONTENT_ENCRYPTION_KEYS)

    assert _revision(engine) == head_revision()
    seed = Seeder(engine)
    now = db_now(seed)
    cipher = shared_content_cipher()
    [stored] = seed.query(
        "SELECT c.content, r.expires_at FROM report_contents c JOIN reports r ON r.id = c.report_id"
    )
    assert bytes(stored.content).startswith(b"gAAAAA")
    assert b"canary-legacy" not in bytes(stored.content)
    opened = cipher.unseal(
        bytes(stored.content), context=report_context(report), max_bytes=MAX_REPORT_BYTES
    )
    assert opened == LEGACY_REPORT
    assert timedelta(days=29) < stored.expires_at - now <= timedelta(days=30)
    excerpts = seed.query(
        "SELECT kind, sealed_content, expires_at, purged_at FROM finding_triage_excerpts "
        "ORDER BY kind"
    )
    for row, expected in zip(excerpts, (REQUEST, RESPONSE), strict=True):
        kind = ExcerptKind(row.kind)
        content = cipher.unseal(
            bytes(row.sealed_content),
            context=excerpt_context(item.sqli, 2, kind),
            max_bytes=EXCERPT_MAX_BYTES[kind],
        )
        assert content == expected.encode()
        assert row.purged_at is None
        assert timedelta(days=29) < row.expires_at - now <= timedelta(days=30)
    columns = seed.query(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_name = 'finding_triage_excerpts' AND column_name = 'content'"
    )
    assert columns == []
    with TestClient(create_app(fresh_database.app_settings())) as client:
        downloaded = client.get(
            f"/api/v1/reports/{report}/download", headers=world.operator_a.headers
        )
        assert downloaded.content == LEGACY_REPORT
        events = client.get(
            f"/api/v1/findings/{item.sqli}/triage-events", headers=world.operator_a.headers
        ).json()["data"]
        assert {e["content"] for e in events[1]["excerpts"]} == {REQUEST, RESPONSE}


def test_existing_content_needs_the_key_and_nothing_changes_without_it(engine: Engine) -> None:
    _legacy(engine)

    with pytest.raises(RuntimeError, match="CONTENT_ENCRYPTION_KEYS"):
        _migrate(engine, "up", "head")

    assert _revision(engine) == "0021"
    [stored] = Seeder(engine).query("SELECT content FROM report_contents")
    assert bytes(stored.content) == LEGACY_REPORT


def test_tampered_existing_content_stops_the_upgrade(engine: Engine) -> None:
    _legacy(engine)
    with engine.begin() as connection:
        connection.execute(
            text("ALTER TABLE report_contents DISABLE TRIGGER report_contents_immutable")
        )
        connection.execute(text("UPDATE report_contents SET content = 'tampered'"))
        connection.execute(
            text("ALTER TABLE report_contents ENABLE TRIGGER report_contents_immutable")
        )

    with pytest.raises(RuntimeError, match="sha256"):
        _migrate(engine, "up", "head", TEST_CONTENT_ENCRYPTION_KEYS)

    assert _revision(engine) == "0021"


def test_an_empty_database_needs_no_key(engine: Engine) -> None:
    _migrate(engine, "up", "head")

    assert _revision(engine) == head_revision()
    _migrate(engine, "down", "0021")
    assert _revision(engine) == "0021"


def test_downgrade_is_refused_once_content_is_encrypted(engine: Engine) -> None:
    _legacy(engine)
    _migrate(engine, "up", "head", TEST_CONTENT_ENCRYPTION_KEYS)

    with pytest.raises(DBAPIError, match="encrypted or purged content"):
        _migrate(engine, "down", "0021")

    assert _revision(engine) == head_revision()


def test_offline_sql_refuses_existing_content() -> None:
    config = alembic_config()
    buffer = io.StringIO()
    config.output_buffer = buffer

    command.upgrade(config, "0021:0022", sql=True)

    script = buffer.getvalue()
    assert "must be encrypted" in script
    assert "ALTER TABLE finding_triage_excerpts DROP COLUMN content" in script
    assert "gAAAAA" in script
