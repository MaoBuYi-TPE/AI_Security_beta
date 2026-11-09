"""secscan-admin rotate-content-keys（ROT-01 的內容部分；docs/DECISIONS.md §30.6）。

報告與摘錄以舊金鑰加密；換版之後只有新金鑰也解得開，可以重複執行；解不開的保留原狀並列出 id。
清除過的報告與摘錄沒有內容，略過。設定以環境變數指向這個測試的資料庫。
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.cli import EXIT_FAILURE, EXIT_OK, main
from secscan.findings.domain.model import LifecycleState, TriageState
from secscan.findings.domain.triage import (
    EXCERPT_MAX_BYTES,
    ExcerptKind,
    ResolutionBasis,
    excerpt_context,
)
from secscan.reports.domain.model import MAX_REPORT_BYTES, ReportFormat, report_context
from secscan.reports.service import ReportService
from secscan.security.blob_cipher import BlobCipher
from secscan.security.key_rings import content_cipher
from secscan.triage.domain.attestation import Attestation
from secscan.triage.service import TriageCommand, TriageService
from secscan.worker.reports import ReportWorker
from secscan.worker.retention import ContentRetention
from tests.integration.api_support import LAB, Seeder, World
from tests.integration.database import ProvisionedDatabase
from tests.integration.triage_support import Scenario, db_now, eligible, scenario

pytestmark = pytest.mark.integration


def _key() -> str:
    return Fernet.generate_key().decode()


@pytest.fixture
def old_key() -> str:
    return _key()


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


@pytest.fixture
def item(queue_engine: Engine, queue_seed: Seeder, world: World) -> Scenario:
    return scenario(queue_engine, queue_seed, world)


@pytest.fixture
def environment(queue_database: ProvisionedDatabase, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("DB_HOST", queue_database.host)
    monkeypatch.setenv("DB_PORT", str(queue_database.port))
    monkeypatch.setenv("DB_NAME", queue_database.name)
    monkeypatch.setenv("DB_USER", queue_database.user)
    monkeypatch.setenv("DB_PASSWORD", queue_database.password)


def _report(engine: Engine, world: World, item: Scenario, cipher: BlobCipher) -> UUID:
    sessions = sessionmaker(engine, expire_on_commit=False)
    with sessions.begin() as session:
        report, _ = ReportService(session, lab=LAB).create(
            world.operator_a.principal,
            item.baseline,
            ReportFormat.JSON,
            idempotency_key=uuid4().hex,
            request_id=None,
        )
    worker = ReportWorker(sessions, owner="worker-k", cipher=cipher, retention=timedelta(days=30))
    assert worker.drain() == 1
    return report.id


def _excerpts(
    engine: Engine, seed: Seeder, world: World, item: Scenario, cipher: BlobCipher
) -> None:
    comparison = eligible(engine, item)
    proof = Attestation(
        performed_at=db_now(seed),
        performed_by="operator",
        procedure="複測",
        result="not_reproduced",
        auth_role="anonymous",
        request_excerpt=f"GET /search?q=1 HTTP/1.1\nHost: {item.host}\n",
        response_excerpt="HTTP/1.1 200\n\n[]",
    )
    with sessionmaker(engine).begin() as session:
        service = TriageService(session, cipher=cipher)
        principal = world.operator_a.principal
        confirm = TriageCommand(expected_version=0, reason="確認", triage=TriageState.CONFIRMED)
        service.change(principal, item.sqli, confirm, request_id=None)
        resolve = TriageCommand(
            expected_version=1,
            reason="人工複測",
            lifecycle=LifecycleState.RESOLVED,
            basis=ResolutionBasis.MANUAL_RETEST,
            comparison_id=comparison,
            attestation=proof,
        )
        service.change(principal, item.sqli, resolve, request_id=None)


def _readable(seed: Seeder, cipher: BlobCipher, report: UUID, finding: UUID) -> bool:
    [stored] = seed.query("SELECT content FROM report_contents WHERE report_id = :id", id=report)
    cipher.unseal(bytes(stored.content), context=report_context(report), max_bytes=MAX_REPORT_BYTES)
    for row in seed.query(
        "SELECT kind, sealed_content FROM finding_triage_excerpts WHERE finding_id = :id",
        id=finding,
    ):
        kind = ExcerptKind(row.kind)
        cipher.unseal(
            bytes(row.sealed_content),
            context=excerpt_context(finding, 2, kind),
            max_bytes=EXCERPT_MAX_BYTES[kind],
        )
    return True


def test_rotation_moves_reports_and_excerpts_to_the_new_key(
    environment: None,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    item: Scenario,
    old_key: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report = _report(queue_engine, world, item, content_cipher(old_key))
    _excerpts(queue_engine, queue_seed, world, item, content_cipher(old_key))
    new_key = _key()
    monkeypatch.setenv("CONTENT_ENCRYPTION_KEYS", f"{new_key},{old_key}")

    assert main(["rotate-content-keys"]) == EXIT_OK

    err = capsys.readouterr().err
    assert "1 份報告、2 段人工複測摘錄" in err
    assert old_key not in err
    assert new_key not in err
    assert _readable(queue_seed, content_cipher(new_key), report, item.sqli)
    [audit] = queue_seed.query(
        "SELECT redacted_changes AS changes, actor_key_id FROM audit_events "
        "WHERE action = 'content_keys.rotate'"
    )
    assert audit.changes == {"reports": 1, "excerpts": 2, "failures": 0}
    assert audit.actor_key_id is None
    monkeypatch.setenv("CONTENT_ENCRYPTION_KEYS", new_key)
    assert main(["rotate-content-keys"]) == EXIT_OK


def test_unreadable_content_is_kept_and_listed(
    environment: None,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    item: Scenario,
    old_key: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report = _report(queue_engine, world, item, content_cipher(old_key))
    [before] = queue_seed.query(
        "SELECT content FROM report_contents WHERE report_id = :id", id=report
    )
    monkeypatch.setenv("CONTENT_ENCRYPTION_KEYS", _key())

    assert main(["rotate-content-keys"]) == EXIT_FAILURE

    err = capsys.readouterr().err
    assert str(report) in err
    [after] = queue_seed.query(
        "SELECT content FROM report_contents WHERE report_id = :id", id=report
    )
    assert bytes(after.content) == bytes(before.content)


def test_rotation_needs_the_content_keys(
    environment: None, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["rotate-content-keys"]) == EXIT_FAILURE

    assert "缺少 CONTENT_ENCRYPTION_KEYS" in capsys.readouterr().err


def test_purged_reports_are_skipped(
    environment: None,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    item: Scenario,
    old_key: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    sessions = sessionmaker(queue_engine, expire_on_commit=False)
    with sessions.begin() as session:
        ReportService(session, lab=LAB).create(
            world.operator_a.principal,
            item.baseline,
            ReportFormat.JSON,
            idempotency_key=uuid4().hex,
            request_id=None,
        )
    past = datetime.now(UTC) - timedelta(days=40)
    ReportWorker(
        sessions,
        owner="worker-k",
        cipher=content_cipher(old_key),
        retention=timedelta(days=30),
        clock=lambda: past,
    ).drain()
    assert ContentRetention(sessions).purge().reports == 1
    monkeypatch.setenv("CONTENT_ENCRYPTION_KEYS", _key())

    assert main(["rotate-content-keys"]) == EXIT_OK

    assert "0 份報告" in capsys.readouterr().err
