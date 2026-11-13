"""migration：全新 DB 可升到 head、可完整降回 base 再升上去，且 model 與 migration 沒有漂移。"""

from pathlib import Path
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import Engine, inspect, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from secscan.cli.services import audit_local
from secscan.migrations import alembic_config, head_revision
from secscan.migrations.metadata import target_metadata
from secscan.scans.domain.allocation import EngineBudgetRequest
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.service import ScanService
from tests.integration.conftest import owner_alembic_config, owner_engine
from tests.integration.database import ProvisionedDatabase
from tests.integration.scan_support import web_scan
from tests.integration.scope_support import LAB

pytestmark = pytest.mark.integration

APP_TABLES = {
    "projects",
    "api_keys",
    "audit_events",
    "targets",
    "scope_grants",
    "api_specs",
    "api_spec_operations",
    "auth_profiles",
    "auth_profile_versions",
    "scans",
    "scanner_runs",
    "scan_events",
    "scan_operations",
    "runner_instances",
    "run_coverage",
    "run_locations",
    "run_rule_locations",
    "artifacts",
    "observations",
    "findings",
    "finding_observations",
    "scan_comparisons",
    "scan_comparison_findings",
    "finding_triage_events",
    "finding_triage_excerpts",
    "reports",
    "report_contents",
    "run_evidence",
    "evidence_holds",
}
TRIGGER_FUNCTIONS = (
    "audit_events_reject_mutation",
    "scope_grants_guard",
    "api_specs_guard",
    "auth_profiles_guard",
    "auth_profile_versions_guard",
    "scans_guard",
    "scanner_runs_guard",
    "scan_records_guard",
    "scan_operations_insert_guard",
    "scanner_runs_container_guard",
    "scanner_runs_comparison_once",
    "run_locations_insert_guard",
    "scan_comparison_guard",
    "scan_comparison_finding_insert_guard",
    "scan_comparison_sealed_check",
    "findings_guard",
    "findings_triage_logged",
    "finding_triage_events_chain",
    "finding_triage_excerpts_insert",
    "finding_triage_excerpts_complete",
    "reports_guard",
    "report_contents_insert_guard",
    "reports_content_check",
    "report_contents_parent_check",
    "auth_profiles_update_guard",
    "auth_profiles_disabled_erased",
    "scanner_runs_engine_budget_frozen",
    "scanner_runs_allotment_once",
    "run_evidence_guard",
    "report_contents_guard",
    "finding_triage_excerpts_guard",
    "reports_purge_complete",
    "evidence_holds_guard",
    "run_evidence_hold_check",
)


def _migrate(engine: Engine, direction: str, target: str) -> None:
    """以 owner 的 engine 升降級（T23b-b1）。"""
    with engine.begin() as connection:
        config = owner_alembic_config(connection)
        if direction == "up":
            command.upgrade(config, target)
        else:
            command.downgrade(config, target)


def _tables(engine: Engine) -> set[str]:
    return set(inspect(engine).get_table_names())


def _current_revisions(engine: Engine) -> list[str]:
    with engine.connect() as connection:
        rows = connection.execute(text("SELECT version_num FROM alembic_version"))
        return list(rows.scalars())


def _existing_functions(engine: Engine) -> set[str]:
    with engine.connect() as connection:
        return {
            name
            for name in TRIGGER_FUNCTIONS
            if connection.execute(
                text("SELECT to_regprocedure(:signature)"), {"signature": f"{name}()"}
            ).scalar()
            is not None
        }


def test_fresh_database_upgrades_to_head(fresh_database: ProvisionedDatabase) -> None:
    engine = owner_engine(fresh_database)
    try:
        _migrate(engine, "up", "head")

        assert _tables(engine) == APP_TABLES | {"alembic_version"}
        assert _current_revisions(engine) == [head_revision()]
        assert _existing_functions(engine) == set(TRIGGER_FUNCTIONS)
    finally:
        engine.dispose()


def test_downgrade_to_base_then_upgrade_again(fresh_database: ProvisionedDatabase) -> None:
    engine = owner_engine(fresh_database)
    try:
        _migrate(engine, "up", "head")
        _migrate(engine, "down", "base")

        assert _tables(engine) == {"alembic_version"}
        assert _current_revisions(engine) == []
        assert _existing_functions(engine) == set()

        _migrate(engine, "up", "head")

        assert _tables(engine) == APP_TABLES | {"alembic_version"}
    finally:
        engine.dispose()


def test_models_and_migrations_do_not_drift(db_engine: Engine) -> None:
    """model 改了卻沒寫 migration（或反過來）時，autogenerate 會看到差異。"""
    with db_engine.connect() as connection:
        context = MigrationContext.configure(
            connection, opts={"compare_type": True, "compare_server_default": True}
        )
        differences = compare_metadata(context, target_metadata)

    assert differences == []


def test_env_reads_connection_from_settings(
    fresh_database: ProvisionedDatabase, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`make migrate` 的路徑：不傳連線時，env.py 依 DB_* 環境變數連線（這裡不讀 repo 的 .env）。

    以 DB_OWNER_* 的 owner 連線；應用程式角色取自 DB_USER（v0025 依它授權）。
    """
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.setenv("DB_HOST", fresh_database.host)
    monkeypatch.setenv("DB_PORT", str(fresh_database.port))
    monkeypatch.setenv("DB_NAME", fresh_database.name)
    monkeypatch.setenv("DB_USER", fresh_database.user)
    monkeypatch.setenv("DB_PASSWORD", fresh_database.password)
    monkeypatch.setenv("DB_OWNER_USER", fresh_database.owner_user)
    monkeypatch.setenv("DB_OWNER_PASSWORD", fresh_database.owner_password)

    command.upgrade(alembic_config(), "head")

    engine = owner_engine(fresh_database)
    try:
        assert _current_revisions(engine) == [head_revision()]
    finally:
        engine.dispose()


def test_downgrade_refuses_unfinished_runs_with_engine_budgets(
    fresh_database: ProvisionedDatabase,
) -> None:
    """v0020（T31）：降回去時舊程式會讓它們分到剩下的全部，子預算悄悄消失，所以拒絕。"""
    engine = owner_engine(fresh_database)
    split = (
        EngineBudgetRequest(ScanEngine.ZAP, max_requests=760, max_duration_seconds=380),
        EngineBudgetRequest(ScanEngine.NUCLEI, max_requests=440, max_duration_seconds=220),
    )
    try:
        _migrate(engine, "up", "head")
        with Session(engine) as session, session.begin():
            world, scan = web_scan(
                session, engines=(ScanEngine.ZAP, ScanEngine.NUCLEI), split=split
            )

        with pytest.raises(DBAPIError, match="unfinished runs still have engine budgets"):
            _migrate(engine, "down", "0019")
        assert _current_revisions(engine) == [head_revision()]

        with Session(engine) as session, session.begin():
            ScanService(session, lab=LAB).cancel(world.operator, scan.id, request_id=None)
        _migrate(engine, "down", "0019")

        assert _current_revisions(engine) == ["0019"]
        removed = {"scanner_runs_engine_budget_frozen", "scanner_runs_allotment_once"}
        assert not removed & _existing_functions(engine)
    finally:
        engine.dispose()


@pytest.mark.parametrize("purged", [False, True])
def test_downgrade_refuses_recorded_evidence(
    fresh_database: ProvisionedDatabase, purged: bool
) -> None:
    """v0021：有 sealed 的紀錄時舊程式讀不了加密檔；有 purged 的紀錄時，降級再升級之後已清除的
    run 會被記成「從來沒有目錄」（資料庫審查 L3）。兩者都拒絕。"""
    engine = owner_engine(fresh_database)
    try:
        _migrate(engine, "up", "head")
        with Session(engine) as session, session.begin():
            world, scan = web_scan(session, engines=(ScanEngine.ZAP,))
            ScanService(session, lab=LAB).cancel(world.operator, scan.id, request_id=None)
        with Session(engine) as session, session.begin():
            run_id, scan_id = session.execute(
                text("SELECT id, scan_id FROM scanner_runs WHERE scan_id = :scan"),
                {"scan": scan.id},
            ).one()
            session.execute(
                text(
                    "INSERT INTO run_evidence (scanner_run_id, scan_id, status, file_count, "
                    "plaintext_bytes, sealed_at) VALUES (:run, :scan, 'sealed', 1, 1, "
                    "now() - interval '8 days')"
                ),
                {"run": run_id, "scan": scan_id},
            )
            if purged:
                session.execute(
                    text(
                        "UPDATE run_evidence SET status = 'purged', purged_at = now() "
                        "WHERE scanner_run_id = :run"
                    ),
                    {"run": run_id},
                )

        with pytest.raises(DBAPIError, match="recorded evidence exists"):
            _migrate(engine, "down", "0020")
        assert _current_revisions(engine) == [head_revision()]
    finally:
        engine.dispose()


@pytest.mark.parametrize("resolved", [False, True])
def test_downgrade_refuses_evidence_holds(
    fresh_database: ProvisionedDatabase, resolved: bool
) -> None:
    """v0023：舊程式不認得隔離，會讓 keeper 再次一直加密失敗；已解除的紀錄是處置的稽核依據
    （docs/DECISIONS.md §30.12）。兩者都拒絕，沒有紀錄時可以降級。"""
    engine = owner_engine(fresh_database)
    try:
        _migrate(engine, "up", "head")
        with Session(engine) as session, session.begin():
            world, scan = web_scan(session, engines=(ScanEngine.ZAP,))
            ScanService(session, lab=LAB).cancel(world.operator, scan.id, request_id=None)
        # v0024 之前留下的紀錄（沒有 inode）：在 0023 寫入，再升回 head。
        _migrate(engine, "down", "0023")
        with Session(engine) as session, session.begin():
            run_id, scan_id = session.execute(
                text("SELECT id, scan_id FROM scanner_runs WHERE scan_id = :scan"),
                {"scan": scan.id},
            ).one()
            session.execute(
                text(
                    "INSERT INTO evidence_holds (directory, scanner_run_id, scan_id, error_code, "
                    "attempts) VALUES (:run, :run, :scan, 'EVIDENCE_TREE_TOO_DEEP', 3)"
                ),
                {"run": run_id, "scan": scan_id},
            )
            if resolved:
                session.execute(
                    text(
                        "INSERT INTO run_evidence (scanner_run_id, scan_id, status, file_count, "
                        "plaintext_bytes, sealed_at) VALUES (:run, :scan, 'sealed', 1, 1, now())"
                    ),
                    {"run": run_id, "scan": scan_id},
                )
                session.execute(
                    text(
                        "UPDATE evidence_holds SET resolved_at = clock_timestamp() "
                        "WHERE directory = :run"
                    ),
                    {"run": run_id},
                )
        _migrate(engine, "up", "head")

        with pytest.raises(DBAPIError, match="holds exist"):
            _migrate(engine, "down", "0022")
        assert _current_revisions(engine) == [head_revision()]
    finally:
        engine.dispose()


def test_downgrade_without_holds_removes_the_table(fresh_database: ProvisionedDatabase) -> None:
    engine = owner_engine(fresh_database)
    try:
        _migrate(engine, "up", "head")
        _migrate(engine, "down", "0022")

        assert _current_revisions(engine) == ["0022"]
        assert "evidence_holds" not in _tables(engine)
        assert not {"evidence_holds_guard", "run_evidence_hold_check"} & _existing_functions(engine)
    finally:
        engine.dispose()


def _legacy_hold(engine: Engine) -> UUID:
    """0023 的 schema 上：一個還沒解除、沒有 inode 的孤兒目錄的隔離紀錄。"""
    directory = uuid4()
    with Session(engine) as session, session.begin():
        session.execute(
            text(
                "INSERT INTO evidence_holds (directory, error_code, attempts) "
                "VALUES (:directory, 'EVIDENCE_TREE_TOO_DEEP', 3)"
            ),
            {"directory": directory},
        )
    return directory


def test_v0024_keeps_legacy_holds_isolating(fresh_database: ProvisionedDatabase) -> None:
    """既有的資料不回填（§30.13）：還沒解除的紀錄維持隔離中（沒有 inode），由搬移指令處理。"""
    engine = owner_engine(fresh_database)
    try:
        _migrate(engine, "up", "0023")
        directory = _legacy_hold(engine)
        _migrate(engine, "up", "head")

        with Session(engine) as session:
            row = session.execute(
                text("SELECT * FROM evidence_holds WHERE directory = :id"), {"id": directory}
            ).one()
        assert (row.isolated_at, row.releasing_at, row.source_ino) == (None, None, None)
        assert (row.move_failures, row.last_move_error, row.last_move_failed_at) == (0, None, None)
    finally:
        engine.dispose()


def test_v0024_downgrade_refuses_isolation_records(fresh_database: ProvisionedDatabase) -> None:
    """舊程式不認得 held/：有 inode、隔離或解除的時間、搬移失敗的紀錄就拒絕降級。"""
    engine = owner_engine(fresh_database)
    try:
        _migrate(engine, "up", "head")
        with Session(engine) as session, session.begin():
            session.execute(
                text(
                    "INSERT INTO evidence_holds (directory, error_code, attempts, source_ino) "
                    "VALUES (:directory, 'EVIDENCE_TREE_TOO_DEEP', 3, 1)"
                ),
                {"directory": uuid4()},
            )

        with pytest.raises(DBAPIError, match="isolation records or a runs layout migration"):
            _migrate(engine, "down", "0023")
        assert _current_revisions(engine) == [head_revision()]
    finally:
        engine.dispose()


def test_v0024_downgrade_restores_the_previous_guard(fresh_database: ProvisionedDatabase) -> None:
    """沒有隔離的資料時可以降級：刪除欄位與 CHECK，還原 0023 的 trigger（不要求 inode）。"""
    engine = owner_engine(fresh_database)
    try:
        _migrate(engine, "up", "0023")
        legacy = _legacy_hold(engine)
        _migrate(engine, "up", "head")
        _migrate(engine, "down", "0023")

        assert _current_revisions(engine) == ["0023"]
        columns = {column["name"] for column in inspect(engine).get_columns("evidence_holds")}
        assert not {"isolated_at", "releasing_at", "move_failures", "source_ino"} & columns
        _legacy_hold(engine)
        with Session(engine) as session:
            count = session.execute(text("SELECT count(*) FROM evidence_holds")).scalar()
            kept = session.execute(
                text("SELECT 1 FROM evidence_holds WHERE directory = :id"), {"id": legacy}
            ).scalar()
        assert (count, kept) == (2, 1)
    finally:
        engine.dispose()


def test_v0024_downgrade_refuses_after_a_layout_migration(
    fresh_database: ProvisionedDatabase,
) -> None:
    """資料庫審查 M1：已經搬到新的 layout（audit runs_layout.*）時，舊程式會把 active/ 的目錄記成
    「沒有目錄」：拒絕降級。"""
    engine = owner_engine(fresh_database)
    try:
        _migrate(engine, "up", "head")
        audit_local(engine, "runs_layout.migrated", {}, object_type="runs_volume")

        with pytest.raises(DBAPIError, match="runs layout migration"):
            _migrate(engine, "down", "0023")
        assert _current_revisions(engine) == [head_revision()]
    finally:
        engine.dispose()


def test_v0024_downgrade_restores_the_exact_previous_function(
    fresh_database: ProvisionedDatabase,
) -> None:
    """資料庫審查 L2：降級之後的 trigger 函式和 0023 的完全相同（UPDATE 的規則也還原）。"""
    engine = owner_engine(fresh_database)
    definition = "SELECT pg_get_functiondef('evidence_holds_guard()'::regprocedure)"
    try:
        _migrate(engine, "up", "0023")
        with engine.connect() as connection:
            before = connection.execute(text(definition)).scalar()
        _migrate(engine, "up", "head")
        with engine.connect() as connection:
            upgraded = connection.execute(text(definition)).scalar()
        _migrate(engine, "down", "0023")
        with engine.connect() as connection:
            after = connection.execute(text(definition)).scalar()

        assert upgraded != before
        assert after == before
    finally:
        engine.dispose()
