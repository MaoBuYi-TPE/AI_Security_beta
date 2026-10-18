"""migration：全新 DB 可升到 head、可完整降回 base 再升上去，且 model 與 migration 沒有漂移。"""

from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import Engine, inspect, text

from secscan.migrations import alembic_config, head_revision
from secscan.migrations.metadata import target_metadata
from tests.integration.conftest import app_engine
from tests.integration.database import ProvisionedDatabase

pytestmark = pytest.mark.integration

APP_TABLES = {"projects", "api_keys", "audit_events"}
REJECT_FUNCTION = "audit_events_reject_mutation"


def _migrate(engine: Engine, direction: str, target: str) -> None:
    with engine.begin() as connection:
        config = alembic_config(connection=connection)
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


def _function_exists(engine: Engine) -> bool:
    with engine.connect() as connection:
        found = connection.execute(
            text("SELECT to_regprocedure(:signature)"), {"signature": f"{REJECT_FUNCTION}()"}
        ).scalar()
    return found is not None


def test_fresh_database_upgrades_to_head(fresh_database: ProvisionedDatabase) -> None:
    engine = app_engine(fresh_database)
    try:
        _migrate(engine, "up", "head")

        assert _tables(engine) == APP_TABLES | {"alembic_version"}
        assert _current_revisions(engine) == [head_revision()]
        assert _function_exists(engine)
    finally:
        engine.dispose()


def test_downgrade_to_base_then_upgrade_again(fresh_database: ProvisionedDatabase) -> None:
    engine = app_engine(fresh_database)
    try:
        _migrate(engine, "up", "head")
        _migrate(engine, "down", "base")

        assert _tables(engine) == {"alembic_version"}
        assert _current_revisions(engine) == []
        assert not _function_exists(engine)

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
    """`make migrate` 的路徑：不傳連線時，env.py 依 DB_* 環境變數連線（這裡不讀 repo 的 .env）。"""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.setenv("DB_HOST", fresh_database.host)
    monkeypatch.setenv("DB_PORT", str(fresh_database.port))
    monkeypatch.setenv("DB_NAME", fresh_database.name)
    monkeypatch.setenv("DB_USER", fresh_database.name)
    monkeypatch.setenv("DB_PASSWORD", fresh_database.password)

    command.upgrade(alembic_config(), "head")

    engine = app_engine(fresh_database)
    try:
        assert _current_revisions(engine) == [head_revision()]
    finally:
        engine.dispose()
