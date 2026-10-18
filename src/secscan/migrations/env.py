"""Alembic 執行環境。

- 線上模式：呼叫端（例如測試）可經 config.attributes["connection"] 傳入連線；
  否則依 Settings（環境變數或 .env 的 DB_*）以不共用連線池的 engine 連線。
- 離線模式（alembic upgrade --sql）：只需要方言，不連線、也不讀取密碼。
"""

from alembic import context
from sqlalchemy import Connection

from secscan.core.config import Settings
from secscan.core.db import create_db_engine
from secscan.migrations import render_item
from secscan.migrations.metadata import target_metadata

OFFLINE_URL = "postgresql+psycopg://"
MIGRATION_APPLICATION_NAME = "secscan-migrate"


def run_migrations_offline() -> None:
    context.configure(
        url=OFFLINE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def _run_with(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_server_default=True,
        render_item=render_item,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    shared = context.config.attributes.get("connection")
    if isinstance(shared, Connection):
        _run_with(shared)
        return
    engine = create_db_engine(Settings(), application_name=MIGRATION_APPLICATION_NAME, pooled=False)
    try:
        with engine.connect() as connection:
            _run_with(connection)
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
