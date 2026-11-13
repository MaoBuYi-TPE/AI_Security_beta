"""Alembic 執行環境。

- 線上模式：呼叫端（例如測試）可經 config.attributes["connection"] 傳入連線（必須以 owner 連線）；
  否則以 migration 專用的 owner 角色連線（T23b-b1；docs/DECISIONS.md §31.4）：帳密取自
  DB_OWNER_USER、DB_OWNER_PASSWORD（環境變數或 .env），主機、port、資料庫與逾時沿用 Settings 的
  DB_*。沒有 DB_OWNER_PASSWORD 就停止，**不退回**應用程式角色（DB_USER）的帳密。
- 每次 migration 之前在同一個 transaction 中檢查角色（secscan.migrations.roles）：應用程式角色的名稱
  取自 DB_USER，放進 config.attributes["app_role"]，v0025 依它授權。傳入連線時，有 app_role 才檢查
  （v0025 之前的版本不需要；升級到 v0025 以後一定要有）。
- CONTENT_ENCRYPTION_KEYS（v0022 加密既有的報告與摘錄）一樣由 Settings 放進
  config.attributes["content_encryption_keys"]；呼叫端已經放了就不覆寫。migration 不讀 os.environ。
- 離線模式（alembic upgrade --sql）：只需要方言，不連線、也不讀取密碼；v0025 的應用程式角色以
  `-x app_role=…` 指定。
"""

from alembic import context
from sqlalchemy import Connection
from sqlalchemy.exc import OperationalError

from secscan.core.config import Settings
from secscan.core.db import create_db_engine
from secscan.migrations import APP_ROLE_ATTRIBUTE, CONTENT_KEYS_ATTRIBUTE, render_item
from secscan.migrations.credentials import MigrationConnectionError, MigrationCredentials
from secscan.migrations.keys import migration_content_keys
from secscan.migrations.metadata import target_metadata
from secscan.migrations.roles import verify_migration_roles

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


def _run_with(connection: Connection, app_role: object) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_server_default=True,
        render_item=render_item,
    )
    with context.begin_transaction():
        if isinstance(app_role, str):
            verify_migration_roles(connection, app_role)
        context.run_migrations()


def run_migrations_online() -> None:
    attributes = context.config.attributes
    shared = attributes.get("connection")
    if isinstance(shared, Connection):
        _run_with(shared, attributes.get(APP_ROLE_ATTRIBUTE))
        return
    settings = Settings()
    owner = MigrationCredentials().owner_settings(settings)
    attributes.setdefault(CONTENT_KEYS_ATTRIBUTE, migration_content_keys(settings))
    app_role = attributes.setdefault(APP_ROLE_ATTRIBUTE, settings.db_user)
    engine = create_db_engine(
        owner, application_name=MIGRATION_APPLICATION_NAME, pooled=False, require_scram=True
    )
    try:
        try:
            connection = engine.connect()
        except OperationalError:
            raise MigrationConnectionError(
                "無法以 migration 的 owner 角色（DB_OWNER_USER）連線：確認 db 已啟動、.env 的 "
                "DB_OWNER_PASSWORD 正確；既有的資料庫請先執行 make db-roles-migrate（升級沒有進行）"
            ) from None
        with connection:
            _run_with(connection, app_role)
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
