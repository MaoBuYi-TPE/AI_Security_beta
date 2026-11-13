"""整合測試 fixture。

- repository 與 service 測試：session 內共用一個已 migrate 的全新資料庫（migrated_database），
  每個測試各自在交易中執行並回滾。
- API 與 CLI 測試：另一個全新資料庫（api_database）。這些測試走正式的 request transaction，
  資料會真正 commit；如果和 migrated_database 共用，repository 測試對資料表總筆數的斷言就會
  被打壞。測試之間以唯一名稱區隔，不依賴全域筆數。
- 佇列與 FakeRunner 的測試：每個測試從 queue_template 複製一份（queue_database），
  不會認領到其他測試的 run。
- 角色（T23b-b1；DECISIONS §31）：migration 以 owner 執行；其他測試一律以應用程式角色執行
  （db_engine、db_session、queue_engine、seed、api_client），api、worker、runner 的功能回歸就在
  逐表 DML 的權限下執行。需要 DDL（故障注入、停用 trigger）或要驗證 trigger 那一層（應用程式角色
  已經沒有該權限的語句）的測試，改用 owner_db_engine、owner_session 或 queue_owner_engine。
"""

from collections.abc import Iterator

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import Connection, Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from secscan.core.db import create_db_engine
from secscan.main import create_app
from secscan.migrations import alembic_config
from tests.integration.api_support import Seeder, World
from tests.integration.database import (
    DatabaseProvisioner,
    IntegrationDbSettings,
    ProvisionedDatabase,
)

TEST_APPLICATION_NAME = "secscan-integration-test"


@pytest.fixture(scope="session")
def provisioner() -> Iterator[DatabaseProvisioner]:
    try:
        settings = IntegrationDbSettings()
    except ValidationError:
        pytest.fail(
            "缺少 TEST_DB_PASSWORD：請先執行 make test-db-up（會自動補齊 .env）", pytrace=False
        )
    db_provisioner = DatabaseProvisioner(settings)
    try:
        db_provisioner.verify_server()
    except OperationalError:
        db_provisioner.close()
        pytest.fail(
            f"連不到 db-test（{settings.host}:{settings.port}）：請先執行 make test-db-up",
            pytrace=False,
        )
    yield db_provisioner
    db_provisioner.close()


@pytest.fixture
def fresh_database(provisioner: DatabaseProvisioner) -> Iterator[ProvisionedDatabase]:
    """尚未 migrate 的全新資料庫（測試 migration 本身用）。"""
    database = provisioner.create()
    yield database
    provisioner.drop(database)


@pytest.fixture(scope="session")
def migrated_database(provisioner: DatabaseProvisioner) -> ProvisionedDatabase:
    """session 共用：全新資料庫升級到 head，等同驗證「全新 DB 可完成 migration」。"""
    database = provisioner.create()
    migrate_to_head(database)
    return database


@pytest.fixture(scope="session")
def db_engine(migrated_database: ProvisionedDatabase) -> Iterator[Engine]:
    engine = app_engine(migrated_database)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(db_engine: Engine) -> Iterator[Session]:
    """每個測試在一個外層交易中執行，結束時回滾；session 的 commit 只會結束 savepoint。"""
    yield from rolled_back_session(db_engine)


@pytest.fixture(scope="session")
def owner_db_engine(migrated_database: ProvisionedDatabase) -> Iterator[Engine]:
    """migrated_database 的 owner：需要 DDL、或要驗證 trigger 那一層的測試。"""
    engine = owner_engine(migrated_database)
    yield engine
    engine.dispose()


@pytest.fixture
def owner_session(owner_db_engine: Engine) -> Iterator[Session]:
    """同 db_session，但以 owner 執行（結束時回滾）。"""
    yield from rolled_back_session(owner_db_engine)


def rolled_back_session(engine: Engine) -> Iterator[Session]:
    with engine.connect() as connection:
        transaction = connection.begin()
        session = Session(
            bind=connection, join_transaction_mode="create_savepoint", expire_on_commit=False
        )
        try:
            yield session
        finally:
            session.close()
            transaction.rollback()


@pytest.fixture(scope="session")
def api_database(provisioner: DatabaseProvisioner) -> ProvisionedDatabase:
    """API 與 CLI 測試專用、會真正 commit 的資料庫（見模組說明）。"""
    database = provisioner.create()
    migrate_to_head(database)
    return database


@pytest.fixture(scope="session")
def queue_template(provisioner: DatabaseProvisioner) -> ProvisionedDatabase:
    """佇列測試的 template：migrate 之後不再連線（CREATE DATABASE … TEMPLATE 的條件）。"""
    database = provisioner.create()
    migrate_to_head(database)
    return database


@pytest.fixture
def queue_database(
    provisioner: DatabaseProvisioner, queue_template: ProvisionedDatabase
) -> Iterator[ProvisionedDatabase]:
    """每個測試專用、會 commit 的資料庫：佇列只會認領這個測試建立的 run。"""
    database = provisioner.clone(queue_template)
    yield database
    provisioner.drop(database)


@pytest.fixture
def queue_engine(queue_database: ProvisionedDatabase) -> Iterator[Engine]:
    engine = app_engine(queue_database)
    yield engine
    engine.dispose()


@pytest.fixture
def queue_owner_engine(queue_database: ProvisionedDatabase) -> Iterator[Engine]:
    """queue_database 的 owner：需要 DDL 的佇列測試（例如停用 trigger 製造舊資料）。"""
    engine = owner_engine(queue_database)
    yield engine
    engine.dispose()


@pytest.fixture
def queue_seed(queue_engine: Engine) -> Seeder:
    """在這個測試專用的資料庫準備資料（見 queue_database）。"""
    return Seeder(queue_engine)


@pytest.fixture
def queue_owner_seed(queue_owner_engine: Engine) -> Seeder:
    """以 owner 查證應用程式角色讀不到的資料（例如只能新增的 run_rule_locations）。"""
    return Seeder(queue_owner_engine)


@pytest.fixture(scope="session")
def api_client(api_database: ProvisionedDatabase) -> Iterator[TestClient]:
    with TestClient(create_app(api_database.app_settings())) as client:
        yield client


@pytest.fixture(scope="session")
def seed(api_database: ProvisionedDatabase) -> Iterator[Seeder]:
    engine = app_engine(api_database)
    yield Seeder(engine)
    engine.dispose()


@pytest.fixture
def world(seed: Seeder) -> World:
    """每個測試各自的一組 admin、project A/B 與 A 的成員。"""
    return seed.world()


def app_engine(database: ProvisionedDatabase) -> Engine:
    """與應用程式相同的 engine 設定（UTC、connect_timeout），連到測試資料庫。"""
    return create_db_engine(
        database.app_settings(), application_name=TEST_APPLICATION_NAME, pooled=False
    )


def owner_seed(database: ProvisionedDatabase) -> Seeder:
    """以 owner 準備應用程式角色做不到的狀態（DDL 的故障注入）；engine 是 NullPool，不留連線。"""
    return Seeder(owner_engine(database))


def owner_engine(database: ProvisionedDatabase) -> Engine:
    """同 app_engine，但以 owner 角色連線。"""
    return create_db_engine(
        database.owner_settings(), application_name=TEST_APPLICATION_NAME, pooled=False
    )


def owner_alembic_config(
    connection: Connection, *, content_encryption_keys: str | None = None
) -> Config:
    """以 owner 的連線升降級時的 Config（env.py 先檢查角色，v0025 依 app_role 授權）。

    應用程式角色依測試角色的命名（<base>_owner → <base>_app；tests/integration/database.py）。
    """
    owner = str(connection.engine.url.username)
    return alembic_config(
        connection=connection,
        content_encryption_keys=content_encryption_keys,
        app_role=owner.removesuffix("_owner") + "_app",
    )


def migrate_to_head(database: ProvisionedDatabase) -> None:
    migrate(database, "upgrade", "head")


def migrate(database: ProvisionedDatabase, direction: str, revision: str) -> None:
    """以 owner 升降級（和 make migrate 一樣先檢查角色；v0025 依 app_role 授權）。"""
    engine = owner_engine(database)
    try:
        with engine.begin() as connection:
            config = owner_alembic_config(connection)
            if direction == "upgrade":
                command.upgrade(config, revision)
            else:
                command.downgrade(config, revision)
    finally:
        engine.dispose()
