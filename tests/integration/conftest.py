"""整合測試 fixture。

- repository 與 service 測試：session 內共用一個已 migrate 的全新資料庫（migrated_database），
  每個測試各自在交易中執行並回滾。
- API 與 CLI 測試：另一個全新資料庫（api_database）。這些測試走正式的 request transaction，
  資料會真正 commit；如果和 migrated_database 共用，repository 測試對資料表總筆數的斷言就會
  被打壞。測試之間以唯一名稱區隔，不依賴全域筆數。
"""

from collections.abc import Iterator

import pytest
from alembic import command
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import Engine
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
    with db_engine.connect() as connection:
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


def migrate_to_head(database: ProvisionedDatabase) -> None:
    engine = app_engine(database)
    try:
        with engine.begin() as connection:
            command.upgrade(alembic_config(connection=connection), "head")
    finally:
        engine.dispose()
