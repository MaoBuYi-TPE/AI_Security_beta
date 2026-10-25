"""整合測試專用的 PostgreSQL（compose.yaml 的 db-test）。

測試資料與正式／開發配置分開（T04 DoD）：
- 連線設定只讀 TEST_DB_*（環境變數或 .env），與應用程式的 DB_* 是不同的鍵、不同的伺服器。
- 只接受 loopback 位址上、cluster_name = secscan-test 的伺服器；設定指錯（例如指到開發用 db）
  時直接拒絕。psycopg 經 libpq 連線，pytest-socket 管不到，所以由這裡把關。
- 每個測試 session 建立專屬的非 superuser 角色與它擁有的全新資料庫，結束時刪除，
  權限和開發／正式環境的應用程式角色一致（不以 superuser 執行 migration 與測試）。
- 測試角色的預設時區刻意設成 Asia/Taipei：伺服器本身是 UTC 時，看不出應用程式的
  UTC 設定有沒有作用。
"""

import secrets
from dataclasses import dataclass, field
from pathlib import Path

import psycopg
from psycopg import sql
from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import URL, Connection, create_engine, text
from sqlalchemy.pool import NullPool

from secscan.core.config import Settings
from tests.secret_support import encryption_keys

REPO_ROOT = Path(__file__).resolve().parents[2]
TEST_CLUSTER_NAME = "secscan-test"
DATABASE_PREFIX = "secscan_t_"
DEFAULT_TEST_DB_PORT = 55433
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
# 不是 UTC、也不是開發機常見的預設值，用來驗證應用程式自己把時區固定成 UTC。
TEST_ROLE_TIMEZONE = "Asia/Taipei"


class IntegrationDbSettings(BaseSettings):
    """db-test 的 superuser 連線設定（只用來建立與刪除每個 session 的角色和資料庫）。"""

    model_config = SettingsConfigDict(
        env_prefix="TEST_DB_",
        env_file=REPO_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    host: str = "127.0.0.1"
    port: int = Field(default=DEFAULT_TEST_DB_PORT, ge=1, le=65535)
    superuser: str = "postgres"
    password: SecretStr

    @field_validator("host")
    @classmethod
    def _loopback_only(cls, host: str) -> str:
        if host not in LOOPBACK_HOSTS:
            raise ValueError(f"TEST_DB_HOST 只接受 loopback 位址 {sorted(LOOPBACK_HOSTS)}")
        return host

    def superuser_url(self) -> URL:
        return URL.create(
            "postgresql+psycopg",
            username=self.superuser,
            password=self.password.get_secret_value(),
            host=self.host,
            port=self.port,
            database="postgres",
            query={"connect_timeout": "5"},
        )


class NotATestServerError(RuntimeError):
    """連到的不是測試專用的伺服器。"""


def ensure_test_cluster(cluster_name: str) -> None:
    if cluster_name != TEST_CLUSTER_NAME:
        raise NotATestServerError(
            f"拒絕在 cluster_name={cluster_name!r} 的伺服器上建立測試資料庫；"
            f"只接受 {TEST_CLUSTER_NAME!r}（compose.yaml 的 db-test）"
        )


@dataclass(frozen=True, slots=True)
class ProvisionedDatabase:
    """一個測試專用資料庫；角色與資料庫同名，密碼為隨機值。"""

    name: str
    host: str
    port: int
    password: str = field(repr=False)

    def app_settings(self) -> Settings:
        """以應用程式角色連到這個資料庫的 Settings（不讀 .env）。"""
        return Settings(
            app_env="test",
            db_host=self.host,
            db_port=self.port,
            db_name=self.name,
            db_user=self.name,
            db_password=SecretStr(self.password),
            secret_encryption_keys=encryption_keys(),
            _env_file=None,
        )


class DatabaseProvisioner:
    """以 db-test 的 superuser 建立與刪除測試資料庫。"""

    def __init__(self, settings: IntegrationDbSettings) -> None:
        self._settings = settings
        self._engine = create_engine(
            settings.superuser_url(), isolation_level="AUTOCOMMIT", poolclass=NullPool
        )
        self._created: list[str] = []

    def verify_server(self) -> None:
        with self._engine.connect() as connection:
            cluster_name = connection.execute(text("SHOW cluster_name")).scalar_one()
        ensure_test_cluster(str(cluster_name))

    def create(self) -> ProvisionedDatabase:
        name = DATABASE_PREFIX + secrets.token_hex(6)
        password = secrets.token_hex(24)
        ident = sql.Identifier(name)
        with self._engine.connect() as connection:
            raw = _driver_connection(connection)
            # CREATE ROLE 失敗時，預設會把整句（含密碼）寫進伺服器日誌。
            raw.execute("SET log_min_error_statement = panic")
            raw.execute(
                sql.SQL(
                    "CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOREPLICATION NOBYPASSRLS PASSWORD {}"
                ).format(ident, sql.Literal(password))
            )
            raw.execute(
                sql.SQL("ALTER ROLE {} SET timezone = {}").format(
                    ident, sql.Literal(TEST_ROLE_TIMEZONE)
                )
            )
            raw.execute(sql.SQL("CREATE DATABASE {} OWNER {}").format(ident, ident))
            raw.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(ident))
        self._created.append(name)
        return ProvisionedDatabase(
            name=name, host=self._settings.host, port=self._settings.port, password=password
        )

    def drop(self, database: ProvisionedDatabase) -> None:
        self._drop(database.name)
        self._created.remove(database.name)

    def close(self) -> None:
        """刪除這個 session 建立、還沒刪掉的資料庫與角色，再釋放連線。"""
        for name in list(self._created):
            self._drop(name)
        self._created.clear()
        self._engine.dispose()

    def _drop(self, name: str) -> None:
        ident = sql.Identifier(name)
        with self._engine.connect() as connection:
            raw = _driver_connection(connection)
            raw.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(ident))
            raw.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(ident))


def _driver_connection(connection: Connection) -> psycopg.Connection[tuple[object, ...]]:
    """CREATE ROLE／DATABASE 不能用參數綁定，改用 psycopg.sql 安全地組識別字與字串常值。"""
    raw = connection.connection.driver_connection
    if not isinstance(raw, psycopg.Connection):
        raise TypeError("整合測試需要 psycopg 連線")
    return raw
