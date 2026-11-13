"""整合測試專用的 PostgreSQL（compose.yaml 的 db-test）。

測試資料與正式／開發配置分開（T04 DoD）：
- 連線設定只讀 TEST_DB_*（環境變數或 .env），與應用程式的 DB_* 是不同的鍵、不同的伺服器。
- 只接受 loopback 位址上、cluster_name = secscan-test 的伺服器；設定指錯（例如指到開發用 db）
  時直接拒絕。psycopg 經 libpq 連線，pytest-socket 管不到，所以由這裡把關。
- 每個測試資料庫有兩個專屬的非 superuser 角色，和開發／正式環境相同（T23b-b1；DECISIONS §31）：
  `<db>_owner` 擁有資料庫與所有物件，只用於 migration 與需要 DDL 的測試；`<db>_app` 只有 v0025
  授予的逐表 DML，其他測試一律以它執行。結束時刪除資料庫與兩個角色。
- 佇列的測試另外從 migrated 的 template 複製（CREATE DATABASE … TEMPLATE）每個測試專用的資料庫：
  佇列會認領任何排隊中的 run，共用資料庫時會認領到別的測試留下的 run。複製的資料庫沿用
  template 的兩個角色；資料庫層級的權限不會從 template 複製，所以另外授予 app 的 CONNECT。
  刪除時只刪資料庫。
- 舊版的資料庫（legacy=True；migrate-db-roles 的測試用）：只有 app 角色，資料庫由它擁有，和
  T23b-b1 之前的開發 DB 相同；owner 角色由移轉指令建立，刪除時一併刪除。
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
from tests.secret_support import content_keys, encryption_keys

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
    """一個測試專用資料庫與它的兩個角色（`<base>_owner`、`<base>_app`）；密碼為隨機值。

    base 是建立時的資料庫名稱；從 template 複製的資料庫（cloned）沿用 template 的 base 與角色。
    """

    name: str
    host: str
    port: int
    password: str = field(repr=False)
    owner_password: str = field(repr=False)
    base: str
    cloned: bool = False

    @property
    def user(self) -> str:
        """應用程式角色（逐表 DML）。"""
        return f"{self.base}_app"

    @property
    def owner_user(self) -> str:
        """owner 角色（擁有資料庫與所有物件；migration 與需要 DDL 的測試）。"""
        return f"{self.base}_owner"

    def app_settings(self) -> Settings:
        """以應用程式角色連到這個資料庫的 Settings（不讀 .env）。"""
        return self._settings(self.user, self.password)

    def owner_settings(self) -> Settings:
        """以 owner 角色連到這個資料庫的 Settings（不讀 .env）。"""
        return self._settings(self.owner_user, self.owner_password)

    def _settings(self, user: str, password: str) -> Settings:
        return Settings(
            app_env="test",
            db_host=self.host,
            db_port=self.port,
            db_name=self.name,
            db_user=user,
            db_password=SecretStr(password),
            secret_encryption_keys=encryption_keys(),
            content_encryption_keys=content_keys(),
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
        self._clones: list[str] = []

    def verify_server(self) -> None:
        with self._engine.connect() as connection:
            cluster_name = connection.execute(text("SHOW cluster_name")).scalar_one()
        ensure_test_cluster(str(cluster_name))

    def create(self, *, legacy: bool = False) -> ProvisionedDatabase:
        """全新的資料庫；legacy=True 時只建立 app 角色，資料庫由它擁有（T23b-b1 之前的狀態）。"""
        name = DATABASE_PREFIX + secrets.token_hex(6)
        database = ProvisionedDatabase(
            name=name,
            host=self._settings.host,
            port=self._settings.port,
            password=secrets.token_hex(24),
            owner_password=secrets.token_hex(24),
            base=name,
        )
        roles = [(database.user, database.password)]
        if not legacy:
            roles.insert(0, (database.owner_user, database.owner_password))
        # 先登記：中途失敗時 close() 也會刪除已經建立的角色與資料庫（_drop 都是 IF EXISTS）。
        self._created.append(name)
        with self._engine.connect() as connection:
            raw = _driver_connection(connection)
            for role, password in roles:
                create_login_role(raw, role, password)
            owner = database.user if legacy else database.owner_user
            ident = sql.Identifier(name)
            raw.execute(sql.SQL("CREATE DATABASE {} OWNER {}").format(ident, sql.Identifier(owner)))
            raw.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(ident))
            if not legacy:
                # 和 initdb 相同：應用程式角色只能連線，資料表的權限由 v0025 授予。
                raw.execute(
                    sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                        ident, sql.Identifier(database.user)
                    )
                )
        return database

    def clone(self, template: ProvisionedDatabase) -> ProvisionedDatabase:
        """以 template（已 migrate、沒有任何連線）複製新的資料庫，擁有者是 template 的 owner。"""
        name = DATABASE_PREFIX + secrets.token_hex(6)
        ident = sql.Identifier(name)
        with self._engine.connect() as connection:
            raw = _driver_connection(connection)
            raw.execute(
                sql.SQL("CREATE DATABASE {} TEMPLATE {} OWNER {}").format(
                    ident, sql.Identifier(template.name), sql.Identifier(template.owner_user)
                )
            )
            raw.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(ident))
            # 資料庫層級的權限不會從 template 複製（CREATE DATABASE 的文件）；物件的權限會。
            raw.execute(
                sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                    ident, sql.Identifier(template.user)
                )
            )
        self._clones.append(name)
        return ProvisionedDatabase(
            name=name,
            host=template.host,
            port=template.port,
            password=template.password,
            owner_password=template.owner_password,
            base=template.base,
            cloned=True,
        )

    def create_role(self, database: ProvisionedDatabase) -> tuple[str, str]:
        """只有這個資料庫 CONNECT 權限的角色（ROLE-01：確認 PUBLIC 的 EXECUTE 已關閉）。

        刪除資料庫時一併刪除（_drop）；只用於 create() 建立的資料庫。
        """
        role, password = f"{database.base}_probe", secrets.token_hex(24)
        with self._engine.connect() as connection:
            raw = _driver_connection(connection)
            create_login_role(raw, role, password)
            raw.execute(
                sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                    sql.Identifier(database.name), sql.Identifier(role)
                )
            )
        return role, password

    def superuser_settings(self) -> IntegrationDbSettings:
        return self._settings

    def drop(self, database: ProvisionedDatabase) -> None:
        if database.cloned:
            self._drop_database(database.name)
            self._clones.remove(database.name)
            return
        self._drop(database.name)
        self._created.remove(database.name)

    def close(self) -> None:
        """刪除這個 session 建立、還沒刪掉的資料庫與角色，再釋放連線（複製的資料庫先刪）。"""
        for name in list(self._clones):
            self._drop_database(name)
        self._clones.clear()
        for name in list(self._created):
            self._drop(name)
        self._created.clear()
        self._engine.dispose()

    def _drop(self, name: str) -> None:
        self._drop_database(name)
        roles = [f"{name}_probe", f"{name}_app", f"{name}_owner"]
        with self._engine.connect() as connection:
            raw = _driver_connection(connection)
            for role in roles:
                raw.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))

    def _drop_database(self, name: str) -> None:
        ident = sql.Identifier(name)
        with self._engine.connect() as connection:
            raw = _driver_connection(connection)
            raw.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(ident))


def create_login_role(
    raw: psycopg.Connection[tuple[object, ...]], role: str, password: str
) -> None:
    """和 initdb 相同屬性的 LOGIN 角色；預設時區刻意設成 Asia/Taipei（見模組說明）。"""
    ident = sql.Identifier(role)
    # CREATE ROLE 失敗時，預設會把整句（含密碼）寫進伺服器日誌。
    raw.execute("SET log_min_error_statement = panic")
    raw.execute(
        sql.SQL(
            "CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
            "NOREPLICATION NOBYPASSRLS PASSWORD {}"
        ).format(ident, sql.Literal(password))
    )
    raw.execute("RESET log_min_error_statement")
    raw.execute(
        sql.SQL("ALTER ROLE {} SET timezone = {}").format(ident, sql.Literal(TEST_ROLE_TIMEZONE))
    )


def _driver_connection(connection: Connection) -> psycopg.Connection[tuple[object, ...]]:
    """CREATE ROLE／DATABASE 不能用參數綁定，改用 psycopg.sql 安全地組識別字與字串常值。"""
    raw = connection.connection.driver_connection
    if not isinstance(raw, psycopg.Connection):
        raise TypeError("整合測試需要 psycopg 連線")
    return raw
