"""角色與擁有權測試的共用工具（T23b-b1）：db-test 的 superuser 與 catalog 快照。"""

from psycopg import sql
from pydantic import SecretStr
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.pool import NullPool

from tests.integration.database import DatabaseProvisioner, _driver_connection

# 這個測試自己的角色與資料庫（名稱以 base 開頭）加上 postgres：擁有權與授權依賴、角色、資料庫的
# 擁有者與 ACL、設定（含 ALTER ROLE ALL）與參數的 ACL。只看自己的範圍，同時有其他測試 session 建立或
# 刪除角色與資料庫時也不受影響（移轉指令「沒有任何改變」的比對）。
_CLUSTER_SNAPSHOT = """
WITH roles AS (SELECT oid, rolname FROM pg_roles WHERE starts_with(rolname, :base)),
databases AS (
    SELECT oid FROM pg_database WHERE starts_with(datname, :base) OR datname = 'postgres'
)
SELECT 'shdepend', concat_ws(' ', d.dbid, d.classid::regclass::text, d.objid, d.objsubid,
    pg_get_userbyid(d.refobjid), d.deptype)
FROM pg_shdepend AS d
WHERE d.refobjid IN (SELECT oid FROM roles) OR d.dbid IN (SELECT oid FROM databases)
    OR (d.dbid = 0 AND d.classid = 'pg_database'::regclass
        AND d.objid IN (SELECT oid FROM databases))
UNION ALL SELECT 'role', concat_ws(' ', rolname, rolsuper, rolcanlogin, rolcreatedb, rolcreaterole)
FROM pg_roles WHERE oid IN (SELECT oid FROM roles)
UNION ALL SELECT 'database', concat_ws(' ', datname, pg_get_userbyid(datdba), datacl::text)
FROM pg_database WHERE oid IN (SELECT oid FROM databases)
UNION ALL SELECT 'setting', concat_ws(' ', setdatabase, setrole, setconfig::text)
FROM pg_db_role_setting
WHERE setrole = 0 OR setrole IN (SELECT oid FROM roles)
    OR setdatabase IN (SELECT oid FROM databases)
UNION ALL SELECT 'parameter', concat_ws(' ', parname, paracl::text) FROM pg_parameter_acl
UNION ALL SELECT 'member', concat_ws(' ', pg_get_userbyid(roleid), pg_get_userbyid(member))
FROM pg_auth_members WHERE member IN (SELECT oid FROM roles) OR roleid IN (SELECT oid FROM roles)
ORDER BY 1, 2
"""


class Superuser:
    """db-test 的 superuser，連到指定的資料庫（製造 superuser 才能做的狀態）。"""

    def __init__(self, provisioner: DatabaseProvisioner, database: str) -> None:
        self._provisioner = provisioner
        settings = provisioner.superuser_settings()
        self.user = settings.superuser
        self.password: SecretStr = settings.password
        url = URL.create(
            "postgresql+psycopg",
            username=settings.superuser,
            password=settings.password.get_secret_value(),
            host=settings.host,
            port=settings.port,
            database=database,
            query={"connect_timeout": "5"},
        )
        self.engine: Engine = create_engine(url, isolation_level="AUTOCOMMIT", poolclass=NullPool)

    def at(self, database: str) -> "Superuser":
        """同一個 superuser，連到另一個資料庫。"""
        return Superuser(self._provisioner, database)

    def run(self, *statements: sql.Composed | sql.SQL | str) -> None:
        with self.engine.connect() as connection:
            raw = _driver_connection(connection)
            for statement in statements:
                raw.execute(statement)

    def rows(self, statement: str, **params: object) -> list[tuple[object, ...]]:
        with self.engine.connect() as connection:
            return [tuple(row) for row in connection.execute(text(statement), params)]

    def cluster_snapshot(self, base: str) -> list[tuple[object, ...]]:
        return self.rows(_CLUSTER_SNAPSHOT, base=base)

    def dispose(self) -> None:
        self.engine.dispose()
