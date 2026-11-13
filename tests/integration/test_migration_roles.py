"""migration 的憑證與角色檢查（T23b-b1；docs/SECURITY_AND_TESTING.md §4.3 的 ROLE-05）。

- env.py 每次 migration 之前檢查角色，不符就停止，資料不變；
- v0025 遇到未分類的資料表、沒有應用程式角色的名稱時停止；
- 升降級（M1）：head → 0024 時 owner 的 default ACL 那一列消失、既有函式的 PUBLIC EXECUTE
  還原；再升到 head，權限、函式的 ACL 與 default ACL 都和第一次升級之後完全相同。
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from psycopg import sql
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.pool import NullPool

from secscan.migrations import alembic_config, head_revision
from secscan.migrations.credentials import (
    MigrationConnectionError,
    MissingOwnerPasswordError,
    OwnerIsAppRoleError,
)
from secscan.migrations.roles import MigrationRoleError
from tests.integration.conftest import migrate, migrate_to_head, owner_engine
from tests.integration.database import DatabaseProvisioner, ProvisionedDatabase
from tests.integration.role_support import Superuser

pytestmark = pytest.mark.integration

PRIVILEGES_SNAPSHOT = """
SELECT 'table', c.relname, coalesce(c.relacl::text, '') FROM pg_class AS c
JOIN pg_namespace AS n ON n.oid = c.relnamespace WHERE n.nspname = 'public'
UNION ALL SELECT 'function', p.proname, coalesce(p.proacl::text, '') FROM pg_proc AS p
JOIN pg_namespace AS n ON n.oid = p.pronamespace WHERE n.nspname = 'public'
UNION ALL SELECT 'default', d.defaclobjtype::text || d.defaclnamespace::text, d.defaclacl::text
FROM pg_default_acl AS d
UNION ALL SELECT 'database', datname, coalesce(datacl::text, '') FROM pg_database
WHERE datname = current_database()
UNION ALL SELECT 'schema', nspname, coalesce(nspacl::text, '') FROM pg_namespace
WHERE nspname = 'public'
ORDER BY 1, 2
"""


def _rows(engine: Engine, statement: str, **params: object) -> list[tuple[object, ...]]:
    with engine.connect() as connection:
        return [tuple(row) for row in connection.execute(text(statement), params)]


def _revision(database: ProvisionedDatabase) -> list[str]:
    engine = owner_engine(database)
    try:
        with engine.connect() as connection:
            exists = connection.execute(text("SELECT to_regclass('alembic_version')")).scalar()
            if exists is None:
                return []
            return [
                str(v)
                for v in connection.execute(
                    text("SELECT version_num FROM alembic_version")
                ).scalars()
            ]
    finally:
        engine.dispose()


@pytest.fixture
def superuser(
    provisioner: DatabaseProvisioner, fresh_database: ProvisionedDatabase
) -> Iterator[Superuser]:
    admin = Superuser(provisioner, fresh_database.name)
    yield admin
    admin.dispose()


def _upgrade_as_owner(database: ProvisionedDatabase, revision: str = "head") -> None:
    migrate(database, "upgrade", revision)


# ---------------------------------------------------------------- make migrate 的憑證


def _settings_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, database: ProvisionedDatabase
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.setenv("DB_HOST", database.host)
    monkeypatch.setenv("DB_PORT", str(database.port))
    monkeypatch.setenv("DB_NAME", database.name)
    monkeypatch.setenv("DB_USER", database.user)
    monkeypatch.setenv("DB_PASSWORD", database.password)


def test_make_migrate_refuses_without_the_owner_password(
    fresh_database: ProvisionedDatabase, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """不退回應用程式角色的帳密。"""
    _settings_env(monkeypatch, tmp_path, fresh_database)

    with pytest.raises(MissingOwnerPasswordError, match="make env"):
        command.upgrade(alembic_config(), "head")

    assert _revision(fresh_database) == []


def test_make_migrate_refuses_when_the_owner_is_the_app_role(
    fresh_database: ProvisionedDatabase, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _settings_env(monkeypatch, tmp_path, fresh_database)
    monkeypatch.setenv("DB_OWNER_USER", fresh_database.user)
    monkeypatch.setenv("DB_OWNER_PASSWORD", fresh_database.password)

    with pytest.raises(OwnerIsAppRoleError):
        command.upgrade(alembic_config(), "head")

    assert _revision(fresh_database) == []


def test_make_migrate_hides_the_driver_message_when_the_owner_cannot_connect(
    fresh_database: ProvisionedDatabase, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _settings_env(monkeypatch, tmp_path, fresh_database)
    monkeypatch.setenv("DB_OWNER_USER", fresh_database.owner_user)
    monkeypatch.setenv("DB_OWNER_PASSWORD", "not-the-password")

    with pytest.raises(MigrationConnectionError, match="DB_OWNER_PASSWORD") as caught:
        command.upgrade(alembic_config(), "head")

    message = str(caught.value)
    assert fresh_database.host not in message
    assert fresh_database.owner_user not in message
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__


# ---------------------------------------------------------------- 角色檢查


def _expect_refusal(database: ProvisionedDatabase, engine: Engine, pattern: str) -> None:
    before = _revision(database)
    with engine.begin() as connection, pytest.raises(MigrationRoleError, match=pattern):
        command.upgrade(alembic_config(connection=connection, app_role=database.user), "head")
    assert _revision(database) == before


def test_refuses_to_run_as_a_superuser(
    fresh_database: ProvisionedDatabase, superuser: Superuser
) -> None:
    _expect_refusal(fresh_database, superuser.engine, "superuser")


def test_refuses_to_run_as_the_app_role(
    fresh_database: ProvisionedDatabase, superuser: Superuser
) -> None:
    superuser.run(
        sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
            sql.Identifier(fresh_database.name), sql.Identifier(fresh_database.user)
        )
    )
    engine = create_engine(
        URL.create(
            "postgresql+psycopg",
            username=fresh_database.user,
            password=fresh_database.password,
            host=fresh_database.host,
            port=fresh_database.port,
            database=fresh_database.name,
        ),
        poolclass=NullPool,
    )
    try:
        _expect_refusal(fresh_database, engine, "不可使用應用程式角色")
    finally:
        engine.dispose()


def test_refuses_a_role_that_does_not_own_the_database(
    provisioner: DatabaseProvisioner, fresh_database: ProvisionedDatabase
) -> None:
    role, password = provisioner.create_role(fresh_database)
    engine = create_engine(
        URL.create(
            "postgresql+psycopg",
            username=role,
            password=password,
            host=fresh_database.host,
            port=fresh_database.port,
            database=fresh_database.name,
        ),
        poolclass=NullPool,
    )
    try:
        _expect_refusal(fresh_database, engine, "必須擁有目前的資料庫")
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    ("statements", "pattern"),
    [
        (
            [
                "CREATE TABLE public.legacy_leftover (id integer)",
                "ALTER TABLE public.legacy_leftover OWNER TO {app}",
            ],
            "擁有 1 個物件",
        ),
        (["ALTER ROLE {app} SET session_replication_role = replica"], "session_replication_role"),
        (["ALTER ROLE {owner} SET search_path = public"], "search_path"),
        (["ALTER DATABASE {database} SET session_replication_role = replica"], "目前的資料庫"),
        (["ALTER ROLE {app} IN DATABASE {database} SET work_mem = '8MB'"], "work_mem"),
        (["ALTER DEFAULT PRIVILEGES FOR ROLE {owner} GRANT SELECT ON TABLES TO {app}"], "default"),
        (
            ["ALTER DEFAULT PRIVILEGES FOR ROLE {app} REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC"],
            "default",
        ),
        (["GRANT {owner} TO {app}"], "成員關係"),
        (["GRANT pg_read_all_data TO {app}"], "成員關係"),
        (["ALTER ROLE {app} CREATEDB"], "CREATEDB"),
        (["ALTER ROLE {app} BYPASSRLS"], "BYPASSRLS"),
        (["ALTER ROLE {owner} CREATEROLE"], "owner 角色不可有"),
        (["GRANT pg_monitor TO {owner}"], "owner 角色不可有任何成員關係"),
        (["GRANT TEMPORARY ON DATABASE {database} TO PUBLIC"], "TEMPORARY"),
        (["GRANT CREATE ON SCHEMA public TO PUBLIC"], "public 的 CREATE"),
        (
            ["ALTER DEFAULT PRIVILEGES FOR ROLE {owner} GRANT ALL ON TABLES TO PUBLIC"],
            "非預期的 default privileges",
        ),
        (["GRANT SET ON PARAMETER session_replication_role TO {app}"], "GRANT ON PARAMETER"),
        (["GRANT SET ON PARAMETER session_replication_role TO PUBLIC"], "GRANT ON PARAMETER"),
        (["GRANT SET ON PARAMETER lo_compat_privileges TO {app}"], "lo_compat_privileges"),
        (["ALTER ROLE ALL SET statement_timeout = '7s'"], "所有角色 的 statement_timeout"),
    ],
)
def test_refuses_unsafe_roles_and_settings(
    fresh_database: ProvisionedDatabase,
    superuser: Superuser,
    statements: list[str],
    pattern: str,
) -> None:
    _upgrade_as_owner(fresh_database, "0024")
    names = {
        "app": sql.Identifier(fresh_database.user),
        "owner": sql.Identifier(fresh_database.owner_user),
        "database": sql.Identifier(fresh_database.name),
    }
    engine = owner_engine(fresh_database)
    try:
        superuser.run(*(sql.SQL(statement).format(**names) for statement in statements))
        _expect_refusal(fresh_database, engine, pattern)
    finally:
        engine.dispose()
        # 整個 cluster 的狀態（參數的 ACL、ALTER ROLE ALL）一定還原；資料庫與角色層級的，
        # 會和資料庫、角色一起刪除。
        if "PARAMETER" in statements[0]:
            parameter = statements[0].split()[4]
            grantee = sql.SQL("PUBLIC") if statements[0].endswith("PUBLIC") else names["app"]
            superuser.run(
                sql.SQL("REVOKE SET ON PARAMETER {} FROM {}").format(sql.SQL(parameter), grantee)
            )
        if "ROLE ALL" in statements[0]:
            superuser.run("ALTER ROLE ALL RESET statement_timeout")


def test_refuses_when_the_app_role_is_missing(fresh_database: ProvisionedDatabase) -> None:
    engine = owner_engine(fresh_database)
    try:
        with engine.begin() as connection, pytest.raises(MigrationRoleError, match="找不到"):
            command.upgrade(
                alembic_config(connection=connection, app_role="secscan_no_such_role"), "head"
            )
    finally:
        engine.dispose()

    assert _revision(fresh_database) == []


def test_v0025_needs_the_app_role_name(fresh_database: ProvisionedDatabase) -> None:
    """傳入連線、沒有 app_role 時不做角色檢查（v0025 之前的版本），但 v0025 本身會停止。"""
    _upgrade_as_owner(fresh_database, "0024")
    engine = owner_engine(fresh_database)
    try:
        with engine.begin() as connection, pytest.raises(RuntimeError, match="v0025 需要"):
            command.upgrade(alembic_config(connection=connection), "head")
    finally:
        engine.dispose()

    assert _revision(fresh_database) == ["0024"]


def test_v0025_stops_on_an_unclassified_table(fresh_database: ProvisionedDatabase) -> None:
    _upgrade_as_owner(fresh_database, "0024")
    engine = owner_engine(fresh_database)
    try:
        with engine.begin() as connection:
            connection.execute(text("CREATE TABLE public.unclassified (id integer)"))
        with pytest.raises(Exception, match="unclassified relations in public: unclassified"):
            _upgrade_as_owner(fresh_database)
    finally:
        engine.dispose()

    assert _revision(fresh_database) == ["0024"]


# ---------------------------------------------------------------- 升降級（M1）


def test_downgrade_restores_the_builtin_defaults_and_upgrade_is_reproducible(
    fresh_database: ProvisionedDatabase,
) -> None:
    migrate_to_head(fresh_database)
    engine = owner_engine(fresh_database)
    try:
        first = _rows(engine, PRIVILEGES_SNAPSHOT)

        migrate(fresh_database, "downgrade", "0024")

        default_acls = _rows(engine, "SELECT count(*) FROM pg_default_acl")
        public_execute = _rows(
            engine,
            "SELECT bool_and(EXISTS (SELECT 1 FROM aclexplode(p.proacl) AS item "
            "WHERE item.grantee = 0 AND item.privilege_type = 'EXECUTE')) FROM pg_proc AS p "
            "JOIN pg_namespace AS n ON n.oid = p.pronamespace WHERE n.nspname = 'public'",
        )
        app_grants = _rows(
            engine,
            "SELECT count(*) FROM pg_class AS c, aclexplode(c.relacl) AS item "
            "WHERE item.grantee = (SELECT oid FROM pg_roles WHERE rolname = :app)",
            app=fresh_database.user,
        )
        assert default_acls == [(0,)]  # A3：還原成內建預設時那一列被刪除
        assert public_execute == [(True,)]
        assert app_grants == [(0,)]
        assert _revision(fresh_database) == ["0024"]

        migrate_to_head(fresh_database)

        assert _rows(engine, PRIVILEGES_SNAPSHOT) == first
        assert _revision(fresh_database) == [head_revision()]
    finally:
        engine.dispose()
