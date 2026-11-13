"""應用程式角色的權限（T23b-b1；docs/SECURITY_AND_TESTING.md §4.3 的 ROLE-01 至 04、08）。

- ROLE-01：catalog 和預期矩陣（tests/db_privileges.py）完全相同；函式與 default privileges。
- ROLE-02：擁有權、繼承與角色／資料庫層級的設定。
- ROLE-03：負向行為（以應用程式角色執行，都是 42501）；之後 trigger、函式、CHECK 與擁有者都不變。
- ROLE-04：正向（identity 取號、沒有 EXECUTE 時 trigger 照常觸發、執行期的列鎖、readiness）。
- ROLE-08：分權之後 T23a 的不變條件（evidence_holds、run_evidence 的 trigger 與 CHECK）。

catalog 以 owner 讀取（看得到全部），行為一律以應用程式角色執行。
"""

from collections.abc import Iterator

import psycopg
import pytest
from sqlalchemy import Connection, Engine, create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.exc import DBAPIError
from sqlalchemy.pool import NullPool

from secscan.core.db import DatabaseStatus, probe_database
from secscan.migrations import head_revision
from tests.db_privileges import (
    ALLOWED_ROLE_SETTINGS,
    APP_TABLE_PRIVILEGES,
    DELETABLE_TABLES,
    EXPECTED_SEQUENCES,
    INSERT_ONLY_TABLES,
    SECURITY_DEFINER_ALLOWLIST,
    STATEFUL_TABLES,
    TABLE_PRIVILEGES,
)
from tests.integration.api_support import Seeder
from tests.integration.conftest import migrate_to_head, owner_engine
from tests.integration.database import DatabaseProvisioner, ProvisionedDatabase
from tests.integration.sql_support import INTEGRITY_CONSTRAINT_VIOLATION

pytestmark = pytest.mark.integration

INSUFFICIENT_PRIVILEGE = "42501"
# 資料表、分割表、view、materialized view、foreign table（v0025 的檢查也用同一組）。
_PUBLIC_RELATIONS = (
    "FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace "
    "WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')"
)


def _rows(engine: Engine, statement: str, **params: object) -> list[tuple[object, ...]]:
    with engine.connect() as connection:
        return [tuple(row) for row in connection.execute(text(statement), params)]


def _scalar(engine: Engine, statement: str, **params: object) -> object:
    with engine.connect() as connection:
        return connection.execute(text(statement), params).scalar_one()


def _sqlstate(connection: Connection, statement: str) -> str | None:
    """在 savepoint 中執行；回傳錯誤的 SQLSTATE（成功時是 None）。語句都是這個檔案寫死的。"""
    savepoint = connection.begin_nested()
    try:
        connection.execute(text(statement))
    except DBAPIError as exc:
        savepoint.rollback()
        return exc.orig.sqlstate if isinstance(exc.orig, psycopg.Error) else "not-psycopg"
    savepoint.rollback()
    return None


# ---------------------------------------------------------------- ROLE-01：資料表與 sequence


def test_table_grants_match_the_expected_matrix(
    owner_db_engine: Engine, migrated_database: ProvisionedDatabase
) -> None:
    tables = {
        str(name)
        for (name,) in _rows(
            owner_db_engine,
            "SELECT c.relname " + _PUBLIC_RELATIONS,
        )
    }
    grants = _rows(
        owner_db_engine,
        "SELECT c.relname, item.privilege_type, item.is_grantable "
        "FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace, "
        "aclexplode(c.relacl) AS item "
        "WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f') "
        "AND item.grantee = (SELECT oid FROM pg_roles WHERE rolname = :app)",
        app=migrated_database.user,
    )

    # 每張表都已分類（未分類的表在這裡失敗：新的 migration 必須明確授權並更新預期值）。
    assert tables == set(APP_TABLE_PRIVILEGES)
    granted: dict[str, set[str]] = {}
    for table, privilege, grantable in grants:
        assert grantable is False, f"{table} 的 {privilege} 有 GRANT OPTION"
        granted.setdefault(str(table), set()).add(str(privilege))
    expected = {table: set(privileges) for table, privileges in APP_TABLE_PRIVILEGES.items()}
    assert granted == expected


@pytest.mark.parametrize("table", sorted(APP_TABLE_PRIVILEGES))
def test_effective_table_privileges_are_exactly_the_matrix(
    owner_db_engine: Engine, migrated_database: ProvisionedDatabase, table: str
) -> None:
    """has_table_privilege 也包含經由 PUBLIC 取得的權限。"""
    effective = {
        privilege
        for privilege in TABLE_PRIVILEGES
        if _scalar(
            owner_db_engine,
            "SELECT has_table_privilege(:app, :table, :privilege)",
            app=migrated_database.user,
            table=f"public.{table}",
            privilege=privilege,
        )
    }

    assert effective == set(APP_TABLE_PRIVILEGES[table])


def test_no_column_grants_and_nothing_for_public(owner_db_engine: Engine) -> None:
    column_acls = _scalar(
        owner_db_engine,
        "SELECT count(*) FROM pg_attribute AS a JOIN pg_class AS c ON c.oid = a.attrelid "
        "JOIN pg_namespace AS n ON n.oid = c.relnamespace "
        "WHERE n.nspname = 'public' AND a.attacl IS NOT NULL",
    )
    public_grants = _scalar(
        owner_db_engine,
        "SELECT count(*) FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace, "
        "aclexplode(c.relacl) AS item WHERE n.nspname = 'public' AND item.grantee = 0",
    )

    assert (column_acls, public_grants) == (0, 0)


def test_sequences_are_only_the_identity_columns_and_have_no_grants(
    owner_db_engine: Engine, migrated_database: ProvisionedDatabase
) -> None:
    sequences = _rows(
        owner_db_engine,
        "SELECT c.relname, has_sequence_privilege(:app, c.oid, 'USAGE') "
        "OR has_sequence_privilege(:app, c.oid, 'SELECT') "
        "OR has_sequence_privilege(:app, c.oid, 'UPDATE') "
        "FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace "
        "WHERE n.nspname = 'public' AND c.relkind = 'S'",
        app=migrated_database.user,
    )

    assert {str(name) for name, _ in sequences} == EXPECTED_SEQUENCES
    assert not any(granted for _, granted in sequences)


def test_database_and_schema_privileges(
    owner_db_engine: Engine, migrated_database: ProvisionedDatabase
) -> None:
    app = migrated_database.user
    [(connect, create, temporary)] = _rows(
        owner_db_engine,
        "SELECT has_database_privilege(:app, current_database(), 'CONNECT'), "
        "has_database_privilege(:app, current_database(), 'CREATE'), "
        "has_database_privilege(:app, current_database(), 'TEMPORARY')",
        app=app,
    )
    database_acl = _rows(
        owner_db_engine,
        "SELECT item.privilege_type, item.is_grantable FROM pg_database AS d, "
        "aclexplode(d.datacl) AS item WHERE d.datname = current_database() "
        "AND item.grantee = (SELECT oid FROM pg_roles WHERE rolname = :app)",
        app=app,
    )
    schemas = _rows(
        owner_db_engine,
        "SELECT nspname, has_schema_privilege(:app, oid, 'USAGE'), "
        "has_schema_privilege(:app, oid, 'CREATE') FROM pg_namespace "
        "WHERE nspname NOT LIKE 'pg\\_%' AND nspname <> 'information_schema'",
        app=app,
    )

    assert (connect, create, temporary) == (True, False, False)
    assert database_acl == [("CONNECT", False)]
    assert schemas == [("public", True, False)]


# ---------------------------------------------------- ROLE-01：函式與 default privileges


def test_every_function_is_a_pinned_trigger_function_without_execute(
    owner_db_engine: Engine, migrated_database: ProvisionedDatabase
) -> None:
    functions = _rows(
        owner_db_engine,
        "SELECT p.proname, p.prorettype = 'trigger'::regtype, p.prosecdef, "
        "'search_path=pg_catalog' = ANY (p.proconfig), r.rolname, p.proacl IS NOT NULL, "
        "has_function_privilege(:app, p.oid, 'EXECUTE') "
        "FROM pg_proc AS p JOIN pg_namespace AS n ON n.oid = p.pronamespace "
        "JOIN pg_roles AS r ON r.oid = p.proowner WHERE n.nspname = 'public'",
        app=migrated_database.user,
    )
    acl_entries = _rows(
        owner_db_engine,
        "SELECT DISTINCT grantee.rolname, grantor.rolname, item.privilege_type, item.is_grantable "
        "FROM pg_proc AS p JOIN pg_namespace AS n ON n.oid = p.pronamespace, "
        "aclexplode(p.proacl) AS item "
        "LEFT JOIN pg_roles AS grantee ON grantee.oid = item.grantee "
        "JOIN pg_roles AS grantor ON grantor.oid = item.grantor WHERE n.nspname = 'public'",
    )

    assert len(functions) >= 37
    for name, is_trigger, definer, pinned, owner, explicit_acl, executable in functions:
        assert is_trigger, name
        assert not definer or name in SECURITY_DEFINER_ALLOWLIST, name
        assert pinned, name
        assert owner == migrated_database.owner_user, name
        assert explicit_acl, name
        assert not executable, name
    owner = migrated_database.owner_user
    assert acl_entries == [(owner, owner, "EXECUTE", False)]


def test_default_privileges_are_the_owners_global_function_entry(
    owner_db_engine: Engine, migrated_database: ProvisionedDatabase
) -> None:
    entries = _rows(
        owner_db_engine,
        "SELECT r.rolname, d.defaclobjtype, d.defaclnamespace, grantee.rolname, "
        "grantor.rolname, item.privilege_type, item.is_grantable "
        "FROM pg_default_acl AS d JOIN pg_roles AS r ON r.oid = d.defaclrole, "
        "aclexplode(d.defaclacl) AS item "
        "LEFT JOIN pg_roles AS grantee ON grantee.oid = item.grantee "
        "JOIN pg_roles AS grantor ON grantor.oid = item.grantor",
    )
    owner = migrated_database.owner_user

    # 只有一列：owner 的全域（namespace 0）函式條目，ACL 只有 owner 自己；沒有 per-schema 的條目。
    assert entries == [(owner, "f", 0, owner, owner, "EXECUTE", False)]


@pytest.fixture
def function_database(provisioner: DatabaseProvisioner) -> Iterator[ProvisionedDatabase]:
    """新建函式要 commit 才看得到：用自己的資料庫，不影響共用的 migrated_database。"""
    database = provisioner.create()
    migrate_to_head(database)
    yield database
    provisioner.drop(database)


def test_functions_created_later_are_not_executable_through_public(
    provisioner: DatabaseProvisioner, function_database: ProvisionedDatabase
) -> None:
    database = function_database
    owner = owner_engine(database)
    try:
        with owner.begin() as connection:
            connection.execute(
                text("CREATE FUNCTION public.role01_probe() RETURNS int LANGUAGE sql AS 'SELECT 1'")
            )
            connection.execute(
                text(
                    "CREATE FUNCTION public.role01_trigger() RETURNS trigger LANGUAGE plpgsql "
                    "SET search_path = pg_catalog AS 'BEGIN RETURN NEW; END'"
                )
            )
        acl = _rows(
            owner,
            "SELECT p.proname, grantee.rolname, grantor.rolname, item.privilege_type, "
            "item.is_grantable FROM pg_proc AS p, aclexplode(p.proacl) AS item "
            "LEFT JOIN pg_roles AS grantee ON grantee.oid = item.grantee "
            "JOIN pg_roles AS grantor ON grantor.oid = item.grantor "
            "WHERE p.proname IN ('role01_probe', 'role01_trigger') ORDER BY p.proname",
        )
    finally:
        owner.dispose()
    probe_role, probe_password = provisioner.create_role(database)

    name = database.owner_user
    assert acl == [
        ("role01_probe", name, name, "EXECUTE", False),
        ("role01_trigger", name, name, "EXECUTE", False),
    ]
    for user, password in (
        (database.user, database.password),
        (probe_role, probe_password),
    ):
        engine = _login(database, user, password)
        try:
            with engine.connect() as connection:
                assert _sqlstate(connection, "SELECT public.role01_probe()") == (
                    INSUFFICIENT_PRIVILEGE
                ), user
        finally:
            engine.dispose()


def _login(database: ProvisionedDatabase, user: str, password: str) -> Engine:
    url = URL.create(
        "postgresql+psycopg",
        username=user,
        password=password,
        host=database.host,
        port=database.port,
        database=database.name,
        query={"connect_timeout": "5"},
    )
    return create_engine(url, poolclass=NullPool)


# ---------------------------------------------------------------- ROLE-02：擁有權、繼承與設定


def test_the_app_role_owns_nothing_in_any_database(
    owner_db_engine: Engine, migrated_database: ProvisionedDatabase
) -> None:
    owned = _scalar(
        owner_db_engine,
        "SELECT count(*) FROM pg_shdepend WHERE deptype = 'o' "
        "AND refclassid = 'pg_authid'::regclass "
        "AND refobjid = (SELECT oid FROM pg_roles WHERE rolname = :app)",
        app=migrated_database.user,
    )

    assert owned == 0


def test_every_grant_to_the_app_role_is_expected(
    owner_db_engine: Engine, migrated_database: ProvisionedDatabase
) -> None:
    """pg_shdepend 中應用程式角色所有的授權依賴（a）：只有目標資料庫、public 與矩陣中的表。

    pg_catalog 的函式、其他 schema、FDW、language、參數、large object 的授權都會在這裡出現。
    """
    grants = _rows(
        owner_db_engine,
        "SELECT CASE WHEN d.classid = 'pg_database'::regclass AND d.objid = "
        "(SELECT oid FROM pg_database WHERE datname = current_database()) THEN 'database' "
        "WHEN d.classid = 'pg_namespace'::regclass THEN 'schema ' || "
        "(SELECT nspname FROM pg_namespace WHERE oid = d.objid) "
        "WHEN d.classid = 'pg_class'::regclass AND d.objsubid = 0 THEN 'table ' || "
        "(SELECT n.nspname || '.' || c.relname FROM pg_class AS c JOIN pg_namespace AS n "
        "ON n.oid = c.relnamespace WHERE c.oid = d.objid) "
        "ELSE d.classid::regclass::text END FROM pg_shdepend AS d "
        "WHERE d.deptype = 'a' AND d.refobjid = (SELECT oid FROM pg_roles WHERE rolname = :app)",
        app=migrated_database.user,
    )
    parameters = _rows(
        owner_db_engine,
        "SELECT p FROM unnest(ARRAY['session_replication_role', 'lo_compat_privileges']) AS p "
        "WHERE has_parameter_privilege(:app, p, 'SET')",
        app=migrated_database.user,
    )

    expected = {"database", "schema public"} | {
        f"table public.{table}" for table in APP_TABLE_PRIVILEGES
    }
    assert sorted(str(kind) for (kind,) in grants) == sorted(expected)
    assert parameters == []


def test_the_owner_owns_the_database_and_every_object(
    owner_db_engine: Engine, migrated_database: ProvisionedDatabase
) -> None:
    owner = migrated_database.owner_user
    database_owner = _scalar(
        owner_db_engine,
        "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database()",
    )
    public_owner = _scalar(
        owner_db_engine,
        "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = 'public'",
    )
    others = _rows(
        owner_db_engine,
        "SELECT 'relation', c.relname, pg_get_userbyid(c.relowner) FROM pg_class AS c "
        "JOIN pg_namespace AS n ON n.oid = c.relnamespace WHERE n.nspname = 'public' "
        "AND c.relowner <> (SELECT oid FROM pg_roles WHERE rolname = :owner) "
        "UNION ALL SELECT 'function', p.proname, pg_get_userbyid(p.proowner) FROM pg_proc AS p "
        "JOIN pg_namespace AS n ON n.oid = p.pronamespace WHERE n.nspname = 'public' "
        "AND p.proowner <> (SELECT oid FROM pg_roles WHERE rolname = :owner) "
        "UNION ALL SELECT 'type', t.typname, pg_get_userbyid(t.typowner) FROM pg_type AS t "
        "JOIN pg_namespace AS n ON n.oid = t.typnamespace WHERE n.nspname = 'public' "
        "AND t.typowner <> (SELECT oid FROM pg_roles WHERE rolname = :owner) "
        "UNION ALL SELECT 'large object', l.oid::text, pg_get_userbyid(l.lomowner) "
        "FROM pg_largeobject_metadata AS l",
        owner=owner,
    )

    assert (database_owner, public_owner, others) == (owner, "pg_database_owner", [])


def test_role_attributes_and_memberships(
    owner_db_engine: Engine, migrated_database: ProvisionedDatabase
) -> None:
    roles = (migrated_database.user, migrated_database.owner_user)
    attributes = _rows(
        owner_db_engine,
        "SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolreplication, "
        "rolbypassrls, rolinherit FROM pg_roles WHERE rolname IN (:app, :owner) ORDER BY rolname",
        app=roles[0],
        owner=roles[1],
    )
    memberships = _scalar(
        owner_db_engine,
        "SELECT count(*) FROM pg_auth_members WHERE member IN "
        "(SELECT oid FROM pg_roles WHERE rolname IN (:app, :owner)) OR roleid IN "
        "(SELECT oid FROM pg_roles WHERE rolname IN (:app, :owner))",
        app=roles[0],
        owner=roles[1],
    )
    inherited = _rows(
        owner_db_engine,
        "SELECT rolname FROM pg_roles WHERE (rolname = :owner OR rolname LIKE 'pg\\_%') "
        "AND (pg_has_role(:app, oid, 'MEMBER') OR pg_has_role(:app, oid, 'USAGE'))",
        app=roles[0],
        owner=roles[1],
    )

    assert sorted(attributes) == sorted(
        (role, True, False, False, False, False, False, True) for role in roles
    )
    assert (memberships, inherited) == (0, [])


def test_no_role_or_database_settings_except_timezone(
    owner_db_engine: Engine, migrated_database: ProvisionedDatabase
) -> None:
    settings = _rows(
        owner_db_engine,
        "SELECT unnest(setconfig) FROM pg_db_role_setting WHERE setrole IN (0, "
        "(SELECT oid FROM pg_roles WHERE rolname = :app), "
        "(SELECT oid FROM pg_roles WHERE rolname = :owner)) "
        "AND setdatabase IN (0, (SELECT oid FROM pg_database WHERE datname = current_database()))",
        app=migrated_database.user,
        owner=migrated_database.owner_user,
    )

    names = {str(entry).split("=", 1)[0].lower() for (entry,) in settings}
    assert names <= ALLOWED_ROLE_SETTINGS


# ---------------------------------------------------------------- ROLE-03：負向行為


def _negative_statements(database: ProvisionedDatabase, first: dict[str, str]) -> list[str]:
    """first：每張表的第一個欄位（UPDATE 要指定存在的欄位，否則先得到 42703）。"""
    app, owner, name = database.user, database.owner_user, database.name
    return [
        # DDL
        "ALTER TABLE scans ADD COLUMN role03 integer",
        "ALTER TABLE scans DROP COLUMN status",
        "DROP TABLE scans",
        # trigger
        "ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only",
        "ALTER TABLE audit_events DISABLE TRIGGER ALL",
        "ALTER TABLE audit_events DISABLE TRIGGER USER",
        "ALTER TRIGGER audit_events_append_only ON audit_events RENAME TO role03",
        "DROP TRIGGER audit_events_append_only ON audit_events",
        "CREATE TRIGGER role03 BEFORE INSERT ON scans FOR EACH ROW "
        "EXECUTE FUNCTION audit_events_reject_mutation()",
        # 函式與約束
        "CREATE OR REPLACE FUNCTION public.audit_events_reject_mutation() RETURNS trigger "
        "LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END'",
        "ALTER FUNCTION audit_events_reject_mutation() RESET search_path",
        "ALTER TABLE audit_events DROP CONSTRAINT ck_audit_events_changes_is_object",
        # 建立物件
        "CREATE TABLE public.role03 (id integer)",
        "CREATE TEMP TABLE role03 (id integer)",
        "CREATE SCHEMA role03",
        "CREATE FUNCTION public.role03() RETURNS integer LANGUAGE sql AS 'SELECT 1'",
        "CREATE VIEW public.role03 AS SELECT 1 AS one",
        "CREATE RULE role03 AS ON INSERT TO scans DO INSTEAD NOTHING",
        "CREATE POLICY role03 ON scans USING (true)",
        "CREATE INDEX role03 ON scans (id)",
        "ALTER TABLE scans ENABLE ROW LEVEL SECURITY",
        # 擁有權與註解
        "COMMENT ON TABLE scans IS 'role03'",
        f'ALTER TABLE scans OWNER TO "{app}"',
        f'REASSIGN OWNED BY "{owner}" TO "{app}"',
        # 資料庫與 schema
        f'ALTER DATABASE "{name}" SET session_replication_role = replica',
        "ALTER SCHEMA public RENAME TO role03",
        # 切換角色
        f'SET ROLE "{owner}"',
        f'SET SESSION AUTHORIZATION "{owner}"',
        # session_replication_role（不經 ALTER TABLE 停用 trigger）
        "SET session_replication_role = replica",
        "SELECT set_config('session_replication_role', 'replica', true)",
        f'ALTER ROLE "{app}" SET session_replication_role = replica',
        # 伺服器與檔案
        "COPY (SELECT 1) TO PROGRAM 'true'",
        "SELECT pg_read_file('/etc/hostname')",
        "SELECT lo_import('/etc/hostname')",
        "REINDEX TABLE scans",
        # 動態 SQL 以呼叫者的權限執行
        "DO $$ BEGIN EXECUTE 'DROP TABLE public.scans'; END $$",
        # 未授權的 DML
        *(f"TRUNCATE {table}" for table in sorted(APP_TABLE_PRIVILEGES)),
        *(
            f"UPDATE {table} SET {first[table]} = {first[table]}"  # noqa: S608 - 固定的表名
            for table in sorted(INSERT_ONLY_TABLES | {"projects", "alembic_version"})
        ),
        *(
            f"DELETE FROM {table}"  # noqa: S608 - 固定的表名
            for table in sorted(INSERT_ONLY_TABLES | STATEFUL_TABLES | {"projects"})
        ),
        "SELECT id FROM projects FOR UPDATE",
        "SELECT id FROM projects FOR NO KEY UPDATE",
        "SELECT id FROM projects FOR SHARE",
        "SELECT id FROM audit_events FOR UPDATE",
        "SELECT 1 FROM run_rule_locations",
        "INSERT INTO alembic_version (version_num) VALUES ('role03')",
        "DELETE FROM alembic_version",
    ]


def test_the_app_role_is_refused_everything_outside_its_grants(
    db_engine: Engine, owner_db_engine: Engine, migrated_database: ProvisionedDatabase
) -> None:
    before = _integrity_snapshot(owner_db_engine)
    first = {
        str(table): str(column)
        for table, column in _rows(
            owner_db_engine,
            "SELECT c.relname, a.attname FROM pg_attribute AS a "
            "JOIN pg_class AS c ON c.oid = a.attrelid "
            "JOIN pg_namespace AS n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'public' AND c.relkind = 'r' AND a.attnum = 1",
        )
    }

    with db_engine.connect() as connection, connection.begin():
        results = {
            statement: _sqlstate(connection, statement)
            for statement in _negative_statements(migrated_database, first)
        }

    assert results == dict.fromkeys(results, INSUFFICIENT_PRIVILEGE)
    assert _integrity_snapshot(owner_db_engine) == before


def test_server_level_statements_are_refused(db_engine: Engine) -> None:
    """ALTER SYSTEM 不能在 transaction 中執行，CREATE EXTENSION 一併以 autocommit 執行。"""
    with db_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
        for statement in ("ALTER SYSTEM SET work_mem = '1MB'", "CREATE EXTENSION pgcrypto"):
            with pytest.raises(DBAPIError) as caught:
                connection.execute(text(statement))
            assert isinstance(caught.value.orig, psycopg.Error)
            assert caught.value.orig.sqlstate == INSUFFICIENT_PRIVILEGE, statement


def test_granting_to_public_only_warns_and_changes_nothing(
    db_engine: Engine, owner_db_engine: Engine
) -> None:
    """沒有 GRANT OPTION 的 GRANT 只發出警告（A7）；ACL 不變。"""
    acl = "SELECT relacl::text FROM pg_class WHERE oid = 'public.scans'::regclass"
    before = _scalar(owner_db_engine, acl)

    with db_engine.connect() as connection, connection.begin():
        connection.execute(text("GRANT SELECT ON scans TO PUBLIC"))
        connection.execute(text("GRANT ALL ON scans TO PUBLIC"))

    assert _scalar(owner_db_engine, acl) == before


def _integrity_snapshot(engine: Engine) -> list[tuple[object, ...]]:
    """trigger 是否啟用、函式定義的雜湊、CHECK 與擁有者。"""
    return _rows(
        engine,
        "SELECT 'trigger', t.tgrelid::regclass::text || '.' || t.tgname, t.tgenabled::text "
        "FROM pg_trigger AS t WHERE NOT t.tgisinternal "
        "UNION ALL SELECT 'function', p.proname, md5(pg_get_functiondef(p.oid)) "
        "FROM pg_proc AS p JOIN pg_namespace AS n ON n.oid = p.pronamespace "
        "WHERE n.nspname = 'public' "
        "UNION ALL SELECT 'check', c.conname, md5(pg_get_constraintdef(c.oid)) "
        "FROM pg_constraint AS c JOIN pg_namespace AS n ON n.oid = c.connamespace "
        "WHERE n.nspname = 'public' "
        "UNION ALL SELECT 'owner', c.relname, pg_get_userbyid(c.relowner) FROM pg_class AS c "
        "JOIN pg_namespace AS n ON n.oid = c.relnamespace WHERE n.nspname = 'public' "
        "ORDER BY 1, 2",
    )


def test_every_trigger_is_enabled(owner_db_engine: Engine) -> None:
    disabled = _rows(
        owner_db_engine,
        "SELECT tgrelid::regclass::text, tgname FROM pg_trigger "
        "WHERE NOT tgisinternal AND tgenabled <> 'O'",
    )

    assert disabled == []


# ---------------------------------------------------------------- ROLE-04：正向


def test_triggers_fire_without_execute_on_their_functions(db_engine: Engine) -> None:
    """A1：trigger 觸發時不檢查函式的 EXECUTE；違規得到 trigger 的 23000，不是 42501。"""
    with db_engine.connect() as connection, connection.begin():
        state = _sqlstate(
            connection,
            "INSERT INTO evidence_holds (directory, error_code, attempts, source_ino, resolved_at) "
            "VALUES (gen_random_uuid(), 'EVIDENCE_TREE_TOO_DEEP', 1, 1, now())",
        )

    assert state == INTEGRITY_CONSTRAINT_VIOLATION


def test_identity_columns_need_no_sequence_privilege(seed: Seeder) -> None:
    """A2：identity 取號不檢查 sequence 的權限（seed 以應用程式角色經 service 建立 scan）。"""
    world = seed.world()
    scan = seed.scan(world.operator_a, seed.scannable(world))

    [row] = seed.query(
        "SELECT queue_position, pg_get_serial_sequence('scans', 'queue_position') AS sequence, "
        "has_sequence_privilege(current_user, pg_get_serial_sequence('scans', 'queue_position'), "
        "'USAGE') AS usable FROM scans WHERE id = :id",
        id=scan.id,
    )

    assert row.queue_position is not None
    assert (str(row.sequence).split(".")[-1], row.usable) == ("scans_queue_position_seq", False)


@pytest.mark.parametrize("table", sorted(STATEFUL_TABLES | DELETABLE_TABLES))
@pytest.mark.parametrize(
    "lock",
    ["FOR UPDATE", "FOR NO KEY UPDATE", "FOR SHARE", "FOR KEY SHARE", "FOR UPDATE SKIP LOCKED"],
)
def test_runtime_row_locks_are_allowed(db_engine: Engine, table: str, lock: str) -> None:
    with db_engine.connect() as connection, connection.begin():
        statement = f"SELECT 1 FROM {table} LIMIT 1 {lock}"  # noqa: S608 - 固定的表名與鎖
        assert _sqlstate(connection, statement) is None


def test_advisory_locks_need_no_grant(db_engine: Engine) -> None:
    with db_engine.connect() as connection, connection.begin():
        for statement in (
            "SELECT pg_advisory_xact_lock(28005, hashtext('role04'))",
            "SELECT pg_try_advisory_lock(8315161208123403877)",
            "SELECT pg_advisory_unlock(8315161208123403877)",
        ):
            assert _sqlstate(connection, statement) is None, statement


def test_readiness_is_ready_with_the_app_role(db_engine: Engine) -> None:
    assert probe_database(db_engine, head_revision()) is DatabaseStatus.READY


# ---------------------------------------------------------------- ROLE-08：T23a 的不變條件


@pytest.mark.parametrize(
    "statement",
    [
        "ALTER TABLE evidence_holds DISABLE TRIGGER evidence_holds_guard",
        "ALTER TABLE evidence_holds DISABLE TRIGGER evidence_holds_no_truncate",
        "ALTER TABLE run_evidence DISABLE TRIGGER run_evidence_hold_check",
        "ALTER TABLE run_evidence DISABLE TRIGGER run_evidence_guard",
        "ALTER TABLE run_evidence DISABLE TRIGGER run_evidence_no_truncate",
        *(
            f"ALTER TABLE evidence_holds DROP CONSTRAINT ck_evidence_holds_{name}"
            for name in (
                "isolated_after_held",
                "releasing_after_isolated",
                "resolved_after_releasing",
                "move_failures_valid",
                "move_error_valid",
                "move_failure_fields",
                "move_failed_after_held",
                "source_ino_valid",
                "isolated_has_source",
            )
        ),
        "SET session_replication_role = replica",
        "DELETE FROM evidence_holds",
        "TRUNCATE evidence_holds",
        "DELETE FROM run_evidence",
        "TRUNCATE run_evidence",
    ],
)
def test_the_app_role_cannot_bypass_the_evidence_hold_invariants(
    db_engine: Engine, statement: str
) -> None:
    with db_engine.connect() as connection, connection.begin():
        assert _sqlstate(connection, statement) == INSUFFICIENT_PRIVILEGE


def test_the_nine_isolation_checks_exist(owner_db_engine: Engine) -> None:
    checks = _rows(
        owner_db_engine,
        "SELECT conname FROM pg_constraint WHERE conrelid = 'evidence_holds'::regclass "
        "AND contype = 'c' AND conname IN ("
        "'ck_evidence_holds_isolated_after_held', 'ck_evidence_holds_releasing_after_isolated', "
        "'ck_evidence_holds_resolved_after_releasing', 'ck_evidence_holds_move_failures_valid', "
        "'ck_evidence_holds_move_error_valid', 'ck_evidence_holds_move_failure_fields', "
        "'ck_evidence_holds_move_failed_after_held', 'ck_evidence_holds_source_ino_valid', "
        "'ck_evidence_holds_isolated_has_source')",
    )

    assert len(checks) == 9


def test_the_app_role_can_only_hurt_itself(
    db_engine: Engine, owner_db_engine: Engine, migrated_database: ProvisionedDatabase
) -> None:
    """A8（§31.7、剩餘風險 2）：在回滾的 transaction 中驗證。

    - `DROP OWNED BY` 自己可以執行，但撤銷不了 owner 授予的權限（實測；和計畫的假設不同）；
    - 可以 `ALTER ROLE` 自己的參數，例如 `default_transaction_read_only`：之後的連線都不能寫入，
      只造成服務中斷；
    - 擁有權、trigger 與約束都不變。
    """
    before = _integrity_snapshot(owner_db_engine)
    app = migrated_database.user
    setting = (
        "SELECT coalesce(string_agg(array_to_string(setconfig, ','), ','), '') "
        "FROM pg_db_role_setting WHERE setrole = "
        "(SELECT oid FROM pg_roles WHERE rolname = current_user)"
    )

    with db_engine.connect() as connection:
        transaction = connection.begin()
        connection.execute(text(f'DROP OWNED BY "{app}"'))
        assert _sqlstate(connection, "SELECT 1 FROM scans LIMIT 1") is None
        connection.execute(text(f'ALTER ROLE "{app}" SET default_transaction_read_only = on'))
        assert "default_transaction_read_only=on" in connection.execute(text(setting)).scalar_one()
        transaction.rollback()

    assert _integrity_snapshot(owner_db_engine) == before
    with db_engine.connect() as connection:
        assert "default_transaction_read_only" not in connection.execute(text(setting)).scalar_one()
