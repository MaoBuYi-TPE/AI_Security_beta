"""既有資料庫的擁有權移轉（T23b-b1；docs/SECURITY_AND_TESTING.md §4.3 的 ROLE-06）。

舊的狀態（S0）由 superuser 建立：應用程式角色擁有資料庫，並以它 migrate（和 T23b-b1 之前的開發 DB
相同）。移轉指令在 db-test 上執行（expected_cluster=secscan-test）；開發 DB 的移轉由使用者執行
（G5）。

- dry-run 列出的物件等於實際的物件，沒有任何改變；
- 移轉之後應用程式角色不擁有任何物件、owner 擁有原本兩者的聯集；不相關的物件（第三個角色的資料庫
  與物件、postgres 中的物件）不變；之後 migrate 到 head，權限符合矩陣；
- 範圍之外的項目一律拒絕、沒有任何改變；中斷時完全 rollback，再執行一次就完成；
- 已移轉（S1、S2）時不寫入任何東西；輸出與例外都不含密碼。
"""

import dataclasses
import secrets
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

import pytest
import sqlalchemy
from alembic import command
from psycopg import sql
from pydantic import SecretStr
from sqlalchemy import Engine, text

from secscan.cli import db_roles
from secscan.cli.db_roles import EXIT_FAILURE, EXIT_OK, Target, migrate_db_roles
from secscan.cli.db_roles_scope import classify as real_classify
from secscan.cli.scram import scram_matches
from secscan.core.db import DatabaseStatus, probe_database
from secscan.migrations import alembic_config, head_revision
from tests.db_privileges import APP_TABLE_PRIVILEGES
from tests.integration.conftest import app_engine, migrate_to_head
from tests.integration.database import TEST_CLUSTER_NAME, DatabaseProvisioner, ProvisionedDatabase
from tests.integration.role_support import Superuser

pytestmark = pytest.mark.integration

APP_OWNED = (
    "SELECT pg_describe_object(d.classid, d.objid, d.objsubid) FROM pg_shdepend AS d "
    "JOIN pg_roles AS r ON r.oid = d.refobjid WHERE d.deptype = 'o' AND r.rolname = :role "
    "AND d.dbid IN (0, (SELECT oid FROM pg_database WHERE datname = current_database())) "
    "ORDER BY 1"
)
OWNED_COUNT = (
    "SELECT count(*) FROM pg_shdepend AS d JOIN pg_roles AS r ON r.oid = d.refobjid "
    "WHERE d.deptype = 'o' AND r.rolname = :role"
)
AUDITS = "SELECT count(*) FROM audit_events WHERE action = 'db_roles.migrated'"


@dataclass
class Legacy:
    """S0 的資料庫，以及這個測試另外建立、要清除的資料庫與角色。"""

    database: ProvisionedDatabase
    superuser: Superuser
    root: Superuser
    extra_databases: list[str] = field(default_factory=list)
    extra_roles: list[str] = field(default_factory=list)
    # 影響整個 cluster 的狀態（例如 GRANT ON PARAMETER … TO PUBLIC）：結束時一定先還原。
    cleanup: list[sql.Composed | sql.SQL] = field(default_factory=list)

    def target(
        self, *, owner_password: str | None = None, cluster: str = TEST_CLUSTER_NAME
    ) -> Target:
        return Target(
            host=self.database.host,
            port=self.database.port,
            database=self.database.name,
            app_role=self.database.user,
            owner_role=self.database.owner_user,
            owner_password=SecretStr(owner_password or self.database.owner_password),
            admin_user=self.root.user,
            admin_password=self.root.password,
            connect_timeout_seconds=5,
            expected_cluster=cluster,
        )

    def names(self) -> dict[str, sql.Identifier]:
        base = self.database.base
        return {
            "app": sql.Identifier(self.database.user),
            "owner": sql.Identifier(self.database.owner_user),
            "database": sql.Identifier(self.database.name),
            "other": sql.Identifier(f"{base}_other"),
            "third": sql.Identifier(f"{base}_third"),
        }

    def database_named(self, suffix: str) -> str:
        name = f"{self.database.base}_{suffix}"
        self.extra_databases.append(name)
        return name

    def role_named(self, suffix: str) -> str:
        name = f"{self.database.base}_{suffix}"
        self.extra_roles.append(name)
        return name


def _legacy(provisioner: DatabaseProvisioner, revision: str | None) -> Iterator[Legacy]:
    database = provisioner.create(legacy=True)
    engine = app_engine(database)
    try:
        # 和 T23b-b1 之前的 make migrate 相同：應用程式角色自己 migrate（不檢查角色）。
        if revision is not None:
            with engine.begin() as connection:
                command.upgrade(alembic_config(connection=connection), revision)
    finally:
        engine.dispose()
    root = Superuser(provisioner, "postgres")
    legacy = Legacy(database=database, superuser=Superuser(provisioner, database.name), root=root)
    try:
        yield legacy
    finally:
        root.run(*legacy.cleanup)
        legacy.superuser.dispose()
        for name in legacy.extra_databases:
            root.run(
                sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name))
            )
        root.run(
            sql.SQL("DROP TABLE IF EXISTS public.{}").format(
                sql.Identifier(f"{database.base}_probe")
            )
        )
        provisioner.drop(database)
        # 第三個角色可能擁有目標資料庫中的物件：資料庫刪除之後才能刪除它。
        for name in legacy.extra_roles:
            root.run(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(name)))
        root.dispose()


@pytest.fixture
def legacy(provisioner: DatabaseProvisioner) -> Iterator[Legacy]:
    """升到 0024 的舊資料庫（和要移轉的開發 DB 相同的物件）。"""
    yield from _legacy(provisioner, "0024")


@pytest.fixture
def small_legacy(provisioner: DatabaseProvisioner) -> Iterator[Legacy]:
    """只升到 0001 的舊資料庫：拒絕的情境只需要少量物件，測試比較快。"""
    yield from _legacy(provisioner, "0001")


@pytest.fixture
def empty_legacy(provisioner: DatabaseProvisioner) -> Iterator[Legacy]:
    """還沒有任何 migration 的舊資料庫（沒有 audit_events）。"""
    yield from _legacy(provisioner, None)


def _owner_exists(legacy: Legacy) -> bool:
    rows = legacy.root.rows(
        "SELECT count(*) FROM pg_roles WHERE rolname = :name", name=legacy.database.owner_user
    )
    return rows == [(1,)]


# ---------------------------------------------------------------- dry-run 與移轉


def test_dry_run_lists_exactly_the_objects_and_changes_nothing(legacy: Legacy) -> None:
    expected = [
        str(name) for (name,) in legacy.superuser.rows(APP_OWNED, role=legacy.database.user)
    ]
    before = legacy.root.cluster_snapshot(legacy.database.base)
    messages: list[str] = []

    assert migrate_db_roles(legacy.target(), dry_run=True, report=messages.append) == EXIT_OK

    listed = [line.removeprefix("  - ") for line in messages if line.startswith("  - ")]
    assert sorted(listed) == sorted(expected)
    assert len(expected) > 60  # 29 張表、2 個 sequence、trigger 函式與資料庫本身
    assert any(line.startswith("小計：") for line in messages)
    assert any("S0" in line for line in messages)
    assert legacy.root.cluster_snapshot(legacy.database.base) == before
    assert not _owner_exists(legacy)


def _unrelated(legacy: Legacy) -> Callable[[], list[tuple[object, ...]]]:
    """第三個角色擁有的另一個資料庫與其中的表，以及 postgres 中的表。"""
    names = legacy.names()
    third = legacy.role_named("third")
    other = legacy.database_named("other")
    legacy.root.run(
        sql.SQL("CREATE ROLE {} NOLOGIN").format(names["third"]),
        sql.SQL("CREATE DATABASE {} OWNER {}").format(names["other"], names["third"]),
        sql.SQL("CREATE TABLE public.{} (id integer)").format(
            sql.Identifier(f"{legacy.database.base}_probe")
        ),
        sql.SQL("ALTER TABLE public.{} OWNER TO {}").format(
            sql.Identifier(f"{legacy.database.base}_probe"), names["third"]
        ),
    )
    in_other = legacy.root.at(other)
    in_other.run(
        "CREATE TABLE public.kept (id integer)",
        sql.SQL("ALTER TABLE public.kept OWNER TO {}").format(sql.Identifier(third)),
    )
    in_other.dispose()

    def snapshot() -> list[tuple[object, ...]]:
        rows = legacy.root.rows(
            "SELECT 'database', datname, pg_get_userbyid(datdba) FROM pg_database "
            "WHERE datname = :other UNION ALL SELECT 'table', relname, pg_get_userbyid(relowner) "
            "FROM pg_class WHERE relname = :probe UNION ALL SELECT 'owned', rolname, "
            "(SELECT count(*) FROM pg_shdepend WHERE refobjid = pg_roles.oid)::text "
            "FROM pg_roles WHERE rolname = :third ORDER BY 1, 2",
            other=other,
            probe=f"{legacy.database.base}_probe",
            third=third,
        )
        inside = legacy.root.at(other)
        try:
            return rows + inside.rows(
                "SELECT 'other table', relname, pg_get_userbyid(relowner) FROM pg_class "
                "WHERE relname = 'kept'"
            )
        finally:
            inside.dispose()

    return snapshot


def test_the_transfer_moves_everything_and_nothing_else(legacy: Legacy) -> None:
    app, owner = legacy.database.user, legacy.database.owner_user
    before_app = legacy.superuser.rows(APP_OWNED, role=app)
    unrelated = _unrelated(legacy)
    unrelated_before = unrelated()
    messages: list[str] = []

    assert migrate_db_roles(legacy.target(), dry_run=False, report=messages.append) == EXIT_OK

    assert legacy.root.rows(OWNED_COUNT, role=app) == [(0,)]
    assert legacy.superuser.rows(APP_OWNED, role=owner) == before_app
    assert unrelated() == unrelated_before
    assert legacy.superuser.rows(AUDITS) == [(1,)]
    assert any("可以登入" in line for line in messages)

    migrate_to_head(legacy.database)

    grants = legacy.superuser.rows(
        "SELECT c.relname, item.privilege_type FROM pg_class AS c, aclexplode(c.relacl) AS item "
        "WHERE item.grantee = (SELECT oid FROM pg_roles WHERE rolname = :app)",
        app=app,
    )
    granted: dict[str, set[str]] = {}
    for table, privilege in grants:
        granted.setdefault(str(table), set()).add(str(privilege))
    assert granted == {table: set(privileges) for table, privileges in APP_TABLE_PRIVILEGES.items()}
    engine = app_engine(legacy.database)
    try:
        assert probe_database(engine, head_revision()) is DatabaseStatus.READY
    finally:
        engine.dispose()


def test_rerunning_after_the_transfer_writes_nothing(legacy: Legacy) -> None:
    assert migrate_db_roles(legacy.target(), dry_run=False, report=lambda _: None) == EXIT_OK
    for stage in ("S1", "S2"):
        if stage == "S2":
            migrate_to_head(legacy.database)
        before = legacy.root.cluster_snapshot(legacy.database.base)
        messages: list[str] = []

        assert migrate_db_roles(legacy.target(), dry_run=False, report=messages.append) == EXIT_OK

        assert any(stage in line for line in messages), stage
        assert any("已完成移轉" in line for line in messages), stage
        assert legacy.root.cluster_snapshot(legacy.database.base) == before, stage
        assert legacy.superuser.rows(AUDITS) == [(1,)], stage


def test_an_existing_owner_with_the_right_password_is_reused(small_legacy: Legacy) -> None:
    names = small_legacy.names()
    small_legacy.root.run(
        sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
            names["owner"], sql.Literal(small_legacy.database.owner_password)
        )
    )

    result = migrate_db_roles(small_legacy.target(), dry_run=False, report=lambda _: None)

    assert result == EXIT_OK
    assert small_legacy.root.rows(OWNED_COUNT, role=small_legacy.database.user) == [(0,)]


def test_an_interrupted_transfer_rolls_back_and_finishes_when_run_again(
    legacy: Legacy, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = legacy.root.cluster_snapshot(legacy.database.base)

    def interrupted(*_args: object) -> None:
        raise RuntimeError("interrupted after REASSIGN OWNED")

    monkeypatch.setattr(db_roles, "record_audit", interrupted)
    with pytest.raises(RuntimeError, match="interrupted"):
        migrate_db_roles(legacy.target(), dry_run=False, report=lambda _: None)

    assert legacy.root.cluster_snapshot(legacy.database.base) == before
    assert not _owner_exists(legacy)

    monkeypatch.undo()
    assert migrate_db_roles(legacy.target(), dry_run=False, report=lambda _: None) == EXIT_OK
    assert legacy.root.rows(OWNED_COUNT, role=legacy.database.user) == [(0,)]


def test_a_different_cluster_is_refused(small_legacy: Legacy) -> None:
    messages: list[str] = []

    result = migrate_db_roles(
        small_legacy.target(cluster="secscan-dev"), dry_run=False, report=messages.append
    )

    assert result == EXIT_FAILURE
    assert any("cluster_name" in line for line in messages)
    assert not _owner_exists(small_legacy)


def test_passwords_never_appear_in_the_output(
    legacy: Legacy, caplog: pytest.LogCaptureFixture
) -> None:
    canary = "canary" + secrets.token_hex(16)
    messages: list[str] = []
    target = legacy.target(owner_password=canary)
    admin = target.admin_password.get_secret_value()

    for dry_run in (True, False):
        migrate_db_roles(target, dry_run=dry_run, report=messages.append)

    text_out = "\n".join(messages) + caplog.text
    assert canary not in text_out
    assert admin not in text_out
    assert legacy.database.password not in text_out


# ---------------------------------------------------------------- 拒絕（沒有任何改變）


def _second_database(legacy: Legacy) -> None:
    name = legacy.database_named("second")
    legacy.root.run(
        sql.SQL("CREATE DATABASE {} OWNER {}").format(sql.Identifier(name), legacy.names()["app"])
    )


def _object_in_other_database(legacy: Legacy) -> None:
    name = legacy.database_named("other")
    legacy.root.run(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    inside = legacy.root.at(name)
    inside.run(
        "CREATE TABLE public.elsewhere (id integer)",
        sql.SQL("ALTER TABLE public.elsewhere OWNER TO {}").format(legacy.names()["app"]),
    )
    inside.dispose()


def _grant_on_other_database(legacy: Legacy) -> None:
    name = legacy.database_named("other")
    legacy.root.run(
        sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)),
        sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
            sql.Identifier(name), legacy.names()["app"]
        ),
    )


def _in_target(*statements: str) -> Callable[[Legacy], None]:
    def setup(legacy: Legacy) -> None:
        names = legacy.names()
        legacy.superuser.run(*(sql.SQL(statement).format(**names) for statement in statements))

    return setup


def _third_role_object(legacy: Legacy) -> None:
    legacy.role_named("third")
    names = legacy.names()
    legacy.root.run(sql.SQL("CREATE ROLE {} NOLOGIN").format(names["third"]))
    legacy.superuser.run(
        "CREATE TABLE public.extra (id integer)",
        sql.SQL("ALTER TABLE public.extra OWNER TO {}").format(names["third"]),
    )


def _owner(*options: str, password: str | None = None) -> Callable[[Legacy], None]:
    def setup(legacy: Legacy) -> None:
        secret = password if password is not None else legacy.database.owner_password
        legacy.root.run(
            sql.SQL("CREATE ROLE {} LOGIN " + " ".join(options) + " PASSWORD {}").format(
                legacy.names()["owner"], sql.Literal(secret)
            )
        )

    return setup


def _parameter_grant(grantee: str) -> Callable[[Legacy], None]:
    """superuser 讓應用程式角色或 PUBLIC 能設定 session_replication_role（繞過 trigger）。"""

    def setup(legacy: Legacy) -> None:
        names = legacy.names()
        to = sql.SQL("PUBLIC") if grantee == "PUBLIC" else names["app"]
        legacy.cleanup.append(
            sql.SQL("REVOKE SET ON PARAMETER session_replication_role FROM {}").format(to)
        )
        legacy.root.run(sql.SQL("GRANT SET ON PARAMETER session_replication_role TO {}").format(to))

    return setup


def _owner_with_membership(legacy: Legacy) -> None:
    _owner()(legacy)
    legacy.root.run(sql.SQL("GRANT pg_monitor TO {}").format(legacy.names()["owner"]))


def _owner_with_another_database(legacy: Legacy) -> None:
    _owner()(legacy)
    name = legacy.database_named("owned")
    legacy.root.run(
        sql.SQL("CREATE DATABASE {} OWNER {}").format(sql.Identifier(name), legacy.names()["owner"])
    )


REFUSALS: dict[str, Callable[[Legacy], None]] = {
    "second-database": _second_database,
    "object-in-other-database": _object_in_other_database,
    "grant-on-other-database": _grant_on_other_database,
    "schema": _in_target("CREATE SCHEMA evil AUTHORIZATION {app}"),
    "large-object": _in_target(
        "SELECT lo_create(16777216)", "ALTER LARGE OBJECT 16777216 OWNER TO {app}"
    ),
    "plain-function": _in_target(
        "CREATE FUNCTION public.helper() RETURNS integer LANGUAGE sql AS 'SELECT 1'",
        "ALTER FUNCTION public.helper() OWNER TO {app}",
    ),
    "view": _in_target(
        "CREATE VIEW public.leak AS SELECT 1 AS one", "ALTER VIEW public.leak OWNER TO {app}"
    ),
    "third-role-object": _third_role_object,
    "superuser-object": _in_target("CREATE TABLE public.superuser_extra (id integer)"),
    "app-default-acl": _in_target(
        "ALTER DEFAULT PRIVILEGES FOR ROLE {app} GRANT SELECT ON TABLES TO PUBLIC"
    ),
    "membership": _in_target("GRANT pg_read_all_data TO {app}"),
    "role-setting": _in_target("ALTER ROLE {app} SET session_replication_role = replica"),
    "database-setting": _in_target("ALTER DATABASE {database} SET search_path = public"),
    "owner-attributes": _owner("CREATEDB"),
    "owner-membership": _owner_with_membership,
    "owner-password": _owner(password="not-the-password-in-dotenv"),
    "owner-other-database": _owner_with_another_database,
    "parameter-acl-app": _parameter_grant("app"),
    "parameter-acl-public": _parameter_grant("PUBLIC"),
    "role-all-setting": lambda legacy: _role_all_setting(legacy),
}


def _role_all_setting(legacy: Legacy) -> None:
    legacy.cleanup.append(sql.SQL("ALTER ROLE ALL RESET statement_timeout"))
    legacy.root.run("ALTER ROLE ALL SET statement_timeout = '7s'")


@pytest.mark.parametrize("scenario", sorted(REFUSALS))
def test_anything_outside_the_expected_scope_is_refused(
    small_legacy: Legacy, scenario: str
) -> None:
    REFUSALS[scenario](small_legacy)
    owner_existed = _owner_exists(small_legacy)
    before = small_legacy.root.cluster_snapshot(small_legacy.database.base)
    messages: list[str] = []

    for dry_run in (True, False):
        result = migrate_db_roles(small_legacy.target(), dry_run=dry_run, report=messages.append)
        assert result == EXIT_FAILURE, (scenario, dry_run)

    assert any("拒絕" in line for line in messages), scenario
    assert small_legacy.root.cluster_snapshot(small_legacy.database.base) == before, scenario
    assert _owner_exists(small_legacy) == owner_existed
    # 清除角色層級的設定與成員關係（資料庫層級的會和資料庫一起刪除）。
    names = small_legacy.names()
    small_legacy.root.run(
        sql.SQL("ALTER ROLE {} RESET ALL").format(names["app"]),
        sql.SQL("REVOKE pg_read_all_data FROM {}").format(names["app"]),
    )


def test_an_open_app_connection_is_refused(small_legacy: Legacy) -> None:
    engine: Engine = app_engine(small_legacy.database)
    messages: list[str] = []
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            result = migrate_db_roles(small_legacy.target(), dry_run=False, report=messages.append)
    finally:
        engine.dispose()

    assert result == EXIT_FAILURE
    assert any("make down" in line for line in messages)
    assert not _owner_exists(small_legacy)


# ---------------------------------------------------------------- 錯誤的路徑


def test_a_database_without_migrations_is_transferred_without_an_audit(
    empty_legacy: Legacy,
) -> None:
    messages: list[str] = []

    assert migrate_db_roles(empty_legacy.target(), dry_run=False, report=messages.append) == EXIT_OK

    assert empty_legacy.root.rows(OWNED_COUNT, role=empty_legacy.database.user) == [(0,)]
    assert any("可以登入" in line for line in messages)


def test_the_owner_is_created_with_a_scram_verifier(small_legacy: Legacy) -> None:
    """明文密碼不送到伺服器：保存的是本機產生的 verifier，而且和 .env 的密碼相符。"""
    assert migrate_db_roles(small_legacy.target(), dry_run=False, report=lambda _: None) == EXIT_OK

    [(verifier,)] = small_legacy.root.rows(
        "SELECT rolpassword FROM pg_authid WHERE rolname = :name",
        name=small_legacy.database.owner_user,
    )
    assert str(verifier).startswith("SCRAM-SHA-256$4096:")
    assert scram_matches(str(verifier), small_legacy.database.owner_password)


def test_a_wrong_admin_password_changes_nothing(small_legacy: Legacy) -> None:
    target = dataclasses.replace(small_legacy.target(), admin_password=SecretStr("wrong"))
    messages: list[str] = []

    assert migrate_db_roles(target, dry_run=False, report=messages.append) == EXIT_FAILURE

    assert any("DB_ADMIN_USER" in line for line in messages)
    assert not _owner_exists(small_legacy)


def test_a_lock_timeout_is_reported_as_retryable(small_legacy: Legacy) -> None:
    """另一個 migrate-db-roles 持有工具的鎖：等 LOCK_TIMEOUT 之後 rollback，沒有任何改變。"""
    messages: list[str] = []
    with small_legacy.superuser.engine.connect() as holder:
        holder.execute(text("SELECT pg_advisory_lock(:key)"), {"key": db_roles.TOOL_LOCK_KEY})
        result = migrate_db_roles(small_legacy.target(), dry_run=False, report=messages.append)

    assert result == EXIT_FAILURE
    assert any("等鎖超過" in line for line in messages)
    assert not _owner_exists(small_legacy)


def test_database_errors_roll_back_everything(
    small_legacy: Legacy, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(connection: object, _target: Target) -> None:
        assert isinstance(connection, sqlalchemy.Connection)
        connection.execute(text("SELECT * FROM no_such_table"))

    monkeypatch.setattr(db_roles, "_reassign", broken)
    messages: list[str] = []

    assert (
        migrate_db_roles(small_legacy.target(), dry_run=False, report=messages.append)
        == EXIT_FAILURE
    )

    assert any("42P01" in line for line in messages)
    assert not _owner_exists(small_legacy)


def test_a_failed_post_check_rolls_back(
    small_legacy: Legacy, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "secscan.cli.db_roles_catalog.ownership_problems",
        lambda *_: ("移轉前後其他角色擁有的物件不同",),
    )
    messages: list[str] = []
    before = small_legacy.root.cluster_snapshot(small_legacy.database.base)

    assert (
        migrate_db_roles(small_legacy.target(), dry_run=False, report=messages.append)
        == EXIT_FAILURE
    )

    assert any("事後檢查不符" in line for line in messages)
    assert small_legacy.root.cluster_snapshot(small_legacy.database.base) == before


def test_objects_created_after_the_classification_are_not_transferred(
    small_legacy: Legacy, monkeypatch: pytest.MonkeyPatch
) -> None:
    """分類之後才出現的物件（READ COMMITTED 下的空檔）：和分類的鍵不同就拒絕。"""
    original = real_classify

    def classify_then_create(snapshot: object) -> object:
        plan = original(snapshot)  # type: ignore[arg-type]
        small_legacy.superuser.run(
            "CREATE TABLE public.late (id integer)",
            sql.SQL("ALTER TABLE public.late OWNER TO {}").format(small_legacy.names()["app"]),
        )
        return plan

    monkeypatch.setattr("secscan.cli.db_roles.classify", classify_then_create)
    messages: list[str] = []

    assert (
        migrate_db_roles(small_legacy.target(), dry_run=False, report=messages.append)
        == EXIT_FAILURE
    )

    assert any("分類之後" in line for line in messages)
    assert not _owner_exists(small_legacy)


def test_a_failure_to_create_the_owner_rolls_back_without_the_password(
    small_legacy: Legacy, monkeypatch: pytest.MonkeyPatch
) -> None:
    """owner 在分類之後才被別人建立：CREATE ROLE 失敗，訊息只有 SQLSTATE，沒有密碼。"""
    original = real_classify
    names = small_legacy.names()

    def classify_then_create(snapshot: object) -> object:
        plan = original(snapshot)  # type: ignore[arg-type]
        small_legacy.cleanup.append(sql.SQL("DROP ROLE IF EXISTS {}").format(names["owner"]))
        small_legacy.root.run(sql.SQL("CREATE ROLE {} NOLOGIN").format(names["owner"]))
        return plan

    monkeypatch.setattr("secscan.cli.db_roles.classify", classify_then_create)
    messages: list[str] = []

    assert (
        migrate_db_roles(small_legacy.target(), dry_run=False, report=messages.append)
        == EXIT_FAILURE
    )

    assert any("無法建立 owner 角色（SQLSTATE 42710）" in line for line in messages)
    assert all(small_legacy.database.owner_password not in line for line in messages)
    assert small_legacy.root.rows(OWNED_COUNT, role=small_legacy.database.user) != [(0,)]


def test_a_failed_commit_is_reported_as_uncertain(small_legacy: Legacy) -> None:
    """commit 時才失敗（deferred constraint trigger）：結果不確定，請以 dry-run 確認。"""
    names = small_legacy.names()
    small_legacy.superuser.run(
        "CREATE FUNCTION public.reject_at_commit() RETURNS trigger LANGUAGE plpgsql "
        "SET search_path = pg_catalog AS 'BEGIN RAISE EXCEPTION ''rejected at commit''; END'",
        sql.SQL("ALTER FUNCTION public.reject_at_commit() OWNER TO {}").format(names["app"]),
        "CREATE CONSTRAINT TRIGGER reject_at_commit AFTER INSERT ON public.audit_events "
        "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.reject_at_commit()",
    )
    messages: list[str] = []

    assert (
        migrate_db_roles(small_legacy.target(), dry_run=False, report=messages.append)
        == EXIT_FAILURE
    )

    assert any("結果不確定" in line for line in messages)
    assert not _owner_exists(small_legacy)


def test_an_owner_that_cannot_log_in_is_reported(legacy: Legacy) -> None:
    assert migrate_db_roles(legacy.target(), dry_run=False, report=lambda _: None) == EXIT_OK
    messages: list[str] = []
    target = dataclasses.replace(legacy.target(), owner_password=SecretStr("wrong-password"))

    assert db_roles.confirm_owner_login(target, messages.append) == EXIT_FAILURE

    assert any("無法以 .env 的 DB_OWNER_PASSWORD 登入" in line for line in messages)
