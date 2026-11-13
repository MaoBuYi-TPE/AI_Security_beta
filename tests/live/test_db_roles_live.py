"""T23b-b1 的 live 驗收：DDL／DML 分權（docs/DECISIONS.md §31；make test-live-db-roles）。

只在 make test-live-runner 建立的獨立 stack 上執行（ENABLE_LIVE_LAB_TESTS=1）。全新的 DB volume 由
initdb 建立兩個角色，recipe 在主機上以 owner 執行 migration，之後才啟動 api、runner、worker。確認：

1. initdb 建立了兩個非 superuser 的角色，資料庫由 owner 擁有；
2. migration 以 owner 執行：public 中每個物件的擁有者都是 owner，版本是 head；應用程式角色的權限
   等於預期矩陣，default privileges 只有 owner 的全域函式條目；
3. api、runner、worker 的連線都是應用程式角色；
4. 應用程式角色的 DDL 被拒；
5. 三個服務的環境變數名稱中沒有 owner 的帳密（只取名稱，值不離開容器）。

psql 在 db 容器內以它自己的環境變數連線：密碼不經過測試，也不會印出。
"""

import subprocess

import pytest

from secscan.migrations import head_revision
from tests.db_privileges import APP_TABLE_PRIVILEGES
from tests.live.support import container, docker, wait_for

pytestmark = [pytest.mark.live]

SERVICES = {"api": "secscan-api", "runner": "secscan-runner", "worker": "secscan-worker"}
_OWNER_PSQL = (
    'PGPASSWORD="$SECSCAN_OWNER_DB_PASSWORD" psql -h 127.0.0.1 -U "$SECSCAN_OWNER_DB_USER" '
    '-d "$SECSCAN_APP_DB_NAME" -At -F "|" -q -v ON_ERROR_STOP=1 '
    '-v owner="$SECSCAN_OWNER_DB_USER" -v app="$SECSCAN_APP_DB_USER"'
)
_APP_PSQL = (
    'PGPASSWORD="$SECSCAN_APP_DB_PASSWORD" psql -h 127.0.0.1 -U "$SECSCAN_APP_DB_USER" '
    '-d "$SECSCAN_APP_DB_NAME" -At -q -v ON_ERROR_STOP=1'
)
# 執行環境中不能出現的變數名稱（owner 的帳密只交給 db 的 initdb）。
OWNER_NAMES = (
    "DB_OWNER_USER",
    "DB_OWNER_PASSWORD",
    "SECSCAN_OWNER_DB_USER",
    "SECSCAN_OWNER_DB_PASSWORD",
)


def _owner_rows(statement: str) -> list[list[str]]:
    output = docker("exec", "-i", container("db"), "sh", "-c", _OWNER_PSQL, stdin=statement)
    return [line.split("|") for line in output.splitlines() if line]


def _as_app(statement: str) -> subprocess.CompletedProcess[str]:
    # 執行的是固定的 docker 指令與這個檔案寫死的 SQL，沒有外部輸入。
    return subprocess.run(  # noqa: S603
        ["docker", "exec", "-i", container("db"), "sh", "-c", _APP_PSQL],  # noqa: S607
        input=statement,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


def test_initdb_created_two_non_superuser_roles_and_the_owner_owns_the_database() -> None:
    roles = _owner_rows(
        "SELECT rolname = :'owner', rolsuper, rolcreatedb, rolcreaterole, rolreplication, "
        "rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname IN (:'owner', :'app') ORDER BY 1;"
    )
    [[database_owner]] = _owner_rows(
        "SELECT pg_get_userbyid(datdba) = :'owner' FROM pg_database "
        "WHERE datname = current_database();"
    )
    memberships = _owner_rows(
        "SELECT count(*) FROM pg_auth_members WHERE member IN (SELECT oid FROM pg_roles "
        "WHERE rolname IN (:'owner', :'app')) OR roleid IN (SELECT oid FROM pg_roles "
        "WHERE rolname IN (:'owner', :'app'));"
    )

    assert roles == [["f", "f", "f", "f", "f", "f", "t"], ["t", "f", "f", "f", "f", "f", "t"]]
    assert database_owner == "t"
    assert memberships == [["0"]]


def test_migrations_ran_as_the_owner_and_granted_the_matrix() -> None:
    not_owned = _owner_rows(
        "SELECT c.relname FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace "
        "WHERE n.nspname = 'public' AND pg_get_userbyid(c.relowner) <> :'owner' "
        "UNION ALL SELECT p.proname FROM pg_proc AS p JOIN pg_namespace AS n "
        "ON n.oid = p.pronamespace WHERE n.nspname = 'public' "
        "AND pg_get_userbyid(p.proowner) <> :'owner';"
    )
    [[revision]] = _owner_rows("SELECT version_num FROM alembic_version;")
    grants = _owner_rows(
        "SELECT c.relname, item.privilege_type FROM pg_class AS c, aclexplode(c.relacl) AS item "
        "WHERE item.grantee = (SELECT oid FROM pg_roles WHERE rolname = :'app') ORDER BY 1, 2;"
    )
    defaults = _owner_rows(
        "SELECT pg_get_userbyid(defaclrole) = :'owner', defaclobjtype, defaclnamespace "
        "FROM pg_default_acl;"
    )

    assert not_owned == []
    assert revision == head_revision()
    granted: dict[str, set[str]] = {}
    for table, privilege in grants:
        granted.setdefault(table, set()).add(privilege)
    assert granted == {table: set(privileges) for table, privileges in APP_TABLE_PRIVILEGES.items()}
    assert defaults == [["t", "f", "0"]]


def test_the_services_connect_as_the_app_role() -> None:
    def observed() -> dict[str, set[str]] | None:
        rows = _owner_rows(
            "SELECT application_name, usename = :'app' FROM pg_stat_activity "
            "WHERE datname = current_database() AND application_name IN "
            "('secscan-api', 'secscan-runner', 'secscan-worker');"
        )
        found: dict[str, set[str]] = {}
        for name, is_app in rows:
            found.setdefault(name, set()).add(is_app)
        return found if set(found) == set(SERVICES.values()) else None

    # runner、worker 輪詢時才連線：等到三個都出現過。api 的 readiness 會連線。
    docker("exec", container("api"), "python", "-c", _READY)
    found = wait_for(observed, timeout=60)

    assert found == {name: {"t"} for name in SERVICES.values()}


_READY = (
    "import urllib.request\n"
    "urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=10).read()\n"
)


@pytest.mark.parametrize(
    ("statement", "message"),
    [
        ("CREATE TABLE public.live_ddl (id integer);", "permission denied for schema public"),
        ("ALTER TABLE scans ADD COLUMN live_ddl integer;", "must be owner"),
        ("ALTER TABLE audit_events DISABLE TRIGGER USER;", "must be owner"),
        ("TRUNCATE audit_events;", "permission denied"),
        ("SET session_replication_role = replica;", "permission denied"),
    ],
)
def test_the_app_role_cannot_run_ddl(statement: str, message: str) -> None:
    result = _as_app(statement)

    assert result.returncode != 0
    assert message in result.stderr


@pytest.mark.parametrize("service", sorted(SERVICES))
def test_the_services_never_receive_the_owner_credentials(service: str) -> None:
    """只在容器內列出變數名稱；值不離開容器、也不印出。"""
    names = docker(
        "exec",
        container(service),
        "python",
        "-c",
        "import os; print('\\n'.join(sorted(os.environ)))",
    ).split()

    assert "DB_USER" in names
    assert not [name for name in names if name in OWNER_NAMES or "OWNER" in name]
