"""每次 migration 之前的角色檢查（T23b-b1；docs/DECISIONS.md §31.4）。

migration 以 owner 角色執行，應用程式角色只有 v0025 授予的逐表 DML。下列任何一項不符合就停止，
不做任何改變：
1. 目前的角色（owner）不是 superuser、擁有目前的資料庫，也沒有其他高風險屬性或成員關係；
2. 應用程式角色存在、不是目前的角色、沒有任何高風險屬性，也沒有任何成員關係（不能經由繼承取得
   owner 或預先定義角色的權限）；
3. 應用程式角色在目前的資料庫與共用物件中不擁有任何物件（擁有者的修改、刪除權限撤銷不了）；
4. 應用程式角色（含經由 PUBLIC）沒有資料庫的 CREATE、TEMPORARY，也沒有 public 的 CREATE；
5. 應用程式角色、目前的角色與目前的資料庫都沒有角色或資料庫層級的設定（例如 superuser 設定的
   session_replication_role = replica 會讓應用程式的連線不觸發 trigger），只允許 timezone；目前的
   連線的 session_replication_role 也必須是 origin；應用程式角色（含經由 PUBLIC）也不能經由
   `GRANT SET ON PARAMETER` 設定這類只有 superuser 能改的參數；
6. default privileges 只能是 v0025 的那一列（owner 的全域函式條目，ACL 只有 owner 自己）。

這些檢查只能偵測：superuser 之後再改設定，這裡擋不住（§31.9 的剩餘風險）。
"""

from collections.abc import Sequence
from dataclasses import dataclass

from sqlalchemy import Connection, text

# 不影響權限與 trigger 的設定：應用程式的連線另外固定 timezone=UTC；整合測試的角色刻意設成
# Asia/Taipei。
ALLOWED_ROLE_SETTINGS = frozenset({"timezone"})
# 只有 superuser 能設定、改了就能繞過 trigger 或 large object 權限檢查的參數。
GUARDED_PARAMETERS = ("session_replication_role", "lo_compat_privileges")
TRANSFER_HINT = "既有的資料庫請先執行 make db-roles-migrate（README 的升級順序）"
_RISKY = (
    "r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls AS risky, "
    "(SELECT count(*) FROM pg_catalog.pg_auth_members AS m "
    "WHERE m.member = r.oid OR m.roleid = r.oid) AS memberships"
)
_CURRENT_ROLE = (
    "SELECT r.rolsuper AS superuser, d.datdba = r.oid AS owns_database, "  # noqa: S608 - 固定的片段
    + _RISKY
    + " FROM pg_catalog.pg_roles AS r, pg_catalog.pg_database AS d "
    "WHERE r.rolname = current_user AND d.datname = current_database()"
)
_NAMED_ROLE = (
    "SELECT r.oid, r.rolsuper AS superuser, "  # noqa: S608 - 固定的片段
    + _RISKY
    + " FROM pg_catalog.pg_roles AS r WHERE r.rolname = :name"
)


class MigrationRoleError(RuntimeError):
    """migration 的角色或設定不符合分權的前提；migration 沒有執行。"""


@dataclass(frozen=True, slots=True)
class _Role:
    oid: int
    risky: bool
    memberships: int


def verify_migration_roles(connection: Connection, app_role: str) -> None:
    problems = migration_role_problems(connection, app_role)
    if problems:
        raise MigrationRoleError("；".join(problems) + "（migration 沒有執行）")


def migration_role_problems(connection: Connection, app_role: str) -> tuple[str, ...]:
    problems = list(_current_role_problems(connection))
    current = connection.execute(text("SELECT current_user")).scalar_one()
    if app_role == current:
        problems.append("migration 必須以 owner 角色執行，不可使用應用程式角色")
        return tuple(problems)
    app = _role(connection, app_role)
    if app is None:
        problems.append(f"找不到應用程式角色 {app_role}")
        return tuple(problems)
    problems.extend(_app_role_problems(connection, app))
    problems.extend(setting_problems(connection, app.oid))
    problems.extend(_default_acl_problems(connection))
    return tuple(problems)


def _current_role_problems(connection: Connection) -> tuple[str, ...]:
    row = connection.execute(text(_CURRENT_ROLE)).one()
    problems = []
    if row.superuser:
        problems.append("migration 不可以 superuser 執行")
    elif row.risky:
        problems.append("owner 角色不可有 CREATEDB、CREATEROLE、REPLICATION 或 BYPASSRLS 屬性")
    if row.memberships:
        problems.append("owner 角色不可有任何成員關係")
    if not row.owns_database:
        problems.append(f"migration 的角色必須擁有目前的資料庫（{TRANSFER_HINT}）")
    return tuple(problems)


def _role(connection: Connection, name: str) -> _Role | None:
    row = connection.execute(text(_NAMED_ROLE), {"name": name}).one_or_none()
    if row is None:
        return None
    return _Role(
        oid=int(row.oid),
        risky=bool(row.superuser or row.risky),
        memberships=int(row.memberships),
    )


def _app_role_problems(connection: Connection, app: _Role) -> tuple[str, ...]:
    problems = []
    if app.risky:
        problems.append(
            "應用程式角色不可有 SUPERUSER、CREATEDB、CREATEROLE、REPLICATION 或 BYPASSRLS 屬性"
        )
    if app.memberships:
        problems.append("應用程式角色不可有任何成員關係（不能經由繼承取得其他角色的權限）")
    owned = connection.execute(
        text(
            "SELECT count(*) FROM pg_catalog.pg_shdepend "
            "WHERE refclassid = 'pg_catalog.pg_authid'::regclass AND refobjid = :role "
            "AND deptype = 'o' AND dbid IN (0, "
            "(SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database()))"
        ),
        {"role": app.oid},
    ).scalar_one()
    if owned:
        problems.append(f"應用程式角色擁有 {owned} 個物件（{TRANSFER_HINT}）")
    creates = connection.execute(
        text(
            "SELECT has_database_privilege(CAST(:role AS oid), current_database(), 'CREATE') "
            "OR has_database_privilege(CAST(:role AS oid), current_database(), 'TEMPORARY') "
            "OR has_schema_privilege(CAST(:role AS oid), 'public', 'CREATE')"
        ),
        {"role": app.oid},
    ).scalar_one()
    if creates:
        problems.append(
            "應用程式角色（含經由 PUBLIC）有資料庫的 CREATE、TEMPORARY 或 public 的 CREATE"
        )
    return tuple(problems)


def _default_acl_problems(connection: Connection) -> tuple[str, ...]:
    """只允許 v0025 的那一列：目前的角色、函式、全域、ACL 只有它自己的 EXECUTE。"""
    unexpected = connection.execute(
        text(
            "SELECT count(*) FROM pg_catalog.pg_default_acl AS entry WHERE NOT ("
            "entry.defaclrole = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user) "
            "AND entry.defaclobjtype = 'f' AND entry.defaclnamespace = 0 "
            "AND entry.defaclacl = ARRAY[pg_catalog.makeaclitem("
            "entry.defaclrole, entry.defaclrole, 'EXECUTE', false)])"
        )
    ).scalar_one()
    if unexpected:
        return (f"有 {unexpected} 列非預期的 default privileges（ALTER DEFAULT PRIVILEGES）",)
    return ()


def setting_problems(connection: Connection, app_oid: int) -> tuple[str, ...]:
    """應用程式角色、目前的角色與目前的資料庫的設定，以及目前連線的 session_replication_role。"""
    current = connection.execute(
        text("SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user")
    ).scalar_one()
    found = (
        *role_settings(connection, (app_oid, int(current))),
        *parameter_grants(connection, app_oid),
    )
    problems = []
    if found:
        problems.append("有角色或資料庫層級的設定：" + "、".join(found))
    replication = connection.execute(
        text("SELECT current_setting('session_replication_role')")
    ).scalar_one()
    if replication != "origin":
        problems.append("目前連線的 session_replication_role 不是 origin（trigger 不會觸發）")
    return tuple(problems)


def parameter_grants(connection: Connection, role: int) -> tuple[str, ...]:
    """應用程式角色（含經由 PUBLIC）能 SET 或 ALTER SYSTEM 的受保護參數（GRANT ON PARAMETER）。"""
    found = []
    for parameter in GUARDED_PARAMETERS:
        granted = connection.execute(
            text(
                "SELECT has_parameter_privilege(CAST(:role AS oid), :parameter, 'SET') "
                "OR has_parameter_privilege(CAST(:role AS oid), :parameter, 'ALTER SYSTEM')"
            ),
            {"role": role, "parameter": parameter},
        ).scalar_one()
        if granted:
            found.append(f"應用程式角色可以設定的參數 {parameter}（GRANT ON PARAMETER）")
    return tuple(found)


def role_settings(connection: Connection, roles: Sequence[int]) -> tuple[str, ...]:
    """這些角色（含 ALTER ROLE ALL）在所有資料庫或目前的資料庫的設定，以及 ALTER DATABASE 的設定。

    只列出名稱，不列出值；ALLOWED_ROLE_SETTINGS 除外。migrate-db-roles 也用它。
    """
    rows = connection.execute(
        text(
            "SELECT CASE WHEN setting.setrole = 0 THEN 'ALL' ELSE role.rolname END AS role_name, "
            "setting.setdatabase <> 0 AS in_database, setting.setconfig AS config "
            "FROM pg_catalog.pg_db_role_setting AS setting "
            "LEFT JOIN pg_catalog.pg_roles AS role ON role.oid = setting.setrole "
            "WHERE (setting.setrole = 0 OR setting.setrole = ANY (CAST(:roles AS oid[]))) "
            "AND setting.setdatabase IN (0, "
            "(SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database()))"
        ),
        {"roles": list(roles)},
    )
    return tuple(
        sorted(
            f"{_setting_scope(row.role_name, in_database=row.in_database)} 的 {name}"
            for row in rows
            for name in _setting_names(row.config)
            if name not in ALLOWED_ROLE_SETTINGS
        )
    )


def _setting_scope(role_name: str | None, *, in_database: bool) -> str:
    role = "所有角色" if role_name == "ALL" else f"角色 {role_name}"
    if role_name == "ALL" and in_database:
        return "目前的資料庫"
    return f"{role}（目前的資料庫）" if in_database else role


def _setting_names(config: list[str] | None) -> tuple[str, ...]:
    return tuple(entry.split("=", 1)[0].strip().lower() for entry in config or ())
