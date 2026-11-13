"""migrate-db-roles 讀取的 catalog（T23b-b1；docs/DECISIONS.md §31.5）。

以 superuser 連到目標資料庫：

- pg_shdepend 是共用的 catalog：應用程式角色與 owner 在**所有資料庫**中的依賴都看得到。目標資料庫與
  共用物件以 pg_describe_object 顯示名稱；其他資料庫只能顯示資料庫與 catalog 的名稱。
- bootstrap superuser 擁有的物件不記在 pg_shdepend（pinned），所以目標資料庫中其他角色的物件另外以
  每個有擁有者欄位的 catalog 列舉（oid ≥ 16384，也就是 initdb 之後建立的物件）。
- 所有查詢都是固定的 SQL，角色名稱以參數傳入。
"""

from dataclasses import dataclass

from sqlalchemy import Connection, text

from secscan.cli.db_roles_scope import Dependency, Kind, RoleFacts, Snapshot
from secscan.cli.scram import scram_matches
from secscan.migrations.roles import parameter_grants, role_settings

# FirstNormalObjectId：initdb 建立的物件（含 plpgsql 與 public）都小於它。
FIRST_USER_OID = 16384

_ROLE = (
    "SELECT r.oid, r.rolcanlogin AND (r.rolvaliduntil IS NULL OR r.rolvaliduntil > now()) "
    "AS login, r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication "
    "OR r.rolbypassrls AS risky, (SELECT count(*) FROM pg_catalog.pg_auth_members AS m "
    "WHERE m.member = r.oid OR m.roleid = r.oid) AS memberships, a.rolpassword AS verifier "
    "FROM pg_catalog.pg_roles AS r JOIN pg_catalog.pg_authid AS a ON a.oid = r.oid "
    "WHERE r.rolname = :name"
)
_CURRENT_DATABASE = "(SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database())"
_KIND = f"""
CASE
    WHEN d.dbid NOT IN (0, {_CURRENT_DATABASE}) THEN 'other'
    WHEN d.classid = 'pg_catalog.pg_database'::regclass THEN
        CASE WHEN d.objid = {_CURRENT_DATABASE} THEN 'target database' ELSE 'database' END
    WHEN d.classid = 'pg_catalog.pg_tablespace'::regclass THEN 'tablespace'
    WHEN d.dbid = 0 THEN 'other'
    WHEN d.classid = 'pg_catalog.pg_class'::regclass AND d.objsubid = 0 THEN (
        SELECT CASE WHEN n.nspname = 'public' AND c.relkind = 'r' THEN 'table'
            WHEN n.nspname = 'public' AND c.relkind = 'S' THEN 'sequence' ELSE 'other' END
        FROM pg_catalog.pg_class AS c
        JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace WHERE c.oid = d.objid)
    WHEN d.classid = 'pg_catalog.pg_proc'::regclass THEN (
        SELECT CASE WHEN n.nspname = 'public'
            AND p.prorettype = 'pg_catalog.trigger'::pg_catalog.regtype
            THEN 'trigger function' ELSE 'other' END
        FROM pg_catalog.pg_proc AS p
        JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace WHERE p.oid = d.objid)
    WHEN d.classid = 'pg_catalog.pg_namespace'::regclass THEN (
        SELECT CASE WHEN nspname = 'public' THEN 'schema public' ELSE 'other' END
        FROM pg_catalog.pg_namespace WHERE oid = d.objid)
    WHEN d.classid = 'pg_catalog.pg_default_acl'::regclass THEN (
        SELECT CASE WHEN a.defaclobjtype = 'f' AND a.defaclnamespace = 0
            AND a.defaclrole = d.refobjid
            AND a.defaclacl
                = ARRAY[pg_catalog.makeaclitem(d.refobjid, d.refobjid, 'EXECUTE', false)]
            THEN 'owner function defaults' ELSE 'other' END
        FROM pg_catalog.pg_default_acl AS a WHERE a.oid = d.objid)
    ELSE 'other'
END
"""  # noqa: S608 - 固定的 SQL 片段
_DEPENDENCIES = f"""
SELECT CASE WHEN r.rolname = :app THEN 'app' ELSE 'owner' END AS role, d.deptype::text AS deptype,
    {_KIND} AS kind,
    CASE WHEN d.dbid IN (0, {_CURRENT_DATABASE})
        THEN pg_catalog.pg_describe_object(d.classid, d.objid, d.objsubid)
        ELSE d.classid::regclass::text END AS identity,
    CASE WHEN d.dbid NOT IN (0, {_CURRENT_DATABASE}) THEN db.datname END AS other_database,
    d.dbid, d.classid, d.objid, d.objsubid
FROM pg_catalog.pg_shdepend AS d
JOIN pg_catalog.pg_roles AS r ON r.oid = d.refobjid
LEFT JOIN pg_catalog.pg_database AS db ON db.oid = d.dbid
WHERE d.refclassid = 'pg_catalog.pg_authid'::regclass AND r.rolname IN (:app, :owner)
ORDER BY 1, 2, 3, 4
"""  # noqa: S608 - 固定的 SQL 片段
# 每個有擁有者欄位的 catalog（目前的資料庫）；暫存的 schema 由系統建立，略過。
_OWNED = (
    ("pg_class", "relowner", ""),
    ("pg_proc", "proowner", ""),
    ("pg_type", "typowner", ""),
    (
        "pg_namespace",
        "nspowner",
        "AND nspname NOT LIKE 'pg\\_temp\\_%' AND nspname NOT LIKE 'pg\\_toast\\_temp\\_%'",
    ),
    ("pg_collation", "collowner", ""),
    ("pg_conversion", "conowner", ""),
    ("pg_operator", "oprowner", ""),
    ("pg_opclass", "opcowner", ""),
    ("pg_opfamily", "opfowner", ""),
    ("pg_ts_config", "cfgowner", ""),
    ("pg_ts_dict", "dictowner", ""),
    ("pg_extension", "extowner", ""),
    ("pg_foreign_data_wrapper", "fdwowner", ""),
    ("pg_foreign_server", "srvowner", ""),
    ("pg_event_trigger", "evtowner", ""),
    ("pg_publication", "pubowner", ""),
    ("pg_statistic_ext", "stxowner", ""),
    ("pg_language", "lanowner", ""),
    ("pg_default_acl", "defaclrole", ""),
)
_OWNED_UNION = " UNION ALL ".join(
    f"SELECT 'pg_catalog.{catalog}'::regclass AS classid, oid AS objid, {column} AS owner "  # noqa: S608
    f"FROM pg_catalog.{catalog} WHERE oid >= {FIRST_USER_OID} {extra}"
    for catalog, column, extra in _OWNED
)
_THIRD_PARTY = (
    "SELECT pg_catalog.pg_describe_object(o.classid, o.objid, 0) || '（擁有者 ' "  # noqa: S608
    f"|| pg_catalog.pg_get_userbyid(o.owner) || '）' FROM ({_OWNED_UNION} "
    "UNION ALL SELECT 'pg_catalog.pg_largeobject'::regclass, oid, lomowner "
    f"FROM pg_catalog.pg_largeobject_metadata WHERE oid >= {FIRST_USER_OID}"
    ") AS o WHERE o.owner NOT IN (SELECT oid FROM pg_catalog.pg_roles "
    "WHERE rolname IN (:app, :owner)) ORDER BY 1"
)
# 移轉前後比較的擁有權依賴（所有資料庫）。
_OWNERSHIP = (
    "SELECT d.dbid, d.classid, d.objid, d.objsubid, r.rolname FROM pg_catalog.pg_shdepend AS d "
    "JOIN pg_catalog.pg_roles AS r ON r.oid = d.refobjid "
    "WHERE d.deptype = 'o' AND d.refclassid = 'pg_catalog.pg_authid'::regclass ORDER BY 1, 2, 3, 4"
)

type ObjectKey = tuple[int, int, int, int]


@dataclass(frozen=True, slots=True)
class Ownership:
    """所有資料庫的擁有權依賴：應用程式角色的、owner 的，以及其他角色的（含角色名稱）。"""

    app: frozenset[ObjectKey]
    owner: frozenset[ObjectKey]
    others: tuple[tuple[int, int, int, int, str], ...]


def snapshot(connection: Connection, *, app: str, owner: str, owner_password: str) -> Snapshot:
    roles = {"app": app, "owner": owner}
    app_facts = _role(connection, app, password=None)
    owner_facts = _role(connection, owner, password=owner_password)
    oids = [oid for oid in (app_facts[1], owner_facts[1]) if oid is not None]
    return Snapshot(
        app=app_facts[0],
        owner=owner_facts[0],
        dependencies=tuple(
            Dependency(
                role=row.role,
                deptype=row.deptype,
                kind=Kind(row.kind),
                identity=row.identity,
                other_database=row.other_database,
                key=(int(row.dbid), int(row.classid), int(row.objid), int(row.objsubid)),
            )
            for row in connection.execute(text(_DEPENDENCIES), roles)
        ),
        third_party_objects=third_party_objects(connection, app=app, owner=owner),
        settings=(
            *role_settings(connection, oids),
            *(parameter_grants(connection, app_facts[1]) if app_facts[1] is not None else ()),
        ),
        connections=int(
            connection.execute(
                text(
                    "SELECT count(*) FROM pg_catalog.pg_stat_activity "
                    "WHERE usename IN (:app, :owner) AND pid <> pg_catalog.pg_backend_pid()"
                ),
                roles,
            ).scalar_one()
        ),
    )


def _role(
    connection: Connection, name: str, *, password: str | None
) -> tuple[RoleFacts, int | None]:
    row = connection.execute(text(_ROLE), {"name": name}).one_or_none()
    if row is None:
        return RoleFacts(exists=False), None
    matches = True if password is None else scram_matches(row.verifier, password)
    facts = RoleFacts(
        exists=True,
        login=bool(row.login),
        risky=bool(row.risky),
        memberships=int(row.memberships),
        password_matches=matches,
    )
    return facts, int(row.oid)


def third_party_objects(connection: Connection, *, app: str, owner: str) -> tuple[str, ...]:
    rows = connection.execute(text(_THIRD_PARTY), {"app": app, "owner": owner})
    return tuple(str(identity) for (identity,) in rows)


def ownership(connection: Connection, *, app: str, owner: str) -> Ownership:
    rows = connection.execute(text(_OWNERSHIP)).all()

    def keys(role: str) -> frozenset[ObjectKey]:
        return frozenset(
            (int(db), int(cls), int(obj), int(sub))
            for db, cls, obj, sub, name in rows
            if name == role
        )

    others = tuple(
        (int(db), int(cls), int(obj), int(sub), str(name))
        for db, cls, obj, sub, name in rows
        if name not in (app, owner)
    )
    return Ownership(app=keys(app), owner=keys(owner), others=others)


def ownership_problems(before: Ownership, after: Ownership) -> tuple[str, ...]:
    """REASSIGN OWNED 之後：應用程式角色不擁有任何物件；owner 擁有原本兩者的聯集；其他角色不變。"""
    problems = []
    if after.app:
        problems.append(f"移轉之後應用程式角色仍擁有 {len(after.app)} 個物件")
    if after.owner != before.owner | before.app:
        problems.append("移轉之後 owner 擁有的物件不等於原本 owner 與應用程式角色的聯集")
    if after.others != before.others:
        problems.append("移轉前後其他角色擁有的物件不同")
    return tuple(problems)
