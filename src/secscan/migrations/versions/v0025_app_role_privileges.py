"""應用程式角色的逐表權限（T23b-b1；docs/DECISIONS.md §31）。

Revision ID: 0025
Revises: 0024
Create Date: 2026-11-12 12:00:00+00:00

schema 由 owner 角色擁有（migration 以它執行，env.py 每次先檢查角色）；api、worker、runner 共用的
應用程式角色只有這裡授予的 DML。擁有者的修改、刪除權限撤銷不了，所以應用程式角色不再擁有任何物件
（既有的資料庫先以 make db-roles-migrate 移轉擁有權）。

升降級說明：
- 以 owner 執行；應用程式角色的名稱由 config.attributes["app_role"] 傳入（env.py 取自 DB_USER），
  offline（--sql）以 `-x app_role=…` 指定，預設 secscan_app。名稱只接受小寫英數與底線。
- upgrade：
  1. 檢查（DO 區塊，offline 產生的 SQL 也包含）：public 中每張表都已分類，有未分類的表就停止；
     應用程式角色存在、不是 superuser、不是目前的角色，也不是它的成員。
  2. 先撤銷應用程式角色在 public 的全部權限（表、sequence、函式、schema）與資料庫的權限，再依矩陣
     授權：結果和先前的狀態無關。
     - 只能新增（trigger 拒絕 UPDATE、DELETE）：SELECT、INSERT；run_rule_locations 只有 INSERT；
     - 有狀態轉換：SELECT、INSERT、UPDATE（執行期的修改與列鎖；FOR UPDATE／SHARE 需要 UPDATE）；
     - report_contents、runner_instances：另加 DELETE；
     - projects：SELECT、INSERT（報告建立改用 advisory lock，不再鎖 projects 的列）；
     - alembic_version：SELECT（readiness 與啟動時的版本檢查）。
     一律不授予 TRUNCATE、REFERENCES、TRIGGER、MAINTAIN、GRANT OPTION 與欄位層級的權限；sequence
     沒有權限（identity 取號不檢查）；資料庫只有 CONNECT，schema 只有 USAGE。
  3. 函式：既有的函式撤銷 PUBLIC 的 EXECUTE（trigger 觸發時不檢查）；owner 之後建立的函式，以
     **全域**的 ALTER DEFAULT PRIVILEGES FOR ROLE <owner> REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC
     處理。
     per-schema（IN SCHEMA）的寫法撤銷不了全域或內建的預設（PostgreSQL 18 文件），不使用。
  - 不修改任何 trigger 與約束。
  - 矩陣直接寫在這裡（當時的快照，不 import 應用程式）；tests/db_privileges.py 另有一份預期值。
  - 之後新增的資料表沒有任何預設授權：新的 migration 依這裡的寫法明確授權，並更新預期值。
- downgrade：撤銷上面的授權（資料庫的 CONNECT 保留：initdb 建立資料庫時就授予，升級之前它是唯一的
  權限），既有函式的 EXECUTE 還給 PUBLIC，owner 的 default privileges 還原成內建預設
  （pg_default_acl 的那一列消失）。擁有權不還原：0024 的程式以應用程式角色擁有 schema 為
  前提，回復步驟見 DECISIONS §31.8（superuser 執行 REASSIGN OWNED）。只用於開發與測試。
"""

import re
from collections.abc import Sequence

from alembic import context, op

revision: str = "0025"
down_revision: str | Sequence[str] | None = "0024"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# 和 secscan.migrations.APP_ROLE_ATTRIBUTE 相同（env.py 由設定放入；測試直接傳入）。
APP_ROLE_ATTRIBUTE = "app_role"
OFFLINE_APP_ROLE = "secscan_app"
_ROLE_NAME = re.compile(r"[a-z_][a-z0-9_]{0,62}")

# 只能新增：trigger 一律拒絕 UPDATE 與 DELETE；由 API、worker 或 trigger 讀取。
_INSERT_ONLY = (
    "api_spec_operations",
    "api_specs",
    "artifacts",
    "audit_events",
    "finding_observations",
    "finding_triage_events",
    "observations",
    "run_coverage",
    "run_locations",
    "scan_comparison_findings",
    "scan_events",
    "scan_operations",
)
# 有狀態轉換（撤銷、停用、換版、佇列、lease、清除標記…；轉換的規則由 trigger 決定）。
_STATEFUL = (
    "api_keys",
    "auth_profile_versions",
    "auth_profiles",
    "evidence_holds",
    "finding_triage_excerpts",
    "findings",
    "reports",
    "run_evidence",
    "scan_comparisons",
    "scanner_runs",
    "scans",
    "scope_grants",
    "targets",
)
_GRANTS = (
    ("SELECT, INSERT", (*_INSERT_ONLY, "projects")),
    # 只新增、程式與 trigger 都不讀取。
    ("INSERT", ("run_rule_locations",)),
    ("SELECT, INSERT, UPDATE", _STATEFUL),
    # 報告內容換版與到期刪除；runner 心跳的 upsert 與刪除過期的實例。
    ("SELECT, INSERT, UPDATE, DELETE", ("report_contents", "runner_instances")),
    ("SELECT", ("alembic_version",)),
)
_CLASSIFIED = tuple(sorted(table for _, tables in _GRANTS for table in tables))


def upgrade() -> None:
    role = _app_role()
    op.execute(_preflight(role))
    _revoke_all(role)
    for privileges, tables in _GRANTS:
        names = ", ".join(f"public.{table}" for table in tables)
        op.execute(f'GRANT {privileges} ON TABLE {names} TO "{role}"')
    op.execute(f'GRANT USAGE ON SCHEMA public TO "{role}"')
    op.execute(_on_current_database(f'GRANT CONNECT ON DATABASE {{}} TO "{role}"'))
    op.execute("REVOKE EXECUTE ON ALL ROUTINES IN SCHEMA public FROM PUBLIC")
    op.execute(_owner_function_defaults("REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC"))


def downgrade() -> None:
    role = _app_role()
    _revoke_all(role, keep_connect=True)
    op.execute("GRANT EXECUTE ON ALL ROUTINES IN SCHEMA public TO PUBLIC")
    op.execute(_owner_function_defaults("GRANT EXECUTE ON FUNCTIONS TO PUBLIC"))


def _app_role() -> str:
    role = context.config.attributes.get(APP_ROLE_ATTRIBUTE)
    if role is None and context.is_offline_mode():
        role = context.get_x_argument(as_dictionary=True).get(APP_ROLE_ATTRIBUTE, OFFLINE_APP_ROLE)
    valid = isinstance(role, str) and _ROLE_NAME.fullmatch(role) is not None
    if not valid or not isinstance(role, str) or role.startswith("pg_"):
        raise RuntimeError(
            "v0025 需要應用程式角色的名稱（DB_USER；只接受小寫英數與底線，不可以 pg_ 開頭）："
            "make migrate 由 DB_USER 取得，offline 以 -x app_role=… 指定（升級沒有進行）"
        )
    return role


def _revoke_all(role: str, *, keep_connect: bool = False) -> None:
    # ROUTINES 含 procedure（FUNCTIONS 不含）。
    for kind in ("TABLES", "SEQUENCES", "ROUTINES"):
        op.execute(f'REVOKE ALL ON ALL {kind} IN SCHEMA public FROM "{role}"')
    op.execute(f'REVOKE ALL ON SCHEMA public FROM "{role}"')
    privileges = "CREATE, TEMPORARY" if keep_connect else "ALL"
    op.execute(_on_current_database(f'REVOKE {privileges} ON DATABASE {{}} FROM "{role}"'))


def _on_current_database(statement: str) -> str:
    """資料庫的名稱只在執行時知道（offline 的 SQL 也一樣）：以 DO 與 quote_ident 組出語句。

    不用 format() 的 % 格式字串：SQLAlchemy 會跳脫文字 SQL 裡的 %（同 0001）。
    """
    before, after = statement.split("{}")
    return f"DO $$ BEGIN EXECUTE '{before}' || quote_ident(current_database()) || '{after}'; END $$"


def _owner_function_defaults(action: str) -> str:
    """owner（目前的角色；env.py 已確認它不是應用程式角色、也不是 superuser）的全域 default ACL。"""
    return (
        "DO $$ BEGIN EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE ' || quote_ident(current_user) "
        f"|| ' {action}'; END $$"
    )


def _preflight(role: str) -> str:
    """表名是這裡的常數，角色名稱已由 _ROLE_NAME 驗證（不含引號）。"""
    known = ", ".join(f"'{table}'" for table in _CLASSIFIED)
    return f"""
DO $$
DECLARE
    unknown text;
BEGIN
    SELECT string_agg(c.relname, ', ' ORDER BY c.relname) INTO unknown
    FROM pg_catalog.pg_class AS c JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
        AND c.relname <> ALL (ARRAY[{known}]);
    IF unknown IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'invalid_grant_operation',
            MESSAGE = 'v0025: unclassified relations in public: ' || unknown;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '{role}') THEN
        RAISE EXCEPTION USING
            ERRCODE = 'invalid_grant_operation',
            MESSAGE = 'v0025: the application role does not exist';
    END IF;
    IF '{role}' = current_user THEN
        RAISE EXCEPTION USING
            ERRCODE = 'invalid_grant_operation',
            MESSAGE = 'v0025: run migrations as the owner, not as the application role';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '{role}' AND rolsuper)
        OR pg_catalog.pg_has_role('{role}', current_user, 'MEMBER') THEN
        RAISE EXCEPTION USING
            ERRCODE = 'invalid_grant_operation',
            MESSAGE = 'v0025: the application role is a superuser or a member of the owner';
    END IF;
END $$
"""  # noqa: S608
