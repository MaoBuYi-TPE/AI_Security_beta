"""應用程式角色的預期權限（T23b-b1；docs/DECISIONS.md §31.2）：整合測試與 Live 共用。

和 migration v0025 分開寫：migration 是當時的快照，這裡是測試的預期值，兩者必須一致
（tests/integration/test_db_privileges.py 以 catalog 比對）。新增資料表時兩邊都要更新，並在
v0025 之後的 migration 中註明每種權限的業務需求（README「新增 schema 變更時」）。
"""

from collections.abc import Mapping
from types import MappingProxyType

# PostgreSQL 18 的資料表權限（has_table_privilege 的名稱）。
TABLE_PRIVILEGES = (
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "TRUNCATE",
    "REFERENCES",
    "TRIGGER",
    "MAINTAIN",
)

_SELECT_INSERT = frozenset({"SELECT", "INSERT"})
_STATEFUL = frozenset({"SELECT", "INSERT", "UPDATE"})
_DELETABLE = frozenset({"SELECT", "INSERT", "UPDATE", "DELETE"})

# A：只能新增（trigger 一律拒絕 UPDATE 與 DELETE），由 API、worker 或 trigger 讀取。
INSERT_ONLY_TABLES = frozenset(
    {
        "audit_events",
        "api_specs",
        "api_spec_operations",
        "artifacts",
        "observations",
        "scan_events",
        "scan_operations",
        "run_coverage",
        "run_locations",
        "finding_observations",
        "finding_triage_events",
        "scan_comparison_findings",
    }
)
# A：只新增、程式與 trigger 都不讀取。
WRITE_ONLY_TABLES = frozenset({"run_rule_locations"})
# B：有狀態轉換（轉換的規則由 trigger 決定），沒有 DELETE。
STATEFUL_TABLES = frozenset(
    {
        "api_keys",
        "auth_profiles",
        "auth_profile_versions",
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
    }
)
# C：需要刪除（報告內容換版與到期刪除、runner 心跳的過期實例）。
DELETABLE_TABLES = frozenset({"report_contents", "runner_instances"})
# D：執行期不修改（報告建立的排隊改用 advisory lock，§31.6）。
APPEND_ONLY_PARENT_TABLES = frozenset({"projects"})
# E：readiness 與啟動時檢查 schema 的版本。
READ_ONLY_TABLES = frozenset({"alembic_version"})


def _matrix() -> Mapping[str, frozenset[str]]:
    expected: dict[str, frozenset[str]] = {}
    for tables, privileges in (
        (INSERT_ONLY_TABLES, _SELECT_INSERT),
        (WRITE_ONLY_TABLES, frozenset({"INSERT"})),
        (STATEFUL_TABLES, _STATEFUL),
        (DELETABLE_TABLES, _DELETABLE),
        (APPEND_ONLY_PARENT_TABLES, _SELECT_INSERT),
        (READ_ONLY_TABLES, frozenset({"SELECT"})),
    ):
        for table in tables:
            assert table not in expected, f"{table} 被分類兩次"
            expected[table] = privileges
    return MappingProxyType(expected)


# 每張資料表 → 應用程式角色的權限（其餘一律沒有，包括 GRANT OPTION 與欄位層級的授權）。
APP_TABLE_PRIVILEGES = _matrix()
# 只有兩個 identity 欄位的 sequence；應用程式角色不需要任何 sequence 權限（identity 取號不檢查）。
EXPECTED_SEQUENCES = frozenset({"scans_queue_position_seq", "reports_queue_position_seq"})
# 允許的 SECURITY DEFINER 函式（目前沒有；新增時寫明理由）。
SECURITY_DEFINER_ALLOWLIST: frozenset[str] = frozenset()
# 不影響權限與 trigger 的角色設定（整合測試的角色刻意把 timezone 設成 Asia/Taipei）。
ALLOWED_ROLE_SETTINGS = frozenset({"timezone"})
