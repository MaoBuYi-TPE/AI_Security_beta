"""findings 與 finding_observations（T19；docs/DECISIONS.md §25.8）。

Revision ID: 0013
Revises: 0012
Create Date: 2026-11-03 12:00:00+00:00

升降級說明：
- upgrade：
  - 建立 findings（target 層級的議題，(target_id, fingerprint) 唯一）。first／last seen 以複合 FK
    引用 scanner_runs（不直接引用 scans，避免和對帳的鎖序形成死鎖）。trigger findings_guard：
    身分、對應與 triage／lifecycle 欄位不可修改（triage 的修改在 T21 另以 migration 開放）；只有
    last_seen 的三個欄位、normalized_severity、severity_conflict、needs_review 可以更新，而且等級、
    衝突與需要確認只會往上、last_seen_at 不會倒退；新的列一律從 unreviewed、open 開始；不能
    DELETE 或 TRUNCATE。
  - 建立 finding_observations（觀察 → finding，每個觀察最多一次），沿用 scan_records_guard 讓它
    append-only。observations 不加欄位（它有 append-only 的 trigger；連結在入庫之後另外計算）。
  - 既有的 observation 不回填（T19 之前的掃描沒有 finding）。
- downgrade：刪除兩張表與 findings_guard，**finding 與連結會消失**，觀察不受影響。只用於開發與測試。
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: str | Sequence[str] | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# 和 findings/models.py 相同的內容（migration 不 import 應用程式的程式）。CHECK 的文字經 text()：
# `:2025` 這種冒號後接數字的寫法會被當成 bind 參數，以 `\:` 跳脫。
_SHA256_HEX = "^[0-9a-f]{64}$"
_KINDS = "'security', 'contract', 'robustness', 'informational'"
_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
_SEVERITIES = ", ".join(f"'{severity}'" for severity in _SEVERITY_ORDER)
_CONFIDENCES = "'false_positive', 'low', 'medium', 'high', 'confirmed', 'unknown'"
_METHODS = "'CONNECT', 'DELETE', 'GET', 'HEAD', 'OPTIONS', 'PATCH', 'POST', 'PUT', 'TRACE'"
_ROLE_PATTERN = "^[a-z][a-z0-9_]{0,63}$"
_FINDING_CHECKS = {
    "fingerprint_valid": f"fingerprint ~ '{_SHA256_HEX}'",
    "kind_valid": f"kind IN ({_KINDS})",
    "rule_group_not_blank": "char_length(btrim(rule_group)) > 0",
    "title_not_blank": "char_length(btrim(title)) > 0",
    "method_valid": f"method IN ({_METHODS})",
    "route_valid": "left(route, 1) = '/' AND route_source IN ('openapi', 'literal')",
    "parameter_valid": (
        "(parameter_location IS NULL) = (parameter_name IS NULL) "
        "AND (parameter_location IS NULL OR parameter_location IN ('query', 'unknown'))"
    ),
    "resource_valid": "resource IS NULL OR left(resource, 1) = '/'",
    "auth_role_valid": f"auth_role ~ '{_ROLE_PATTERN}'",
    "severity_valid": f"normalized_severity IN ({_SEVERITIES})",
    "cwe_valid": (
        "(cwe_id IS NULL) = (cwe_source IS NULL) AND (cwe_id IS NULL OR cwe_id > 0) "
        "AND (cwe_source IS NULL OR cwe_source IN ('rule_group', 'tool'))"
    ),
    "owasp_top10_2025_valid": (
        "CASE WHEN owasp_top10_2025 IS NULL THEN owasp_top10_2025_source = 'none' "
        r"ELSE owasp_top10_2025 ~ '^A(0[1-9]|10)\:2025$' "
        "AND owasp_top10_2025_source = 'official' END"
    ),
    "owasp_api_2023_valid": (
        "CASE WHEN owasp_api_2023 IS NULL THEN owasp_api_2023_source = 'none' "
        r"ELSE owasp_api_2023 ~ '^API([1-9]|10)\:2023$' "
        "AND owasp_api_2023_source = 'curated' END"
    ),
    "mapping_version_not_blank": "char_length(btrim(mapping_version)) > 0",
    "taxonomy_sha256_valid": f"taxonomy_sha256 ~ '{_SHA256_HEX}'",
    "triage_state_valid": (
        "triage_state IN ('unreviewed', 'confirmed', 'false_positive', 'accepted_risk')"
    ),
    "lifecycle_state_valid": "lifecycle_state IN ('open', 'resolved', 'reopened')",
    "times": "last_seen_at >= created_at",
}
# 可以更新的欄位；其餘（身分、對應、triage 與 lifecycle）都不可修改。
_MUTABLE = (
    "last_seen_run_id",
    "last_seen_scan_id",
    "last_seen_at",
    "normalized_severity",
    "severity_conflict",
    "needs_review",
)
_SEVERITY_ARRAY = "ARRAY[" + _SEVERITIES + "]"
_CREATE_FINDINGS_GUARD = f"""
CREATE FUNCTION findings_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.triage_state <> 'unreviewed' OR NEW.lifecycle_state <> 'open' THEN
            RAISE EXCEPTION USING
                ERRCODE = 'integrity_constraint_violation',
                MESSAGE = 'findings: new rows start unreviewed and open';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP <> 'UPDATE' THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'findings rows cannot be removed (' || TG_OP || ' blocked)';
    END IF;
    IF (to_jsonb(NEW) - ARRAY[{", ".join(f"'{column}'" for column in _MUTABLE)}])
        IS DISTINCT FROM (to_jsonb(OLD) - ARRAY[{", ".join(f"'{column}'" for column in _MUTABLE)}])
    THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'findings: only the last seen run and the aggregates can change';
    END IF;
    IF array_position({_SEVERITY_ARRAY}, NEW.normalized_severity)
            < array_position({_SEVERITY_ARRAY}, OLD.normalized_severity)
        OR NEW.severity_conflict < OLD.severity_conflict
        OR NEW.needs_review < OLD.needs_review
        OR NEW.last_seen_at < OLD.last_seen_at
    THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'findings: aggregates only move upwards';
    END IF;
    RETURN NEW;
END;
$$
"""
# (trigger 名稱, 資料表, 時機, 層級, 函式)
_TRIGGERS = (
    (
        "findings_guard_rows",
        "findings",
        "BEFORE INSERT OR UPDATE OR DELETE",
        "ROW",
        "findings_guard",
    ),
    ("findings_no_truncate", "findings", "BEFORE TRUNCATE", "STATEMENT", "findings_guard"),
    (
        "finding_observations_immutable",
        "finding_observations",
        "BEFORE UPDATE OR DELETE",
        "ROW",
        "scan_records_guard",
    ),
    (
        "finding_observations_no_truncate",
        "finding_observations",
        "BEFORE TRUNCATE",
        "STATEMENT",
        "scan_records_guard",
    ),
)


def _now(name: str) -> sa.Column[Any]:
    return sa.Column(
        name, sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
    )


def _run_key(prefix: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        [f"{prefix}_run_id", f"{prefix}_scan_id"],
        ["scanner_runs.id", "scanner_runs.scan_id"],
        name=f"fk_findings_{prefix}_run",
        ondelete="RESTRICT",
    )


def upgrade() -> None:
    _create_findings()
    _create_finding_observations()
    op.execute(_CREATE_FINDINGS_GUARD)
    for name, table, timing, level, function in _TRIGGERS:
        op.execute(
            f"CREATE TRIGGER {name} {timing} ON {table} "
            f"FOR EACH {level} EXECUTE FUNCTION {function}()"
        )


def _create_findings() -> None:
    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("rule_group", sa.String(160), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("method", sa.String(7), nullable=False),
        sa.Column("route", sa.String(2048), nullable=False),
        sa.Column("route_source", sa.String(32), nullable=False),
        sa.Column("parameter_location", sa.String(32), nullable=True),
        sa.Column("parameter_name", sa.String(512), nullable=True),
        sa.Column("resource", sa.String(2048), nullable=True),
        sa.Column("auth_role", sa.String(64), nullable=False),
        sa.Column("auth_verified", sa.Boolean(), nullable=False),
        sa.Column("normalized_severity", sa.String(32), nullable=False),
        sa.Column("severity_conflict", sa.Boolean(), nullable=False),
        sa.Column("needs_review", sa.Boolean(), nullable=False),
        sa.Column("cwe_id", sa.Integer(), nullable=True),
        sa.Column("cwe_source", sa.String(32), nullable=True),
        sa.Column("owasp_top10_2025", sa.String(16), nullable=True),
        sa.Column("owasp_top10_2025_source", sa.String(32), nullable=False),
        sa.Column("owasp_api_2023", sa.String(16), nullable=True),
        sa.Column("owasp_api_2023_source", sa.String(32), nullable=False),
        sa.Column("mapping_version", sa.String(64), nullable=False),
        sa.Column("taxonomy_sha256", sa.String(64), nullable=False),
        sa.Column(
            "triage_state", sa.String(32), server_default=sa.text("'unreviewed'"), nullable=False
        ),
        sa.Column(
            "lifecycle_state", sa.String(32), server_default=sa.text("'open'"), nullable=False
        ),
        sa.Column("first_seen_run_id", sa.Uuid(), nullable=False),
        sa.Column("first_seen_scan_id", sa.Uuid(), nullable=False),
        sa.Column("last_seen_run_id", sa.Uuid(), nullable=False),
        sa.Column("last_seen_scan_id", sa.Uuid(), nullable=False),
        _now("last_seen_at"),
        _now("created_at"),
        *(
            sa.CheckConstraint(condition, name=op.f(f"ck_findings_{name}"))
            for name, condition in _FINDING_CHECKS.items()
        ),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["targets.id"],
            name=op.f("fk_findings_target_id_targets"),
            ondelete="RESTRICT",
        ),
        _run_key("first_seen"),
        _run_key("last_seen"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_findings")),
        sa.UniqueConstraint(
            "target_id", "fingerprint", name=op.f("uq_findings_target_id_fingerprint")
        ),
    )


def _create_finding_observations() -> None:
    op.create_table(
        "finding_observations",
        sa.Column("observation_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("normalized_severity", sa.String(32), nullable=False),
        sa.Column("normalized_confidence", sa.String(32), nullable=False),
        sa.Column("needs_review", sa.Boolean(), nullable=False),
        sa.Column("taxonomy_sha256", sa.String(64), nullable=False),
        _now("created_at"),
        sa.CheckConstraint(
            f"normalized_severity IN ({_SEVERITIES})",
            name=op.f("ck_finding_observations_severity_valid"),
        ),
        sa.CheckConstraint(
            f"normalized_confidence IN ({_CONFIDENCES})",
            name=op.f("ck_finding_observations_confidence_valid"),
        ),
        sa.CheckConstraint(
            f"taxonomy_sha256 ~ '{_SHA256_HEX}'",
            name=op.f("ck_finding_observations_taxonomy_sha256_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["observation_id"],
            ["observations.id"],
            name=op.f("fk_finding_observations_observation_id_observations"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name=op.f("fk_finding_observations_finding_id_findings"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("observation_id", name=op.f("pk_finding_observations")),
    )
    op.create_index(
        "ix_finding_observations_finding_id", "finding_observations", ["finding_id"], unique=False
    )


def downgrade() -> None:
    op.drop_table("finding_observations")
    op.drop_table("findings")
    op.execute("DROP FUNCTION findings_guard()")
