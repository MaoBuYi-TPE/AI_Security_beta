"""掃描目標與範圍授權：targets、scope_grants（T06）。

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-19 09:00:00+00:00

升降級說明：
- upgrade：建立 targets 與 scope_grants 及其 FK／unique／check。scope_grants 另加 trigger：
  UPDATE 只允許 pending→approved、pending→revoked、approved→revoked，而且只能改狀態與
  核准、撤銷欄位；DELETE 與 TRUNCATE 一律拒絕（docs/DECISIONS.md §10.4）。
- downgrade：刪除這兩個資料表與 trigger 函式，**所有 target 與授權紀錄都會消失**。
  只用於開發與測試，正式環境不要 downgrade。
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: str | Sequence[str] | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# 建立後不可變的欄位：範圍、預算、期限與申請紀錄。
_IMMUTABLE_COLUMNS = (
    "id",
    "target_id",
    "version",
    "allowed_origins",
    "allowed_ips",
    "allowed_paths",
    "allow_all_paths",
    "excluded_paths",
    "allowed_methods",
    "requests_per_second",
    "max_requests",
    "max_duration_seconds",
    "authorization_reference",
    "valid_from",
    "valid_until",
    "requested_by_key_id",
    "created_at",
)
_APPROVAL_COLUMNS = ("approved_by_key_id", "approved_at", "approval_note")
_REVOCATION_COLUMNS = ("revoked_by_key_id", "revoked_at", "revocation_reason")


def _row(prefix: str, columns: Sequence[str]) -> str:
    return "(" + ", ".join(f"{prefix}.{column}" for column in columns) + ")"


def _changed(columns: Sequence[str]) -> str:
    return f"{_row('NEW', columns)} IS DISTINCT FROM {_row('OLD', columns)}"


# 不用 RAISE 的 % 格式字串：SQLAlchemy 會把文字 SQL 裡的 % 跳脫，改用字串串接。
# 固定 search_path，函式不受呼叫端 search_path 影響（避免被同名物件劫持）。
_CREATE_GUARD_FUNCTION = f"""
CREATE FUNCTION scope_grants_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP <> 'UPDATE' THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'scope_grants rows are kept for audit (' || TG_OP || ' blocked)';
    END IF;
    IF NOT ((OLD.status = 'pending' AND NEW.status IN ('approved', 'revoked'))
            OR (OLD.status = 'approved' AND NEW.status = 'revoked')) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'scope_grants status change not allowed ('
                || OLD.status || ' -> ' || NEW.status || ')';
    END IF;
    IF {_changed(_IMMUTABLE_COLUMNS)} THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'scope_grants scope is immutable; request a new version instead';
    END IF;
    IF NEW.status <> 'approved' AND {_changed(_APPROVAL_COLUMNS)} THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'scope_grants approval can only be recorded when approving';
    END IF;
    IF NEW.status <> 'revoked' AND {_changed(_REVOCATION_COLUMNS)} THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'scope_grants revocation can only be recorded when revoking';
    END IF;
    RETURN NEW;
END;
$$
"""
_CREATE_ROW_TRIGGER = """
CREATE TRIGGER scope_grants_guard_rows
BEFORE UPDATE OR DELETE ON scope_grants
FOR EACH ROW EXECUTE FUNCTION scope_grants_guard()
"""
_CREATE_TRUNCATE_TRIGGER = """
CREATE TRIGGER scope_grants_no_truncate
BEFORE TRUNCATE ON scope_grants
FOR EACH STATEMENT EXECUTE FUNCTION scope_grants_guard()
"""


def upgrade() -> None:
    op.create_table(
        "targets",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("canonical_origin", sa.String(length=256), nullable=False),
        sa.Column("environment", sa.String(length=16), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("char_length(btrim(name)) > 0", name=op.f("ck_targets_name_not_blank")),
        sa.CheckConstraint("kind IN ('web', 'api', 'hybrid')", name=op.f("ck_targets_kind_valid")),
        sa.CheckConstraint("environment IN ('lab')", name=op.f("ck_targets_environment_valid")),
        sa.CheckConstraint(
            "canonical_origin ~ '^http://[a-z0-9.-]+(:[1-9][0-9]{0,4})?$'",
            name=op.f("ck_targets_origin_canonical"),
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_targets_project_id_projects"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_targets")),
        sa.UniqueConstraint(
            "project_id", "canonical_origin", name=op.f("uq_targets_project_id_canonical_origin")
        ),
    )
    op.create_table(
        "scope_grants",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("allowed_origins", postgresql.ARRAY(sa.String(length=256)), nullable=False),
        sa.Column("allowed_ips", postgresql.ARRAY(postgresql.INET()), nullable=False),
        sa.Column("allowed_paths", postgresql.ARRAY(sa.String(length=512)), nullable=False),
        sa.Column("allow_all_paths", sa.Boolean(), nullable=False),
        sa.Column("excluded_paths", postgresql.ARRAY(sa.String(length=512)), nullable=False),
        sa.Column("allowed_methods", postgresql.ARRAY(sa.String(length=7)), nullable=False),
        sa.Column("requests_per_second", sa.Integer(), nullable=False),
        sa.Column("max_requests", sa.Integer(), nullable=False),
        sa.Column("max_duration_seconds", sa.Integer(), nullable=False),
        sa.Column("authorization_reference", sa.String(length=200), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("requested_by_key_id", sa.Uuid(), nullable=False),
        sa.Column("approved_by_key_id", sa.Uuid(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approval_note", sa.String(length=500), nullable=True),
        sa.Column("revoked_by_key_id", sa.Uuid(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(length=500), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("version > 0", name=op.f("ck_scope_grants_version_positive")),
        sa.CheckConstraint(
            "status IN ('pending', 'approved', 'revoked')",
            name=op.f("ck_scope_grants_status_valid"),
        ),
        sa.CheckConstraint(
            "cardinality(allowed_origins) BETWEEN 1 AND 4",
            name=op.f("ck_scope_grants_origins_count"),
        ),
        sa.CheckConstraint(
            "cardinality(allowed_ips) BETWEEN 1 AND 16", name=op.f("ck_scope_grants_ips_count")
        ),
        sa.CheckConstraint(
            "cardinality(allowed_methods) >= 1 AND allowed_methods <@ "
            "ARRAY['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE']::varchar[]",
            name=op.f("ck_scope_grants_methods_valid"),
        ),
        sa.CheckConstraint(
            "cardinality(excluded_paths) <= 64 AND CASE WHEN allow_all_paths "
            "THEN cardinality(allowed_paths) = 0 "
            "ELSE cardinality(allowed_paths) BETWEEN 1 AND 256 END",
            name=op.f("ck_scope_grants_paths_valid"),
        ),
        sa.CheckConstraint(
            "requests_per_second > 0 AND max_requests > 0 AND max_duration_seconds > 0",
            name=op.f("ck_scope_grants_budget_positive"),
        ),
        sa.CheckConstraint("valid_from < valid_until", name=op.f("ck_scope_grants_window_order")),
        sa.CheckConstraint(
            "char_length(btrim(authorization_reference)) > 0",
            name=op.f("ck_scope_grants_reference_not_blank"),
        ),
        sa.CheckConstraint(
            "(approved_at IS NULL) = (approved_by_key_id IS NULL) "
            "AND (approved_at IS NULL) = (approval_note IS NULL) "
            "AND (revoked_at IS NULL) = (revoked_by_key_id IS NULL) "
            "AND (revoked_at IS NULL) = (revocation_reason IS NULL) "
            "AND (approval_note IS NULL OR char_length(btrim(approval_note)) > 0) "
            "AND (revocation_reason IS NULL OR char_length(btrim(revocation_reason)) > 0)",
            name=op.f("ck_scope_grants_decisions_complete"),
        ),
        sa.CheckConstraint(
            "CASE status "
            "WHEN 'pending' THEN approved_at IS NULL AND revoked_at IS NULL "
            "WHEN 'approved' THEN approved_at IS NOT NULL AND revoked_at IS NULL "
            "ELSE revoked_at IS NOT NULL END",
            name=op.f("ck_scope_grants_status_matches_decisions"),
        ),
        sa.CheckConstraint(
            "(approved_at IS NULL OR (approved_at >= created_at AND approved_at < valid_until)) "
            "AND (revoked_at IS NULL OR revoked_at >= created_at) "
            "AND (revoked_at IS NULL OR approved_at IS NULL OR revoked_at >= approved_at)",
            name=op.f("ck_scope_grants_decision_times"),
        ),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["targets.id"],
            name=op.f("fk_scope_grants_target_id_targets"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_key_id"],
            ["api_keys.id"],
            name=op.f("fk_scope_grants_requested_by_key_id_api_keys"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["approved_by_key_id"],
            ["api_keys.id"],
            name=op.f("fk_scope_grants_approved_by_key_id_api_keys"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["revoked_by_key_id"],
            ["api_keys.id"],
            name=op.f("fk_scope_grants_revoked_by_key_id_api_keys"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scope_grants")),
        sa.UniqueConstraint("target_id", "version", name=op.f("uq_scope_grants_target_id_version")),
    )
    op.execute(_CREATE_GUARD_FUNCTION)
    op.execute(_CREATE_ROW_TRIGGER)
    op.execute(_CREATE_TRUNCATE_TRIGGER)


def downgrade() -> None:
    # 刪除資料表會一併刪除它的 trigger；函式要另外刪。
    op.drop_table("scope_grants")
    op.execute("DROP FUNCTION scope_grants_guard()")
    op.drop_table("targets")
