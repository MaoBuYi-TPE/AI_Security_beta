"""停用 auth profile、全域稽核查詢的索引（T21；docs/DECISIONS.md §28.7）。

Revision ID: 0019
Revises: 0018
Create Date: 2026-11-08 21:00:00+00:00

升降級說明：
- upgrade：
  - auth_profiles 新增 `disabled_at` 與 `disabled_by_key_id`（兩者同時有值或同時是 NULL）。
  - auth_profiles_guard 改版：原本拒絕所有 UPDATE；現在只允許「從未停用 → 停用」一次（其他欄位
    不變），停用是終止狀態。DELETE 與 TRUNCATE 仍然拒絕。停用時清除目前版本的密文（既有的
    auth_profile_versions_guard 已允許清除）。
  - audit_events 新增 (created_at, id) 索引：全域稽核查詢由新到舊分頁。
- downgrade：刪除索引與兩個欄位，恢復 v0004 的 auth_profiles_guard；停用紀錄會消失（被清除的密文
  不會回來）。只用於開發與測試。
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0019"
down_revision: str | Sequence[str] | None = "0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_V4_GUARD = """
CREATE OR REPLACE FUNCTION auth_profiles_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = 'integrity_constraint_violation',
        MESSAGE = TG_TABLE_NAME || ' rows are immutable (' || TG_OP || ' blocked)';
END;
$$
"""
_GUARD = """
CREATE OR REPLACE FUNCTION auth_profiles_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    -- 巢狀的 IF：PL/pgSQL 的 AND 不保證短路，statement 層級的 TRUNCATE 沒有 OLD／NEW 的欄位。
    IF TG_OP = 'UPDATE' THEN
        IF OLD.disabled_at IS NULL
            AND NEW.disabled_at IS NOT NULL
            AND (to_jsonb(NEW) - ARRAY['disabled_at', 'disabled_by_key_id'])
                = (to_jsonb(OLD) - ARRAY['disabled_at', 'disabled_by_key_id'])
        THEN
            RETURN NEW;
        END IF;
    END IF;
    RAISE EXCEPTION USING
        ERRCODE = 'integrity_constraint_violation',
        MESSAGE = TG_TABLE_NAME || ' rows are immutable except disabling once (' || TG_OP
            || ' blocked)';
END;
$$
"""


def upgrade() -> None:
    op.add_column("auth_profiles", sa.Column("disabled_at", sa.DateTime(timezone=True)))
    op.add_column("auth_profiles", sa.Column("disabled_by_key_id", sa.Uuid()))
    op.create_foreign_key(
        op.f("fk_auth_profiles_disabled_by_key_id_api_keys"),
        "auth_profiles",
        "api_keys",
        ["disabled_by_key_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_check_constraint(
        op.f("ck_auth_profiles_disabled_valid"),
        "auth_profiles",
        "(disabled_at IS NULL) = (disabled_by_key_id IS NULL) "
        "AND (disabled_at IS NULL OR disabled_at >= created_at)",
    )
    op.execute(_GUARD)
    op.create_index(op.f("ix_audit_events_created_at_id"), "audit_events", ["created_at", "id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_audit_events_created_at_id"), table_name="audit_events")
    op.execute(_V4_GUARD)
    op.drop_constraint(op.f("ck_auth_profiles_disabled_valid"), "auth_profiles", type_="check")
    op.drop_constraint(
        op.f("fk_auth_profiles_disabled_by_key_id_api_keys"), "auth_profiles", type_="foreignkey"
    )
    op.drop_column("auth_profiles", "disabled_by_key_id")
    op.drop_column("auth_profiles", "disabled_at")
