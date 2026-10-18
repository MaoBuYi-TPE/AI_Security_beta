"""身分與稽核：projects、api_keys、audit_events（T04）。

Revision ID: 0001
Revises:
Create Date: 2026-10-18 06:36:16.121481+00:00

升降級說明：
- upgrade：建立三個資料表及其 FK／unique／check／index；audit_events 另加 trigger，
  拒絕 UPDATE、DELETE 與 TRUNCATE（append-only）。
- downgrade：刪除這三個資料表與 trigger 函式，**所有專案、API key 與稽核紀錄都會消失**。
  只用於開發與測試，正式環境不要 downgrade。
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# 不用 RAISE 的 % 格式字串：SQLAlchemy 會把文字 SQL 裡的 % 跳脫，改用字串串接。
# 固定 search_path，函式不受呼叫端 search_path 影響（避免被同名物件劫持）。
_CREATE_REJECT_FUNCTION = """
CREATE FUNCTION audit_events_reject_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = 'integrity_constraint_violation',
        MESSAGE = 'audit_events is append-only (' || TG_OP || ' blocked)';
END;
$$
"""
_CREATE_ROW_TRIGGER = """
CREATE TRIGGER audit_events_append_only
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION audit_events_reject_mutation()
"""
_CREATE_TRUNCATE_TRIGGER = """
CREATE TRIGGER audit_events_no_truncate
BEFORE TRUNCATE ON audit_events
FOR EACH STATEMENT EXECUTE FUNCTION audit_events_reject_mutation()
"""


def upgrade() -> None:
    op.create_table(
        "projects",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("char_length(btrim(name)) > 0", name=op.f("ck_projects_name_not_blank")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_projects")),
        sa.UniqueConstraint("name", name=op.f("uq_projects_name")),
    )
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=True),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("prefix", sa.String(length=32), nullable=False),
        sa.Column("key_hash", sa.LargeBinary(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(role = 'platform_admin') = (project_id IS NULL)",
            name=op.f("ck_api_keys_role_project_scope"),
        ),
        sa.CheckConstraint(
            "role IN ('platform_admin', 'operator', 'viewer')", name=op.f("ck_api_keys_role_valid")
        ),
        sa.CheckConstraint("char_length(btrim(name)) > 0", name=op.f("ck_api_keys_name_not_blank")),
        sa.CheckConstraint(
            "char_length(btrim(prefix)) > 0", name=op.f("ck_api_keys_prefix_not_blank")
        ),
        sa.CheckConstraint(
            "expires_at IS NULL OR expires_at > created_at",
            name=op.f("ck_api_keys_expires_after_created"),
        ),
        sa.CheckConstraint("octet_length(key_hash) = 32", name=op.f("ck_api_keys_key_hash_length")),
        sa.CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= created_at",
            name=op.f("ck_api_keys_revoked_after_created"),
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_api_keys_project_id_projects"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_api_keys")),
        sa.UniqueConstraint("key_hash", name=op.f("uq_api_keys_key_hash")),
        sa.UniqueConstraint("prefix", name=op.f("uq_api_keys_prefix")),
    )
    op.create_index(op.f("ix_api_keys_project_id"), "api_keys", ["project_id"], unique=False)
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("clock_timestamp()"),
            nullable=False,
        ),
        sa.Column("actor_key_id", sa.Uuid(), nullable=True),
        sa.Column("project_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("object_type", sa.String(length=64), nullable=False),
        sa.Column("object_id", sa.Uuid(), nullable=True),
        sa.Column("request_id", sa.String(length=64), nullable=True),
        sa.Column(
            "redacted_changes",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "jsonb_typeof(redacted_changes) = 'object'",
            name=op.f("ck_audit_events_changes_is_object"),
        ),
        sa.CheckConstraint(
            "char_length(btrim(action)) > 0", name=op.f("ck_audit_events_action_not_blank")
        ),
        sa.CheckConstraint(
            "char_length(btrim(object_type)) > 0",
            name=op.f("ck_audit_events_object_type_not_blank"),
        ),
        sa.ForeignKeyConstraint(
            ["actor_key_id"],
            ["api_keys.id"],
            name=op.f("fk_audit_events_actor_key_id_api_keys"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_audit_events_project_id_projects"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_events")),
    )
    op.create_index(
        op.f("ix_audit_events_project_id_created_at"),
        "audit_events",
        ["project_id", "created_at"],
        unique=False,
    )
    op.execute(_CREATE_REJECT_FUNCTION)
    op.execute(_CREATE_ROW_TRIGGER)
    op.execute(_CREATE_TRUNCATE_TRIGGER)


def downgrade() -> None:
    # 刪除資料表會一併刪除它的 trigger；函式要另外刪。
    op.drop_index(op.f("ix_audit_events_project_id_created_at"), table_name="audit_events")
    op.drop_table("audit_events")
    op.execute("DROP FUNCTION audit_events_reject_mutation()")
    op.drop_index(op.f("ix_api_keys_project_id"), table_name="api_keys")
    op.drop_table("api_keys")
    op.drop_table("projects")
