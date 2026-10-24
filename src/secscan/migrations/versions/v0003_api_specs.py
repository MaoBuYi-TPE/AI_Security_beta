"""API 規格與 operation inventory：api_specs、api_spec_operations（T07）。

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-24 09:00:00+00:00

升降級說明：
- upgrade：建立 api_specs 與 api_spec_operations 及其 FK／unique／check。正規化文件存在
  api_specs.document（bytea），CHECK 確認 `sha256(document)` 與 document_sha256 相符。
  兩張表另加 trigger：UPDATE、DELETE 與 TRUNCATE 一律拒絕（docs/DECISIONS.md §11.5）。
- downgrade：刪除這兩個資料表與 trigger 函式，**所有上傳的規格與 inventory 都會消失**。
  只用於開發與測試，正式環境不要 downgrade。
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | Sequence[str] | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLES = ("api_specs", "api_spec_operations")

# 不用 RAISE 的 % 格式字串：SQLAlchemy 會把文字 SQL 裡的 % 跳脫，改用字串串接。
# 固定 search_path，函式不受呼叫端 search_path 影響（避免被同名物件劫持）。
_CREATE_GUARD_FUNCTION = """
CREATE FUNCTION api_specs_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = 'integrity_constraint_violation',
        MESSAGE = TG_TABLE_NAME || ' rows are immutable (' || TG_OP || ' blocked); '
            || 'upload a new version instead';
END;
$$
"""


def _row_trigger(table: str) -> str:
    return (
        f"CREATE TRIGGER {table}_immutable BEFORE UPDATE OR DELETE ON {table} "
        "FOR EACH ROW EXECUTE FUNCTION api_specs_guard()"
    )


def _truncate_trigger(table: str) -> str:
    return (
        f"CREATE TRIGGER {table}_no_truncate BEFORE TRUNCATE ON {table} "
        "FOR EACH STATEMENT EXECUTE FUNCTION api_specs_guard()"
    )


def upgrade() -> None:
    op.create_table(
        "api_specs",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("source_format", sa.String(length=8), nullable=False),
        sa.Column("source_size_bytes", sa.Integer(), nullable=False),
        sa.Column("source_sha256", sa.LargeBinary(), nullable=False),
        sa.Column("document", sa.LargeBinary(), nullable=False),
        sa.Column("document_sha256", sa.LargeBinary(), nullable=False),
        sa.Column("openapi_version", sa.String(length=16), nullable=False),
        sa.Column("base_path", sa.String(length=512), nullable=False),
        sa.Column("operation_count", sa.Integer(), nullable=False),
        sa.Column("uploaded_by_key_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("version > 0", name=op.f("ck_api_specs_version_positive")),
        sa.CheckConstraint(
            "source_format IN ('json', 'yaml')", name=op.f("ck_api_specs_format_valid")
        ),
        sa.CheckConstraint(
            "source_size_bytes BETWEEN 1 AND 1048576", name=op.f("ck_api_specs_source_size_valid")
        ),
        sa.CheckConstraint(
            "octet_length(source_sha256) = 32", name=op.f("ck_api_specs_source_sha256_length")
        ),
        sa.CheckConstraint(
            "octet_length(document) BETWEEN 1 AND 2097152",
            name=op.f("ck_api_specs_document_size_valid"),
        ),
        sa.CheckConstraint(
            "document_sha256 = sha256(document)",
            name=op.f("ck_api_specs_document_sha256_matches"),
        ),
        sa.CheckConstraint(
            r"openapi_version ~ '^3\.0\.(0|[1-9][0-9]*)$'",
            name=op.f("ck_api_specs_openapi_version_valid"),
        ),
        sa.CheckConstraint(
            "base_path = '' OR (left(base_path, 1) = '/' AND right(base_path, 1) <> '/')",
            name=op.f("ck_api_specs_base_path_valid"),
        ),
        sa.CheckConstraint(
            "operation_count BETWEEN 0 AND 1000", name=op.f("ck_api_specs_operation_count_valid")
        ),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["targets.id"],
            name=op.f("fk_api_specs_target_id_targets"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["uploaded_by_key_id"],
            ["api_keys.id"],
            name=op.f("fk_api_specs_uploaded_by_key_id_api_keys"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_api_specs")),
        sa.UniqueConstraint("target_id", "version", name=op.f("uq_api_specs_target_id_version")),
    )
    op.create_table(
        "api_spec_operations",
        sa.Column("spec_id", sa.Uuid(), nullable=False),
        sa.Column("ordinal", sa.Integer(), autoincrement=False, nullable=False),
        sa.Column("method", sa.String(length=7), nullable=False),
        sa.Column("path", sa.String(length=512), nullable=False),
        sa.Column("operation_id", sa.String(length=200), nullable=True),
        sa.CheckConstraint(
            "method IN ('GET', 'PUT', 'POST', 'DELETE', 'OPTIONS', 'HEAD', 'PATCH', 'TRACE')",
            name=op.f("ck_api_spec_operations_method_valid"),
        ),
        sa.CheckConstraint("left(path, 1) = '/'", name=op.f("ck_api_spec_operations_path_valid")),
        sa.CheckConstraint(
            "operation_id IS NULL OR char_length(btrim(operation_id)) > 0",
            name=op.f("ck_api_spec_operations_operation_id_not_blank"),
        ),
        sa.CheckConstraint(
            "ordinal >= 0 AND ordinal < 1000", name=op.f("ck_api_spec_operations_ordinal_valid")
        ),
        sa.ForeignKeyConstraint(
            ["spec_id"],
            ["api_specs.id"],
            name=op.f("fk_api_spec_operations_spec_id_api_specs"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("spec_id", "ordinal", name=op.f("pk_api_spec_operations")),
        sa.UniqueConstraint(
            "spec_id", "method", "path", name=op.f("uq_api_spec_operations_spec_id_method_path")
        ),
        sa.UniqueConstraint(
            "spec_id", "operation_id", name=op.f("uq_api_spec_operations_spec_id_operation_id")
        ),
    )
    op.execute(_CREATE_GUARD_FUNCTION)
    for table in _TABLES:
        op.execute(_row_trigger(table))
        op.execute(_truncate_trigger(table))


def downgrade() -> None:
    # 刪除資料表會一併刪除它的 trigger；函式要另外刪。
    op.drop_table("api_spec_operations")
    op.drop_table("api_specs")
    op.execute("DROP FUNCTION api_specs_guard()")
