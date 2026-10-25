"""被測目標的認證設定：auth_profiles、auth_profile_versions（T08）。

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-25 09:00:00+00:00

升降級說明：
- upgrade：建立 auth_profiles 與 auth_profile_versions 及其 FK／unique／check，以及部分唯一索引
  uq_auth_profile_versions_live_secret（每個 profile 最多一份密文）。trigger：
  - auth_profiles：UPDATE、DELETE 與 TRUNCATE 一律拒絕。
  - auth_profile_versions：INSERT 必須帶密文；UPDATE 只允許「清除密文」（同時記下 secret_erased_at）
    與「重新加密」（金鑰換版），而且其他欄位都不能改；DELETE 與 TRUNCATE 一律拒絕
    （docs/DECISIONS.md §12.3）。
- downgrade：刪除這兩個資料表與 trigger 函式，**所有認證設定與加密的 secret 都會消失**。
  只用於開發與測試，正式環境不要 downgrade。
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: str | Sequence[str] | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# 版本列建立後不能改的欄位（只有密文與清除時間可以依規則改變）。
_VERSION_COLUMNS = (
    "profile_id",
    "version",
    "type",
    "header_name",
    "preflight_method",
    "preflight_path",
    "preflight_expected_status",
    "preflight_expected_json",
    "created_by_key_id",
    "created_at",
)


def _row(prefix: str) -> str:
    return "(" + ", ".join(f"{prefix}.{column}" for column in _VERSION_COLUMNS) + ")"


# 不用 RAISE 的 % 格式字串：SQLAlchemy 會把文字 SQL 裡的 % 跳脫，改用字串串接。
# 固定 search_path，函式不受呼叫端 search_path 影響（避免被同名物件劫持）。
_CREATE_PROFILES_GUARD = """
CREATE FUNCTION auth_profiles_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = 'integrity_constraint_violation',
        MESSAGE = TG_TABLE_NAME || ' rows are immutable (' || TG_OP || ' blocked)';
END;
$$
"""

_CREATE_VERSIONS_GUARD = f"""
CREATE FUNCTION auth_profile_versions_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.encrypted_secret IS NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = 'integrity_constraint_violation',
                MESSAGE = 'auth_profile_versions: a new version must carry a secret';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE'
        AND {_row("NEW")} IS NOT DISTINCT FROM {_row("OLD")}
        AND OLD.encrypted_secret IS NOT NULL
        AND OLD.secret_erased_at IS NULL
    THEN
        -- 清除：密文變成 NULL，同時記下清除的時間。
        IF NEW.encrypted_secret IS NULL AND NEW.secret_erased_at IS NOT NULL THEN
            RETURN NEW;
        END IF;
        -- 重新加密（金鑰換版）：換成另一份密文，清除時間維持 NULL。
        IF NEW.encrypted_secret IS NOT NULL
            AND NEW.encrypted_secret IS DISTINCT FROM OLD.encrypted_secret
            AND NEW.secret_erased_at IS NULL
        THEN
            RETURN NEW;
        END IF;
    END IF;
    RAISE EXCEPTION USING
        ERRCODE = 'integrity_constraint_violation',
        MESSAGE = 'auth_profile_versions: ' || TG_OP
            || ' blocked; only erasing or re-encrypting the secret is allowed';
END;
$$
"""


def upgrade() -> None:
    op.create_table(
        "auth_profiles",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("role_label", sa.String(length=64), nullable=False),
        sa.Column("created_by_key_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "char_length(btrim(name)) > 0", name=op.f("ck_auth_profiles_name_not_blank")
        ),
        sa.CheckConstraint(
            "role_label ~ '^[a-z][a-z0-9_]{0,63}$' AND role_label NOT IN ('anonymous')",
            name=op.f("ck_auth_profiles_role_label_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["targets.id"],
            name=op.f("fk_auth_profiles_target_id_targets"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_key_id"],
            ["api_keys.id"],
            name=op.f("fk_auth_profiles_created_by_key_id_api_keys"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_auth_profiles")),
        sa.UniqueConstraint(
            "target_id", "role_label", name=op.f("uq_auth_profiles_target_id_role_label")
        ),
    )
    op.create_table(
        "auth_profile_versions",
        sa.Column("profile_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), autoincrement=False, nullable=False),
        sa.Column("type", sa.String(length=16), nullable=False),
        sa.Column("header_name", sa.String(length=64), nullable=True),
        sa.Column("preflight_method", sa.String(length=7), nullable=False),
        sa.Column("preflight_path", sa.String(length=512), nullable=False),
        sa.Column("preflight_expected_status", sa.Integer(), nullable=False),
        sa.Column(
            "preflight_expected_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        sa.Column("encrypted_secret", sa.LargeBinary(), nullable=True),
        sa.Column("secret_erased_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_key_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("version > 0", name=op.f("ck_auth_profile_versions_version_positive")),
        sa.CheckConstraint(
            "type IN ('bearer', 'api_key_header', 'cookie')",
            name=op.f("ck_auth_profile_versions_type_valid"),
        ),
        sa.CheckConstraint(
            "(type = 'api_key_header') = (header_name IS NOT NULL)",
            name=op.f("ck_auth_profile_versions_header_name_matches_type"),
        ),
        sa.CheckConstraint(
            "header_name IS NULL OR header_name ~ '^[A-Za-z0-9]+(-[A-Za-z0-9]+)*$'",
            name=op.f("ck_auth_profile_versions_header_name_valid"),
        ),
        sa.CheckConstraint(
            "preflight_method = 'GET'", name=op.f("ck_auth_profile_versions_preflight_method_valid")
        ),
        sa.CheckConstraint(
            "left(preflight_path, 1) = '/' "
            "AND strpos(preflight_path, '{') = 0 AND strpos(preflight_path, '}') = 0",
            name=op.f("ck_auth_profile_versions_preflight_path_valid"),
        ),
        sa.CheckConstraint(
            "preflight_expected_status BETWEEN 200 AND 299",
            name=op.f("ck_auth_profile_versions_preflight_status_valid"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(preflight_expected_json) = 'object' "
            "AND preflight_expected_json <> '{}'::jsonb "
            "AND octet_length(preflight_expected_json::text) <= 65536",
            name=op.f("ck_auth_profile_versions_preflight_expected_json_valid"),
        ),
        sa.CheckConstraint(
            "(encrypted_secret IS NULL) = (secret_erased_at IS NOT NULL)",
            name=op.f("ck_auth_profile_versions_secret_erasure_consistent"),
        ),
        sa.CheckConstraint(
            "encrypted_secret IS NULL OR ("
            "substring(encrypted_secret FROM 1 FOR 6) = 'gAAAAA'::bytea "
            "AND octet_length(encrypted_secret) <= 11236)",
            name=op.f("ck_auth_profile_versions_encrypted_secret_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["profile_id"],
            ["auth_profiles.id"],
            name=op.f("fk_auth_profile_versions_profile_id_auth_profiles"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_key_id"],
            ["api_keys.id"],
            name=op.f("fk_auth_profile_versions_created_by_key_id_api_keys"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("profile_id", "version", name=op.f("pk_auth_profile_versions")),
    )
    op.create_index(
        "uq_auth_profile_versions_live_secret",
        "auth_profile_versions",
        ["profile_id"],
        unique=True,
        postgresql_where=sa.text("encrypted_secret IS NOT NULL"),
    )
    op.execute(_CREATE_PROFILES_GUARD)
    op.execute(_CREATE_VERSIONS_GUARD)
    op.execute(
        "CREATE TRIGGER auth_profiles_immutable BEFORE UPDATE OR DELETE ON auth_profiles "
        "FOR EACH ROW EXECUTE FUNCTION auth_profiles_guard()"
    )
    op.execute(
        "CREATE TRIGGER auth_profiles_no_truncate BEFORE TRUNCATE ON auth_profiles "
        "FOR EACH STATEMENT EXECUTE FUNCTION auth_profiles_guard()"
    )
    op.execute(
        "CREATE TRIGGER auth_profile_versions_guard_rows "
        "BEFORE INSERT OR UPDATE OR DELETE ON auth_profile_versions "
        "FOR EACH ROW EXECUTE FUNCTION auth_profile_versions_guard()"
    )
    op.execute(
        "CREATE TRIGGER auth_profile_versions_no_truncate BEFORE TRUNCATE ON auth_profile_versions "
        "FOR EACH STATEMENT EXECUTE FUNCTION auth_profiles_guard()"
    )


def downgrade() -> None:
    # 刪除資料表會一併刪除它的 trigger 與索引；函式要另外刪。
    op.drop_table("auth_profile_versions")
    op.drop_table("auth_profiles")
    op.execute("DROP FUNCTION auth_profile_versions_guard()")
    op.execute("DROP FUNCTION auth_profiles_guard()")
