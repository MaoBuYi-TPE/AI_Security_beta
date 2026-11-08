"""停用 auth profile、全域稽核查詢的索引（T21；docs/DECISIONS.md §28.7）。

Revision ID: 0019
Revises: 0018
Create Date: 2026-11-08 21:00:00+00:00

升降級說明：
- upgrade：
  - auth_profiles 新增 `disabled_at` 與 `disabled_by_key_id`（兩者同時有值或同時是 NULL）。
  - auth_profiles 原本以 `auth_profiles_guard` 拒絕所有 UPDATE 與 DELETE。改成兩個 trigger：
    UPDATE 由新的 `auth_profiles_update_guard` 只允許「從未停用 → 停用」一次（其他欄位不變，停用
    是終止狀態）；DELETE 仍由 `auth_profiles_guard` 拒絕。`auth_profiles_guard` 本身不變（它也掛在
    auth_profile_versions 的 TRUNCATE 上，函式中不能引用只屬於 auth_profiles 的欄位：PL/pgSQL 依
    trigger 所屬資料表的 row type 解析 OLD 的欄位）。
  - auth_profile_versions_guard 改版：已停用的 profile 不能新增版本。
  - deferred constraint trigger：profile 轉成停用時，commit 時不能還有任何帶密文的版本（停用時
    一定清除目前的密文）。
  - 索引：audit_events (created_at, id)（全域稽核查詢由新到舊分頁）、auth_profiles 的
    disabled_by_key_id（FK）。
  - 執行時先停 api 與 worker（建立索引期間會擋住 audit 的寫入）。
- downgrade：恢復 v0004 的 trigger 與 auth_profile_versions_guard，刪除新的函式、索引與兩個欄位；
  停用紀錄會消失（被清除的密文不會回來）。只用於開發與測試。
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0019"
down_revision: str | Sequence[str] | None = "0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# 和 v0004 相同的內容（migration 不 import 應用程式或其他 migration 的程式）。
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


_DISABLED_PARENT = """
        IF EXISTS (
            SELECT 1 FROM public.auth_profiles AS profile
            WHERE profile.id = NEW.profile_id AND profile.disabled_at IS NOT NULL
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'integrity_constraint_violation',
                MESSAGE = 'auth_profile_versions: a disabled profile cannot get new versions';
        END IF;"""


def _versions_guard(*, disable_aware: bool) -> str:
    parent = _DISABLED_PARENT if disable_aware else ""
    return f"""
CREATE OR REPLACE FUNCTION auth_profile_versions_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.encrypted_secret IS NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = 'integrity_constraint_violation',
                MESSAGE = 'auth_profile_versions: a new version must carry a secret';
        END IF;{parent}
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


_UPDATE_GUARD = """
CREATE FUNCTION auth_profiles_update_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF OLD.disabled_at IS NULL
        AND NEW.disabled_at IS NOT NULL
        AND (to_jsonb(NEW) - ARRAY['disabled_at', 'disabled_by_key_id'])
            = (to_jsonb(OLD) - ARRAY['disabled_at', 'disabled_by_key_id'])
    THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION USING
        ERRCODE = 'integrity_constraint_violation',
        MESSAGE = 'auth_profiles rows are immutable except disabling once (UPDATE blocked)';
END;
$$
"""
_DISABLED_ERASED = """
CREATE FUNCTION auth_profiles_disabled_erased() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM public.auth_profile_versions AS version
        WHERE version.profile_id = NEW.id AND version.encrypted_secret IS NOT NULL
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'auth_profiles: a disabled profile must not keep any secret';
    END IF;
    RETURN NULL;
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
    op.create_index(
        op.f("ix_auth_profiles_disabled_by_key_id"), "auth_profiles", ["disabled_by_key_id"]
    )
    op.execute(_UPDATE_GUARD)
    op.execute("DROP TRIGGER auth_profiles_immutable ON auth_profiles")
    op.execute(
        "CREATE TRIGGER auth_profiles_update_guard BEFORE UPDATE ON auth_profiles "
        "FOR EACH ROW EXECUTE FUNCTION auth_profiles_update_guard()"
    )
    op.execute(
        "CREATE TRIGGER auth_profiles_no_delete BEFORE DELETE ON auth_profiles "
        "FOR EACH ROW EXECUTE FUNCTION auth_profiles_guard()"
    )
    op.execute(_versions_guard(disable_aware=True))
    op.execute(_DISABLED_ERASED)
    op.execute(
        "CREATE CONSTRAINT TRIGGER auth_profiles_disabled_erased AFTER UPDATE ON auth_profiles "
        "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW "
        "WHEN (OLD.disabled_at IS NULL AND NEW.disabled_at IS NOT NULL) "
        "EXECUTE FUNCTION auth_profiles_disabled_erased()"
    )
    op.create_index(op.f("ix_audit_events_created_at_id"), "audit_events", ["created_at", "id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_audit_events_created_at_id"), table_name="audit_events")
    op.execute("DROP TRIGGER auth_profiles_disabled_erased ON auth_profiles")
    op.execute("DROP FUNCTION auth_profiles_disabled_erased()")
    op.execute(_versions_guard(disable_aware=False))
    op.execute("DROP TRIGGER auth_profiles_no_delete ON auth_profiles")
    op.execute("DROP TRIGGER auth_profiles_update_guard ON auth_profiles")
    op.execute(
        "CREATE TRIGGER auth_profiles_immutable BEFORE UPDATE OR DELETE ON auth_profiles "
        "FOR EACH ROW EXECUTE FUNCTION auth_profiles_guard()"
    )
    op.execute("DROP FUNCTION auth_profiles_update_guard()")
    op.drop_index(op.f("ix_auth_profiles_disabled_by_key_id"), table_name="auth_profiles")
    op.drop_constraint(op.f("ck_auth_profiles_disabled_valid"), "auth_profiles", type_="check")
    op.drop_constraint(
        op.f("fk_auth_profiles_disabled_by_key_id_api_keys"), "auth_profiles", type_="foreignkey"
    )
    op.drop_column("auth_profiles", "disabled_by_key_id")
    op.drop_column("auth_profiles", "disabled_at")
