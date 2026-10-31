"""T33：每個 run 的 Guard policy 版本，歷史資料不回填。

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-01 00:00:00+00:00

upgrade 新增 nullable 欄位；舊 plan 的 null 保留未記錄的事實。新 plan 必須同時寫版本，
之後兩者一起凍結。downgrade 只供隔離測試；有實驗版紀錄即拒絕，避免抹去證據後被當作 strict。
沒有實驗版紀錄時先還原 0011 的 trigger/function，再刪欄位（strict 的顯式紀錄會消失）。
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: str | Sequence[str] | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_CHECK = (
    "guard_policy_version IS NULL OR (guard_policy_version IN "
    "('strict-1', 'encoded-params-1') AND plan_hash IS NOT NULL)"
)
_FUNCTION = """
CREATE OR REPLACE FUNCTION scanner_runs_plan_once() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF OLD.plan_hash IS NULL AND NEW.plan_hash IS NOT NULL
        AND NEW.guard_policy_version IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'scanner_runs: a new plan requires its guard policy version';
    END IF;
    IF OLD.plan_hash IS NOT NULL AND (
        NEW.plan_hash IS DISTINCT FROM OLD.plan_hash
        OR NEW.profile_definition_sha256 IS DISTINCT FROM OLD.profile_definition_sha256
        OR NEW.guard_policy_version IS DISTINCT FROM OLD.guard_policy_version
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'scanner_runs: the plan can only be recorded once';
    END IF;
    RETURN NEW;
END;
$$
"""
# Migration 是當時的快照；不得 import 應用程式或其他 migration。
_PREVIOUS_FUNCTION = """
CREATE OR REPLACE FUNCTION scanner_runs_plan_once() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF OLD.plan_hash IS NOT NULL AND (
        NEW.plan_hash IS DISTINCT FROM OLD.plan_hash
        OR NEW.profile_definition_sha256 IS DISTINCT FROM OLD.profile_definition_sha256
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'scanner_runs: the plan can only be recorded once';
    END IF;
    RETURN NEW;
END;
$$
"""


def _trigger(*, version: bool) -> None:
    columns = "plan_hash, profile_definition_sha256"
    if version:
        columns += ", guard_policy_version"
    op.execute("DROP TRIGGER scanner_runs_plan_once ON scanner_runs")
    op.execute(
        "CREATE TRIGGER scanner_runs_plan_once BEFORE UPDATE OF "
        + columns
        + " ON scanner_runs FOR EACH ROW EXECUTE FUNCTION scanner_runs_plan_once()"
    )


def upgrade() -> None:
    op.add_column("scanner_runs", sa.Column("guard_policy_version", sa.String(32), nullable=True))
    op.create_check_constraint(
        op.f("ck_scanner_runs_guard_policy_version_valid"), "scanner_runs", _CHECK
    )
    op.execute(_FUNCTION)
    _trigger(version=True)


def downgrade() -> None:
    # 先等既有 writer 完成，再檢查證據；鎖持有到 migration 交易結束，避免檢查後的新寫入
    # 在 DROP COLUMN 取得鎖之前提交，造成實驗政策證據被刪去。
    op.execute("LOCK TABLE scanner_runs IN ACCESS EXCLUSIVE MODE")
    experimental = op.get_bind().scalar(
        sa.text(
            "SELECT EXISTS (SELECT 1 FROM scanner_runs "
            "WHERE guard_policy_version = 'encoded-params-1')"
        )
    )
    if experimental:
        raise RuntimeError("實驗版 Guard policy 的紀錄存在：拒絕移除版本證據")
    op.execute(_PREVIOUS_FUNCTION)
    _trigger(version=False)
    op.drop_constraint(
        op.f("ck_scanner_runs_guard_policy_version_valid"), "scanner_runs", type_="check"
    )
    op.drop_column("scanner_runs", "guard_policy_version")
