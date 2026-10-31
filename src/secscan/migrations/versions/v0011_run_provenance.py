"""每個 run 實際執行的內容（T16；docs/DECISIONS.md §20.2）。

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-31 18:00:00+00:00

升降級說明：
- upgrade：scanner_runs 新增 plan_hash（ExecutionPlan 的 sha256）與 profile_definition_sha256（zap
  的規則定義的 sha256），都可為 null。runner 在建立容器之前寫入一次（以 plan_hash IS NULL 為條件的
  fenced update）；run 結束之後由 0009 的 trigger 凍結。CHECK：sha256 的格式；只有記下容器的 run 有
  plan_hash；profile 定義只屬於 zap、而且要和 plan_hash 一起。既有的資料列兩者都是 null，符合 CHECK
  （T16 之前的 run 沒有這個紀錄，API 回 null）。
  - trigger scanner_runs_plan_once：plan_hash 有值之後，兩個欄位都不能再改（比照 0009 的
    container_removed_at；只在 UPDATE 這兩個欄位時觸發）。
- downgrade：刪除 trigger、函式與兩個欄位，已記下的版本會消失；只用於開發與測試。
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | Sequence[str] | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# 和 scans/models.py 相同的內容（migration 不 import 應用程式的程式）。
_SHA256_HEX = "^[0-9a-f]{64}$"
_RUN_CHECKS = {
    "plan_hash_valid": (
        f"plan_hash IS NULL OR (plan_hash ~ '{_SHA256_HEX}' AND container_name IS NOT NULL)"
    ),
    "profile_definition_valid": (
        "profile_definition_sha256 IS NULL "
        f"OR (profile_definition_sha256 ~ '{_SHA256_HEX}' AND engine = 'zap' "
        "AND plan_hash IS NOT NULL)"
    ),
}


# 不用 RAISE 的 % 格式字串（SQLAlchemy 會跳脫文字 SQL 裡的 %）；固定 search_path（同 0009）。
_PLAN_ONCE = """
CREATE FUNCTION scanner_runs_plan_once() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF OLD.plan_hash IS NOT NULL AND (
        NEW.plan_hash IS DISTINCT FROM OLD.plan_hash
        OR NEW.profile_definition_sha256 IS DISTINCT FROM OLD.profile_definition_sha256
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'scanner_runs: the plan can only be recorded once';
    END IF;
    RETURN NEW;
END;
$$
"""
_PLAN_ONCE_TRIGGER = (
    "CREATE TRIGGER scanner_runs_plan_once "
    "BEFORE UPDATE OF plan_hash, profile_definition_sha256 ON scanner_runs "
    "FOR EACH ROW EXECUTE FUNCTION scanner_runs_plan_once()"
)


def upgrade() -> None:
    op.add_column("scanner_runs", sa.Column("plan_hash", sa.String(64), nullable=True))
    op.add_column(
        "scanner_runs", sa.Column("profile_definition_sha256", sa.String(64), nullable=True)
    )
    for name, condition in _RUN_CHECKS.items():
        op.create_check_constraint(op.f(f"ck_scanner_runs_{name}"), "scanner_runs", condition)
    op.execute(_PLAN_ONCE)
    op.execute(_PLAN_ONCE_TRIGGER)


def downgrade() -> None:
    op.execute("DROP TRIGGER scanner_runs_plan_once ON scanner_runs")
    op.execute("DROP FUNCTION scanner_runs_plan_once()")
    for name in reversed(_RUN_CHECKS):
        op.drop_constraint(op.f(f"ck_scanner_runs_{name}"), "scanner_runs", type_="check")
    op.drop_column("scanner_runs", "profile_definition_sha256")
    op.drop_column("scanner_runs", "plan_hash")
