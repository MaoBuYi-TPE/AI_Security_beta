"""引擎子預算與每個 run 分到的秒數（T31；docs/DECISIONS.md §29）。

Revision ID: 0020
Revises: 0019
Create Date: 2026-11-08 23:00:00+00:00

升降級說明：
- upgrade：
  - scanner_runs 新增三個可為 null 的整數欄位：
    - budget_max_requests、budget_max_duration_seconds：建立 scan 時凍結的引擎上限（選填；沒有
      指定時兩者都是 null，行為和之前相同：每個 run 分到剩下的全部）。
    - seconds_allotted：容器版的 run 開始時分到的秒數（和既有的 requests_allotted 一起寫入）。
  - 既有的資料列三個欄位都是 null，符合 CHECK；不回填（T31 之前的 run 沒有記下秒數，API 回 null）。
  - CHECK：
    - engine_budget_valid：上限同時有值或同時是 null、都是正整數、只屬於掃描引擎（不是 preflight、
      fake）。
    - seconds_allotted_valid：秒數不為負，而且只和請求數一起出現。
    - allotment_within_engine_budget：有上限的 run 寫入請求數時，秒數也必須寫入，兩者都不超過上限。
      還不認得上限的舊 runner 只寫請求數，會在這裡失敗、容器不會建立（fail closed）。
  - trigger scanner_runs_engine_budget_frozen：上限的欄位不能修改（只能在建立 scan 時寫入；0009 的
    trigger 已經只允許在建立 scan 的 transaction 新增 run，結束的 run 也整列凍結）。
  - trigger scanner_runs_allotment_once：秒數寫入之後，請求數與秒數都不能再改。
  - 先停 api、runner、worker，再升級，然後一起以新版啟動（舊的 runner 不會寫秒數，見上）。
- downgrade：刪除 trigger、函式、CHECK 與三個欄位，已記下的上限與秒數會消失；只用於開發與測試。
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0020"
down_revision: str | Sequence[str] | None = "0019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COLUMNS = ("budget_max_requests", "budget_max_duration_seconds", "seconds_allotted")
# 和 scans/models.py 相同的內容（migration 不 import 應用程式的程式）。
_RUN_CHECKS = {
    "engine_budget_valid": (
        "(budget_max_requests IS NULL) = (budget_max_duration_seconds IS NULL) "
        "AND (budget_max_requests IS NULL OR (budget_max_requests > 0 "
        "AND budget_max_duration_seconds > 0 "
        "AND engine NOT IN ('preflight', 'fake')))"
    ),
    "seconds_allotted_valid": (
        "seconds_allotted IS NULL OR (seconds_allotted >= 0 AND requests_allotted IS NOT NULL)"
    ),
    "allotment_within_engine_budget": (
        "budget_max_requests IS NULL OR requests_allotted IS NULL "
        "OR (seconds_allotted IS NOT NULL AND requests_allotted <= budget_max_requests "
        "AND seconds_allotted <= budget_max_duration_seconds)"
    ),
}

# 不用 RAISE 的 % 格式字串（SQLAlchemy 會跳脫文字 SQL 裡的 %）；固定 search_path（同 0009）。
_BUDGET_FROZEN = """
CREATE FUNCTION scanner_runs_engine_budget_frozen() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF NEW.budget_max_requests IS DISTINCT FROM OLD.budget_max_requests
        OR NEW.budget_max_duration_seconds IS DISTINCT FROM OLD.budget_max_duration_seconds
    THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'scanner_runs: the engine budget is frozen when the scan is created';
    END IF;
    RETURN NEW;
END;
$$
"""
_BUDGET_FROZEN_TRIGGER = (
    "CREATE TRIGGER scanner_runs_engine_budget_frozen "
    "BEFORE UPDATE OF budget_max_requests, budget_max_duration_seconds ON scanner_runs "
    "FOR EACH ROW EXECUTE FUNCTION scanner_runs_engine_budget_frozen()"
)
_ALLOTMENT_ONCE = """
CREATE FUNCTION scanner_runs_allotment_once() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF OLD.seconds_allotted IS NOT NULL AND (
        NEW.seconds_allotted IS DISTINCT FROM OLD.seconds_allotted
        OR NEW.requests_allotted IS DISTINCT FROM OLD.requests_allotted
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'scanner_runs: the allotment can only be recorded once';
    END IF;
    RETURN NEW;
END;
$$
"""
_ALLOTMENT_ONCE_TRIGGER = (
    "CREATE TRIGGER scanner_runs_allotment_once "
    "BEFORE UPDATE OF requests_allotted, seconds_allotted ON scanner_runs "
    "FOR EACH ROW EXECUTE FUNCTION scanner_runs_allotment_once()"
)


def upgrade() -> None:
    for column in _COLUMNS:
        op.add_column("scanner_runs", sa.Column(column, sa.Integer(), nullable=True))
    for name, condition in _RUN_CHECKS.items():
        op.create_check_constraint(op.f(f"ck_scanner_runs_{name}"), "scanner_runs", condition)
    op.execute(_BUDGET_FROZEN)
    op.execute(_BUDGET_FROZEN_TRIGGER)
    op.execute(_ALLOTMENT_ONCE)
    op.execute(_ALLOTMENT_ONCE_TRIGGER)


def downgrade() -> None:
    op.execute("DROP TRIGGER scanner_runs_allotment_once ON scanner_runs")
    op.execute("DROP FUNCTION scanner_runs_allotment_once()")
    op.execute("DROP TRIGGER scanner_runs_engine_budget_frozen ON scanner_runs")
    op.execute("DROP FUNCTION scanner_runs_engine_budget_frozen()")
    for name in reversed(_RUN_CHECKS):
        op.drop_constraint(op.f(f"ck_scanner_runs_{name}"), "scanner_runs", type_="check")
    for column in reversed(_COLUMNS):
        op.drop_column("scanner_runs", column)
