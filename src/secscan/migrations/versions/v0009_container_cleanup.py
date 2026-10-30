"""容器確認刪除的時間（T13；docs/DECISIONS.md §17.3）。

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-30 09:00:00+00:00

升降級說明：
- upgrade：
  - scanner_runs 新增 container_removed_at（容器確認不存在的時間；可為 null）。CHECK：只有記下
    容器的 run 才能有值，而且不早於 run 開始的時間。既有的資料列都是 null，符合 CHECK；升級之前
    的容器 run 都會成為待處理，由 runner 的對帳逐一確認（不回填）。
  - 部分索引 ix_scanner_runs_pending_containers：對帳找還沒確認刪除的容器。
  - 改寫 scanner_runs_guard()：container_removed_at 只能寫入一次；已終止的 run 只允許補寫它
    （其他欄位完全不變，以 to_jsonb 比較，之後新增的欄位也一併凍結）。
- downgrade：先還原 0005 的 trigger 函式，再刪除索引、CHECK 與欄位，**已記下的刪除時間會消失**。
  只用於開發與測試，正式環境不要 downgrade。
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | Sequence[str] | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# 和 scans/models.py 相同的內容（migration 不 import 應用程式的程式）。
_REMOVED_AFTER_START = (
    "container_removed_at IS NULL "
    "OR (container_name IS NOT NULL AND container_removed_at >= started_at)"
)
_PENDING = "container_name IS NOT NULL AND container_removed_at IS NULL"
# 0005 的內容（migration 是當時的快照，不引用其他 migration）。
_TERMINAL_RUNS = "'cancelled', 'failed', 'interrupted', 'succeeded', 'timed_out'"
_IDENTITY = "({p}.id, {p}.scan_id, {p}.engine, {p}.sequence, {p}.created_at)"
_CREATED_IN_THIS_TRANSACTION = (
    "EXISTS (SELECT 1 FROM public.scans AS parent "
    "WHERE parent.id = NEW.scan_id AND parent.created_at = now())"
)
_INSERT = f"""
    IF TG_OP = 'INSERT' THEN
        IF NOT (NEW.status = 'queued' AND NEW.lease_owner IS NULL AND NEW.started_at IS NULL
            AND NEW.finished_at IS NULL AND NEW.error_code IS NULL)
        THEN
            RAISE EXCEPTION USING
                ERRCODE = 'integrity_constraint_violation',
                MESSAGE = 'scanner_runs: a new run must be queued without a lease';
        END IF;
        IF NOT {_CREATED_IN_THIS_TRANSACTION} THEN
            RAISE EXCEPTION USING
                ERRCODE = 'integrity_constraint_violation',
                MESSAGE = 'scanner_runs: runs can only be added while creating their scan';
        END IF;
        RETURN NEW;
    END IF;"""
_BLOCKED = """
    RAISE EXCEPTION USING
        ERRCODE = 'integrity_constraint_violation',
        MESSAGE = 'scanner_runs: ' || TG_OP || ' blocked; only an unfinished run can change '
            || 'and its identity is fixed';"""
_SAME_IDENTITY = f"{_IDENTITY.format(p='NEW')} IS NOT DISTINCT FROM {_IDENTITY.format(p='OLD')}"

# 不用 RAISE 的 % 格式字串（SQLAlchemy 會跳脫文字 SQL 裡的 %）；固定 search_path。
# 巢狀的 IF：TRUNCATE 與 DELETE 時 NEW 是 NULL，不能和 UPDATE 的條件寫在同一個運算式。
_GUARD = f"""
CREATE OR REPLACE FUNCTION scanner_runs_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN{_INSERT}
    IF TG_OP = 'UPDATE' THEN
        IF OLD.container_removed_at IS NOT NULL
            AND NEW.container_removed_at IS DISTINCT FROM OLD.container_removed_at
        THEN
            RAISE EXCEPTION USING
                ERRCODE = 'integrity_constraint_violation',
                MESSAGE = 'scanner_runs: container_removed_at can only be recorded once';
        END IF;
        IF {_SAME_IDENTITY} THEN
            IF OLD.status NOT IN ({_TERMINAL_RUNS}) THEN
                RETURN NEW;
            END IF;
            IF OLD.container_removed_at IS NULL AND NEW.container_removed_at IS NOT NULL
                AND to_jsonb(NEW) - 'container_removed_at' = to_jsonb(OLD) - 'container_removed_at'
            THEN
                RETURN NEW;
            END IF;
        END IF;
    END IF;{_BLOCKED}
END;
$$
"""

_PREVIOUS_GUARD = f"""
CREATE OR REPLACE FUNCTION scanner_runs_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN{_INSERT}
    IF TG_OP = 'UPDATE'
        AND {_SAME_IDENTITY}
        AND OLD.status NOT IN ({_TERMINAL_RUNS})
    THEN
        RETURN NEW;
    END IF;{_BLOCKED}
END;
$$
"""


def upgrade() -> None:
    op.add_column(
        "scanner_runs",
        sa.Column("container_removed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_check_constraint(
        op.f("ck_scanner_runs_container_removed_after_start"),
        "scanner_runs",
        _REMOVED_AFTER_START,
    )
    op.create_index(
        "ix_scanner_runs_pending_containers",
        "scanner_runs",
        ["created_at"],
        unique=False,
        postgresql_where=sa.text(_PENDING),
    )
    op.execute(_GUARD)


def downgrade() -> None:
    op.execute(_PREVIOUS_GUARD)
    op.drop_index(
        "ix_scanner_runs_pending_containers",
        table_name="scanner_runs",
        postgresql_where=sa.text(_PENDING),
    )
    op.drop_constraint(
        op.f("ck_scanner_runs_container_removed_after_start"), "scanner_runs", type_="check"
    )
    op.drop_column("scanner_runs", "container_removed_at")
