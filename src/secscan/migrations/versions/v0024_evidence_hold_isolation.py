"""隔離目錄的機密性隔離（T23a；docs/DECISIONS.md §30.13）。

Revision ID: 0024
Revises: 0023
Create Date: 2026-11-11 12:00:00+00:00

升降級說明：
- upgrade：
  - evidence_holds 新增欄位：
    - isolated_at：目錄已搬到 runs volume 的 held/（worker 讀不到）的時間；NULL 是「隔離中」。
    - releasing_at：retry-evidence 已在 held/ 加密並驗證、開始搬回 active/ 的時間。
    - move_failures、last_move_error、last_move_failed_at：搬不到 held/ 的次數、最近一次的代碼與
      時間（隔離中的明文仍在 active/，必須看得見；§30.13）。
    - source_ino：隔離之前在 active/ 記下的來源目錄 inode，對帳以它確認 held/ 中的目錄就是原本
      那一個。不存 st_dev（重開機之後可能改變），「同一個裝置」在執行時和 held/ 本身比較。
  - 既有的資料不回填：還沒解除的紀錄維持隔離中（由 make runs-layout-migrate 記下 inode、搬移），
    已解除的維持 NULL（這個版本之前就解除、從未搬移）。所以 CHECK 都寫成「有值時才比較」，
    「解除需要 releasing_at」放在 trigger。
  - 9 個 CHECK（和 scans/evidence_models.py 相同）：時間的先後、次數非負、代碼的清單、失敗欄位
    一致、inode 非負、隔離完成必須有 inode。
  - 改寫 trigger 函式 evidence_holds_guard（時間一律由 trigger 以 clock_timestamp() 寫入）：
    - 新增：必須有 source_ino；其他新欄位必須是 NULL 或 0；其餘同 0023。
    - 修改：只允許下列之一，其他欄位完全不變（to_jsonb 比較）；已解除的紀錄一律拒絕。
      0. 記錄來源 inode：source_ino 由 NULL 寫入一次，還沒隔離完成（v0024 之前留下的紀錄）。
      1. 記錄搬移失敗：還沒隔離完成；move_failures 剛好加 1，代碼由 CHECK 限制。
      2. 隔離完成：isolated_at 由 NULL 寫入一次，必須已有 source_ino。
      3. 開始解除：releasing_at 由 NULL 寫入一次，必須已隔離完成。
      4. 解除：同 0023（run 的目錄必須已有 sealed 的 run_evidence），另外必須已開始解除。
    - 刪除、TRUNCATE：一律拒絕（同 0023）。
- 升級時先停 api、worker 與 runner（新增欄位與 CHECK 會鎖住 evidence_holds）。
- downgrade：先鎖住 evidence_holds 再檢查；任何一列有 source_ino、隔離或解除的時間、搬移失敗，
  或已經執行過 runs volume 的 layout 搬移（audit `runs_layout.*`）就拒絕：舊程式不認得 active/ 與
  held/，會把搬走的目錄當成「從來沒有目錄」記成 none，明文永遠不會被加密或清除（資料庫審查 M1）。
  runs-init 建立的新 volume 不寫 DB、這裡偵測不到：降級之前要先把 active/ 的目錄搬回根目錄、刪除
  .layout（DECISIONS §30.13）。否則還原 0023 的 trigger 函式，刪除 CHECK 與欄位。只用於開發與測試。
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0024"
down_revision: str | Sequence[str] | None = "0023"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# 和 scans/evidence_models.py 相同的內容（migration 不 import 應用程式的程式）。
_MOVE_CODES = (
    "'EVIDENCE_HOLD_CONFLICT', 'EVIDENCE_HOLD_DIRECTORY_MISSING', "
    "'EVIDENCE_HOLD_MOVE_FAILED', 'EVIDENCE_HOLD_NOT_DIRECTORY'"
)
_CHECKS = {
    "isolated_after_held": "isolated_at IS NULL OR isolated_at >= held_at",
    "releasing_after_isolated": (
        "releasing_at IS NULL OR (isolated_at IS NOT NULL AND releasing_at >= isolated_at)"
    ),
    "resolved_after_releasing": (
        "resolved_at IS NULL OR releasing_at IS NULL OR resolved_at >= releasing_at"
    ),
    "move_failures_valid": "move_failures >= 0",
    "move_error_valid": f"last_move_error IS NULL OR last_move_error IN ({_MOVE_CODES})",
    "move_failure_fields": (
        "(move_failures = 0) = (last_move_error IS NULL) "
        "AND (move_failures = 0) = (last_move_failed_at IS NULL)"
    ),
    "move_failed_after_held": "last_move_failed_at IS NULL OR last_move_failed_at >= held_at",
    "source_ino_valid": "source_ino IS NULL OR source_ino >= 0",
    "isolated_has_source": "isolated_at IS NULL OR source_ino IS NOT NULL",
}
_COLUMNS = (
    "isolated_at",
    "releasing_at",
    "move_failures",
    "last_move_error",
    "last_move_failed_at",
    "source_ino",
)
# 新增與 run 的檢查和 0023 相同（終止狀態是當時的快照）；不用 RAISE 的 % 格式字串。
_INSERT = """
    IF TG_OP = 'INSERT' THEN
        IF NEW.resolved_at IS NOT NULL{extra_insert} THEN
            RAISE EXCEPTION USING
                ERRCODE = 'integrity_constraint_violation',
                MESSAGE = 'evidence_holds: a new hold must be unresolved{insert_detail}';
        END IF;{source_check}
        NEW.held_at := clock_timestamp();
        IF NEW.scanner_run_id IS NULL THEN
            IF EXISTS (SELECT 1 FROM public.scanner_runs AS run WHERE run.id = NEW.directory) THEN
                RAISE EXCEPTION USING
                    ERRCODE = 'integrity_constraint_violation',
                    MESSAGE = 'evidence_holds: a known run must be held as that run';
            END IF;
            RETURN NEW;
        END IF;
        PERFORM pg_advisory_xact_lock(23012, hashtext(NEW.scanner_run_id::text));
        IF NOT EXISTS (
            SELECT 1 FROM public.scanner_runs AS run
            WHERE run.id = NEW.scanner_run_id
                AND run.status IN ('cancelled', 'failed', 'interrupted', 'succeeded', 'timed_out')
                AND (run.container_name IS NULL OR run.container_removed_at IS NOT NULL)
        ) OR EXISTS (
            SELECT 1 FROM public.run_evidence AS evidence
            WHERE evidence.scanner_run_id = NEW.scanner_run_id
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'integrity_constraint_violation',
                MESSAGE = 'evidence_holds: the run must be finished, its container removed and its '
                    || 'evidence not yet recorded';
        END IF;
        RETURN NEW;
    END IF;"""
_RESOLVE = """
        NEW.resolved_at := clock_timestamp();
        IF NEW.scanner_run_id IS NULL OR EXISTS (
            SELECT 1 FROM public.run_evidence AS evidence
            WHERE evidence.scanner_run_id = NEW.scanner_run_id AND evidence.status = 'sealed'
        ) THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'evidence_holds: a run can only be resolved after its evidence is sealed';"""
_V24_INSERT = _INSERT.format(
    extra_insert=(
        " OR NEW.isolated_at IS NOT NULL OR NEW.releasing_at IS NOT NULL\n"
        "            OR NEW.move_failures <> 0 OR NEW.last_move_error IS NOT NULL\n"
        "            OR NEW.last_move_failed_at IS NOT NULL"
    ),
    insert_detail=", not yet isolated and without move failures",
    source_check="""
        IF NEW.source_ino IS NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = 'integrity_constraint_violation',
                MESSAGE = 'evidence_holds: a new hold must record the inode of its directory';
        END IF;""",
)
_GUARD = f"""
CREATE OR REPLACE FUNCTION evidence_holds_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN{_V24_INSERT}
    IF TG_OP = 'UPDATE' AND OLD.resolved_at IS NULL THEN
        -- 0. 記錄來源 inode（v0024 之前留下、還沒隔離完成的紀錄）。
        IF OLD.source_ino IS NULL AND NEW.source_ino IS NOT NULL AND OLD.isolated_at IS NULL
            AND to_jsonb(NEW) - 'source_ino' = to_jsonb(OLD) - 'source_ino'
        THEN
            RETURN NEW;
        END IF;
        -- 1. 記錄搬移失敗：還沒隔離完成，次數剛好加 1，時間由這裡寫入。
        IF OLD.isolated_at IS NULL AND NEW.move_failures = OLD.move_failures + 1
            AND NEW.last_move_error IS NOT NULL
            AND to_jsonb(NEW) - ARRAY['move_failures', 'last_move_error', 'last_move_failed_at']
                = to_jsonb(OLD) - ARRAY['move_failures', 'last_move_error', 'last_move_failed_at']
        THEN
            NEW.last_move_failed_at := clock_timestamp();
            RETURN NEW;
        END IF;
        -- 2. 隔離完成：目錄已搬到 held/，必須已有來源 inode。
        IF OLD.isolated_at IS NULL AND NEW.isolated_at IS NOT NULL AND OLD.source_ino IS NOT NULL
            AND to_jsonb(NEW) - 'isolated_at' = to_jsonb(OLD) - 'isolated_at'
        THEN
            NEW.isolated_at := clock_timestamp();
            RETURN NEW;
        END IF;
        -- 3. 開始解除：已隔離完成，retry-evidence 已在 held/ 加密並驗證。
        IF OLD.releasing_at IS NULL AND NEW.releasing_at IS NOT NULL
            AND OLD.isolated_at IS NOT NULL
            AND to_jsonb(NEW) - 'releasing_at' = to_jsonb(OLD) - 'releasing_at'
        THEN
            NEW.releasing_at := clock_timestamp();
            RETURN NEW;
        END IF;
        -- 4. 解除：必須已開始解除，run 的目錄必須已有 sealed 的 run_evidence。
        IF NEW.resolved_at IS NOT NULL AND OLD.releasing_at IS NOT NULL
            AND to_jsonb(NEW) - 'resolved_at' = to_jsonb(OLD) - 'resolved_at'
        THEN{_RESOLVE}
        END IF;
    END IF;
    RAISE EXCEPTION USING
        ERRCODE = 'integrity_constraint_violation',
        MESSAGE = 'evidence_holds: ' || TG_OP || ' blocked; only the recorded isolation steps '
            || 'are allowed';
END;
$$
"""
# downgrade 還原的 0023 函式（同 0023 的內容）。
_V23_GUARD = f"""
CREATE OR REPLACE FUNCTION evidence_holds_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN{_INSERT.format(extra_insert="", insert_detail="", source_check="")}
    IF TG_OP = 'UPDATE' AND OLD.resolved_at IS NULL AND NEW.resolved_at IS NOT NULL
        AND to_jsonb(NEW) - 'resolved_at' = to_jsonb(OLD) - 'resolved_at'
    THEN{_RESOLVE}
    END IF;
    RAISE EXCEPTION USING
        ERRCODE = 'integrity_constraint_violation',
        MESSAGE = 'evidence_holds: ' || TG_OP || ' blocked; a hold can only be resolved once';
END;
$$
"""
_REFUSE_ISOLATION = """
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM evidence_holds
        WHERE source_ino IS NOT NULL OR isolated_at IS NOT NULL OR releasing_at IS NOT NULL
            OR move_failures <> 0
    ) OR EXISTS (
        SELECT 1 FROM audit_events
        WHERE action IN (
            'runs_layout.migrate', 'runs_layout.migrated', 'runs_layout.migrate_failed'
        )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'object_in_use',
            MESSAGE = 'evidence_holds: isolation records or a runs layout migration exist; the '
                || 'previous version does not know active/ and held/ and would treat moved '
                || 'directories as missing';
    END IF;
END;
$$
"""


def upgrade() -> None:
    op.add_column("evidence_holds", sa.Column("isolated_at", sa.DateTime(timezone=True)))
    op.add_column("evidence_holds", sa.Column("releasing_at", sa.DateTime(timezone=True)))
    op.add_column(
        "evidence_holds",
        sa.Column("move_failures", sa.Integer(), server_default=sa.text("0"), nullable=False),
    )
    op.add_column("evidence_holds", sa.Column("last_move_error", sa.String(32)))
    op.add_column("evidence_holds", sa.Column("last_move_failed_at", sa.DateTime(timezone=True)))
    op.add_column("evidence_holds", sa.Column("source_ino", sa.BigInteger()))
    for name, condition in _CHECKS.items():
        op.create_check_constraint(op.f(f"ck_evidence_holds_{name}"), "evidence_holds", condition)
    op.execute(_GUARD)


def downgrade() -> None:
    op.execute("LOCK TABLE evidence_holds IN ACCESS EXCLUSIVE MODE")
    op.execute(_REFUSE_ISOLATION)
    op.execute(_V23_GUARD)
    for name in _CHECKS:
        op.drop_constraint(op.f(f"ck_evidence_holds_{name}"), "evidence_holds", type_="check")
    for column in reversed(_COLUMNS):
        op.drop_column("evidence_holds", column)
