"""需要人工處理的原始證據（T23a 方案 B；docs/DECISIONS.md §30.12）。

Revision ID: 0023
Revises: 0022
Create Date: 2026-11-10 12:00:00+00:00

升降級說明：
- upgrade：
  - 新增 evidence_holds：runs volume 中一個目錄連續超過深度或條目數的上限而加密失敗時，keeper 新增
    一列（主鍵 directory，就是目錄名稱）。run 的目錄以 (scanner_run_id, scan_id) 引用 scanner_runs
    （scanner_run_id 就是 directory）；孤兒目錄兩者都是 NULL。記下錯誤代碼、隔離之前連續失敗的次數、
    隔離時間，以及人工重試加密成功的時間（resolved_at）。
  - CHECK：run 的兩個欄位同時有或同時沒有；scanner_run_id 等於 directory；錯誤代碼的清單；次數至少
    1；解除不早於隔離。
  - 部分索引 ix_evidence_holds_active：retention-status 列出還沒解除的隔離。外鍵不另建索引：
    scanner_runs 的刪除與身分欄位的修改都被 scanner_runs_guard 拒絕，參照端的檢查不會執行，而且
    scanner_run_id 等於主鍵 directory（資料庫審查 L4）。
  - trigger evidence_holds_guard：
    - 新增：還沒解除。run 的目錄：run 已終止、沒有容器或容器已確認刪除，而且還沒有 run_evidence
      （隔離的 run 不能被記成 none、sealed 或 purged）。孤兒目錄：scanner_runs 中沒有這個 id。
    - 修改：只允許 resolved_at 由 NULL 寫入一次，其他欄位完全不變（to_jsonb 比較）；run 的目錄
      必須已有 sealed 的 run_evidence（同一個 transaction 先寫入），所以不可能沒有加密就解除。
      孤兒目錄的加密 DB 無法確認，由 retry-evidence 保證（§30.12 的剩餘風險）。
    - held_at 與 resolved_at 一律由 trigger 以 clock_timestamp() 寫入，不採用用戶端的值（稽核時間
      不能回溯；資料庫審查 L6）。
    - 刪除、TRUNCATE：一律拒絕（隔離紀錄是處置的依據）。
  - 反方向（資料庫審查 M1）：run_evidence 新增 deferred constraint trigger run_evidence_hold_check：
    commit 時這個 run 還有沒解除的隔離就拒絕（retry-evidence 在同一個 transaction 先寫
    run_evidence、再解除，commit 時已解除）。新增隔離與新增 run_evidence 都先取得以 run 為鍵的交易
    層級 advisory lock（兩個 int4 的鍵，和 keeper 的 bigint 鍵不重疊），兩者不會同時 commit 而都看
    不到對方。run_evidence 的欄位、CHECK 與 0021 的 run_evidence_guard 都不變；不需要回填（升級之前
    沒有隔離）。
- 升級時先停 api、worker 與 runner：建立外鍵會鎖住 scanner_runs（SHARE ROW EXCLUSIVE）。
- downgrade：先依讀取端的順序以 ACCESS EXCLUSIVE 鎖住 scanner_runs、run_evidence 與 evidence_holds
  再檢查（刪除帶外鍵的資料表也要鎖 scanner_runs；資料庫審查 L3）；同樣先停 api、worker 與 runner。
  有任何紀錄就拒絕：舊程式不認得隔離，會把隔離的 run 當成待加密、讓 keeper 再次一直失敗，已解除的
  紀錄也是處置的稽核依據。否則刪除 trigger、函式與資料表。只用於開發與測試。
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0023"
down_revision: str | Sequence[str] | None = "0022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# 和 scans/evidence_models.py 相同的內容（migration 不 import 應用程式的程式）。
_CHECKS = {
    "run_columns_paired": "(scanner_run_id IS NULL) = (scan_id IS NULL)",
    "directory_is_run": "scanner_run_id IS NULL OR scanner_run_id = directory",
    "error_code_valid": (
        "error_code IN ('EVIDENCE_TREE_TOO_DEEP', 'EVIDENCE_TREE_TOO_MANY_ENTRIES')"
    ),
    "attempts_positive": "attempts >= 1",
    "resolved_after_held": "resolved_at IS NULL OR resolved_at >= held_at",
}
# 不用 RAISE 的 % 格式字串（SQLAlchemy 會跳脫文字 SQL 裡的 %）；固定 search_path（同 0009）。
# 終止狀態和 0005、0021 相同（migration 是當時的快照，固定的字面值）。
# 兩個函式都先取得以 run 為鍵的交易層級 advisory lock（23012, hashtext(run_id)）：兩個 int4 的鍵
# （第一個是固定的類別），和 keeper 以一個 bigint 為鍵的 session lock 不在同一個鍵空間。
_GUARD = """
CREATE FUNCTION evidence_holds_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.resolved_at IS NOT NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = 'integrity_constraint_violation',
                MESSAGE = 'evidence_holds: a new hold must be unresolved';
        END IF;
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
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.resolved_at IS NULL AND NEW.resolved_at IS NOT NULL
        AND to_jsonb(NEW) - 'resolved_at' = to_jsonb(OLD) - 'resolved_at'
    THEN
        NEW.resolved_at := clock_timestamp();
        IF NEW.scanner_run_id IS NULL OR EXISTS (
            SELECT 1 FROM public.run_evidence AS evidence
            WHERE evidence.scanner_run_id = NEW.scanner_run_id AND evidence.status = 'sealed'
        ) THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'evidence_holds: a run can only be resolved after its evidence is sealed';
    END IF;
    RAISE EXCEPTION USING
        ERRCODE = 'integrity_constraint_violation',
        MESSAGE = 'evidence_holds: ' || TG_OP || ' blocked; a hold can only be resolved once';
END;
$$
"""
_HOLD_CHECK = """
CREATE FUNCTION run_evidence_hold_check() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(23012, hashtext(NEW.scanner_run_id::text));
    IF EXISTS (
        SELECT 1 FROM public.evidence_holds AS hold
        WHERE hold.directory = NEW.scanner_run_id AND hold.resolved_at IS NULL
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'run_evidence: a held run can only be recorded while resolving its hold';
    END IF;
    RETURN NULL;
END;
$$
"""
_TRIGGERS = (
    "CREATE TRIGGER evidence_holds_guard BEFORE INSERT OR UPDATE OR DELETE ON evidence_holds "
    "FOR EACH ROW EXECUTE FUNCTION evidence_holds_guard()",
    "CREATE TRIGGER evidence_holds_no_truncate BEFORE TRUNCATE ON evidence_holds "
    "FOR EACH STATEMENT EXECUTE FUNCTION evidence_holds_guard()",
    "CREATE CONSTRAINT TRIGGER run_evidence_hold_check AFTER INSERT ON run_evidence "
    "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION run_evidence_hold_check()",
)
_REFUSE_HOLDS = """
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM evidence_holds) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'object_in_use',
            MESSAGE = 'evidence_holds: holds exist; the previous version would retry held '
                || 'directories forever, and resolved holds are the audit trail of the handling';
    END IF;
END;
$$
"""


def upgrade() -> None:
    op.create_table(
        "evidence_holds",
        sa.Column("directory", sa.Uuid(), nullable=False),
        sa.Column("scanner_run_id", sa.Uuid()),
        sa.Column("scan_id", sa.Uuid()),
        sa.Column("error_code", sa.String(32), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column(
            "held_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.clock_timestamp(),
            nullable=False,
        ),
        sa.Column("resolved_at", sa.DateTime(timezone=True)),
        sa.PrimaryKeyConstraint("directory", name=op.f("pk_evidence_holds")),
        sa.ForeignKeyConstraint(
            ["scanner_run_id", "scan_id"],
            ["scanner_runs.id", "scanner_runs.scan_id"],
            name=op.f("fk_evidence_holds_scanner_run_id_scan_id_scanner_runs"),
            ondelete="RESTRICT",
        ),
        *(
            sa.CheckConstraint(condition, name=op.f(f"ck_evidence_holds_{name}"))
            for name, condition in _CHECKS.items()
        ),
    )
    op.create_index(
        "ix_evidence_holds_active",
        "evidence_holds",
        ["held_at"],
        postgresql_where=sa.text("resolved_at IS NULL"),
    )
    op.execute(_GUARD)
    op.execute(_HOLD_CHECK)
    for trigger in _TRIGGERS:
        op.execute(trigger)


def downgrade() -> None:
    op.execute("LOCK TABLE scanner_runs, run_evidence, evidence_holds IN ACCESS EXCLUSIVE MODE")
    op.execute(_REFUSE_HOLDS)
    op.execute("DROP TRIGGER run_evidence_hold_check ON run_evidence")
    op.execute("DROP FUNCTION run_evidence_hold_check()")
    op.drop_table("evidence_holds")
    op.execute("DROP FUNCTION evidence_holds_guard()")
