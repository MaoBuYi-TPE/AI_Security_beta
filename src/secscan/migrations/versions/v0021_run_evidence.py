"""原始證據的保護狀態（T23a；docs/DECISIONS.md §30.3）。

Revision ID: 0021
Revises: 0020
Create Date: 2026-11-09 12:00:00+00:00

升降級說明：
- upgrade：
  - 新增 run_evidence：每個 run 一列（主鍵 scanner_run_id，以 (scanner_run_id, scan_id) 引用
    scanner_runs），記下 runs volume 中這個 run 的目錄是 none（從來沒有目錄）、sealed（只剩加密檔）
    或 purged（保留期限到了已刪除），以及加密、清除的時間與數量。沒有紀錄就是 pending。
  - CHECK：狀態的清單；none 沒有加密時間與數量；purged 才有清除時間，而且不早於加密時間。
  - 部分索引 ix_run_evidence_sealed：清除時找加密時間已過期的目錄。
  - trigger run_evidence_guard：
    - 新增：狀態只能是 none 或 sealed；run 必須已終止，而且沒有容器或容器已確認刪除
      （之後沒有任何程序會再寫這個目錄）。
    - 修改：只允許 sealed → purged 一次（寫入清除時間，不晚於現在），其他欄位完全不變（to_jsonb
      比較）。
    - 刪除、TRUNCATE：一律拒絕。
  - 既有的資料不回填：升級之後 runner 的 keeper 會分批加密既有的 run 目錄（第一次加密時才開始
    計算 7 天的保留期限），不會一升級就刪除。
  - 錯誤碼 PARSE_DEADLINE_EXCEEDED 不需要 migration：scanner_runs 的 CHECK 只檢查錯誤碼的格式。
- 升級時先停 api、worker 與 runner：建立外鍵會鎖住 scanner_runs（SHARE ROW EXCLUSIVE），而
  make migrate 讓 0021 與 0022 在同一個 transaction 中執行，鎖會持有到 0022 加密完既有的報告
  （資料庫審查 L1）。
- downgrade：先以 ACCESS EXCLUSIVE 鎖住資料表再檢查（檢查與刪除之間不會有新紀錄）。已經有 sealed 或
  purged 的紀錄時拒絕：舊程式不認得加密檔（會把它們報成未加密、也不會清除）；purged 的紀錄刪掉
  之後再升級，已清除的 run 會被記成「從來沒有目錄」。否則刪除 trigger、函式與資料表。只用於開發與
  測試。
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0021"
down_revision: str | Sequence[str] | None = "0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# 和 scans/evidence_models.py 相同的內容（migration 不 import 應用程式的程式）。
_CHECKS = {
    "status_valid": "status IN ('none', 'purged', 'sealed')",
    "sealed_matches_status": "(status = 'none') = (sealed_at IS NULL)",
    "purged_matches_status": "(status = 'purged') = (purged_at IS NOT NULL)",
    "purged_after_sealed": "purged_at IS NULL OR purged_at >= sealed_at",
    "counts_valid": (
        "file_count >= 0 AND plaintext_bytes >= 0 "
        "AND (status <> 'none' OR (file_count = 0 AND plaintext_bytes = 0))"
    ),
}
# 不用 RAISE 的 % 格式字串（SQLAlchemy 會跳脫文字 SQL 裡的 %）；固定 search_path（同 0009）。
# 終止狀態和 0005 相同（migration 是當時的快照，固定的字面值）。
_GUARD = """
CREATE FUNCTION run_evidence_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status NOT IN ('none', 'sealed') OR NEW.purged_at IS NOT NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = 'integrity_constraint_violation',
                MESSAGE = 'run_evidence: a new record must be none or sealed';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM public.scanner_runs AS run
            WHERE run.id = NEW.scanner_run_id
                AND run.status IN ('cancelled', 'failed', 'interrupted', 'succeeded', 'timed_out')
                AND (run.container_name IS NULL OR run.container_removed_at IS NOT NULL)
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'integrity_constraint_violation',
                MESSAGE = 'run_evidence: the run must be finished and its container removed';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF OLD.status = 'sealed' AND NEW.status = 'purged' AND NEW.purged_at IS NOT NULL
            AND NEW.purged_at <= clock_timestamp()
            AND to_jsonb(NEW) - 'status' - 'purged_at' = to_jsonb(OLD) - 'status' - 'purged_at'
        THEN
            RETURN NEW;
        END IF;
    END IF;
    RAISE EXCEPTION USING
        ERRCODE = 'integrity_constraint_violation',
        MESSAGE = 'run_evidence: ' || TG_OP || ' blocked; a record can only be purged once';
END;
$$
"""
_TRIGGERS = (
    "CREATE TRIGGER run_evidence_guard BEFORE INSERT OR UPDATE OR DELETE ON run_evidence "
    "FOR EACH ROW EXECUTE FUNCTION run_evidence_guard()",
    "CREATE TRIGGER run_evidence_no_truncate BEFORE TRUNCATE ON run_evidence "
    "FOR EACH STATEMENT EXECUTE FUNCTION run_evidence_guard()",
)
_REFUSE_SEALED = """
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM run_evidence WHERE status IN ('sealed', 'purged')) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'object_in_use',
            MESSAGE = 'run_evidence: recorded evidence exists; the previous version cannot read or '
                || 'purge sealed directories, and purged runs would later look like they never '
                || 'had one';
    END IF;
END;
$$
"""


def upgrade() -> None:
    op.create_table(
        "run_evidence",
        sa.Column("scanner_run_id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("file_count", sa.Integer(), nullable=False),
        sa.Column("plaintext_bytes", sa.BigInteger(), nullable=False),
        sa.Column("sealed_at", sa.DateTime(timezone=True)),
        sa.Column("purged_at", sa.DateTime(timezone=True)),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.clock_timestamp(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("scanner_run_id", name=op.f("pk_run_evidence")),
        sa.ForeignKeyConstraint(
            ["scanner_run_id", "scan_id"],
            ["scanner_runs.id", "scanner_runs.scan_id"],
            name=op.f("fk_run_evidence_scanner_run_id_scan_id_scanner_runs"),
            ondelete="RESTRICT",
        ),
        *(
            sa.CheckConstraint(condition, name=op.f(f"ck_run_evidence_{name}"))
            for name, condition in _CHECKS.items()
        ),
    )
    op.create_index(
        "ix_run_evidence_sealed",
        "run_evidence",
        ["sealed_at"],
        postgresql_where=sa.text("status = 'sealed'"),
    )
    op.execute(_GUARD)
    for trigger in _TRIGGERS:
        op.execute(trigger)


def downgrade() -> None:
    op.execute("LOCK TABLE run_evidence IN ACCESS EXCLUSIVE MODE")
    op.execute(_REFUSE_SEALED)
    op.drop_table("run_evidence")
    op.execute("DROP FUNCTION run_evidence_guard()")
