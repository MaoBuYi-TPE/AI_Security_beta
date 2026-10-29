"""preflight 的 run 與結果、轉送的請求涵蓋的 operation（T12；docs/DECISIONS.md §16.5、§16.6）。

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-29 12:00:00+00:00

升降級說明：
- upgrade：
  - scanner_runs 的 engine 多一個 preflight，sequence 的上限從 4 改成 5（重建兩個 CHECK）。
  - scanner_runs 新增 preflight_result：只有 preflight 的 run 可以有值，值是五種結果之一。
  - scanner_runs 新增 coverage_recorded（預設 false）：worker 已把這個 run 的 telemetry 對應到
    operation（沒有 telemetry 時維持 false，coverage 就不算有量測依據）。
  - 建立 run_coverage：一個 run 轉送的請求涵蓋的 operation（scan 凍結的 operation），以及是否
    帶著認證 header。資料列不可修改、刪除或 TRUNCATE（沿用 scan_records_guard）。
- downgrade：刪除 run_coverage 與 preflight_result，CHECK 改回原本的內容。**已有 preflight
  的 run 會讓 downgrade 失敗**（CHECK 不允許 preflight）：只用於開發與測試，正式環境不要
  downgrade。
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | Sequence[str] | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# 和 scans/models.py 相同的內容（migration 不 import 應用程式的程式）。
_ENGINES_BEFORE = "'zap', 'nuclei', 'schemathesis', 'fake'"
_ENGINES = "'zap', 'nuclei', 'schemathesis', 'fake', 'preflight'"
_RESULTS = "'passed', 'failed', 'inconclusive', 'blocked', 'not_executed'"
_PREFLIGHT_RESULT = (
    f"preflight_result IS NULL OR (engine = 'preflight' AND preflight_result IN ({_RESULTS}))"
)


def upgrade() -> None:
    _replace_run_checks(engines=_ENGINES, sequences=5)
    op.add_column("scanner_runs", sa.Column("preflight_result", sa.String(32), nullable=True))
    op.create_check_constraint(
        op.f("ck_scanner_runs_preflight_result_valid"), "scanner_runs", _PREFLIGHT_RESULT
    )
    op.add_column(
        "scanner_runs",
        sa.Column(
            "coverage_recorded", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
    )
    op.create_table(
        "run_coverage",
        sa.Column("scanner_run_id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("authenticated", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["scanner_run_id", "scan_id"],
            ["scanner_runs.id", "scanner_runs.scan_id"],
            name=op.f("fk_run_coverage_scanner_run_id_scanner_runs"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["scan_id", "ordinal"],
            ["scan_operations.scan_id", "scan_operations.ordinal"],
            name=op.f("fk_run_coverage_scan_id_scan_operations"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("scanner_run_id", "ordinal", name=op.f("pk_run_coverage")),
    )
    op.create_index("ix_run_coverage_scan_id", "run_coverage", ["scan_id"], unique=False)
    op.execute(
        "CREATE TRIGGER run_coverage_immutable BEFORE UPDATE OR DELETE ON run_coverage "
        "FOR EACH ROW EXECUTE FUNCTION scan_records_guard()"
    )
    op.execute(
        "CREATE TRIGGER run_coverage_no_truncate BEFORE TRUNCATE ON run_coverage "
        "FOR EACH STATEMENT EXECUTE FUNCTION scan_records_guard()"
    )


def downgrade() -> None:
    op.drop_index("ix_run_coverage_scan_id", table_name="run_coverage")
    op.drop_table("run_coverage")
    op.drop_column("scanner_runs", "coverage_recorded")
    op.drop_constraint(
        op.f("ck_scanner_runs_preflight_result_valid"), "scanner_runs", type_="check"
    )
    op.drop_column("scanner_runs", "preflight_result")
    _replace_run_checks(engines=_ENGINES_BEFORE, sequences=4)


def _replace_run_checks(*, engines: str, sequences: int) -> None:
    for name in ("engine_valid", "sequence_valid"):
        op.drop_constraint(op.f(f"ck_scanner_runs_{name}"), "scanner_runs", type_="check")
    op.create_check_constraint(
        op.f("ck_scanner_runs_engine_valid"), "scanner_runs", f"engine IN ({engines})"
    )
    op.create_check_constraint(
        op.f("ck_scanner_runs_sequence_valid"),
        "scanner_runs",
        f"sequence BETWEEN 1 AND {sequences}",
    )
