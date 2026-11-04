"""findings 加上 category（T19 的簽核；docs/DECISIONS.md §25.14）。

Revision ID: 0014
Revises: 0013
Create Date: 2026-11-04 12:00:00+00:00

升降級說明：
- upgrade：findings 新增 `category`（kind 之下的分類：vulnerability、misconfiguration、technology、
  detection、hardening，fallback 是 unclassified）與 CHECK `ck_findings_category_valid`（值合法、和
  kind 一致）。既有的資料列以 ADD COLUMN 的預設值填成 unclassified（PostgreSQL 直接填入，不經
  UPDATE，所以 findings_guard 不會擋），再移除預設值：之後的寫入必須明確給值。category 和身分一樣
  不可修改（findings_guard 比對整列，新欄位自動包含在內），所以回填的列一併標成 needs_review
  （只會往上，trigger 允許）：它們的分類沒有經過 v2 的審查，人工確認之前和審查過的 finding 分開
  統計（安全審查）。既有的 finding 都是開發與測試的資料；要乾淨的分類就重建開發 DB。
- downgrade：刪除 CHECK 與欄位，分類的資訊會消失；upgrade 標上的 needs_review 不會改回
  （trigger 只允許往上）。只用於開發與測試。
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: str | Sequence[str] | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# 和 findings/models.py 相同的內容（migration 不 import 應用程式的程式）。
_CHECK = "ck_findings_category_valid"
_CONDITION = (
    "category IN ('vulnerability', 'misconfiguration', 'technology', 'detection', 'hardening', "
    "'unclassified') AND (category = 'unclassified' "
    "OR (kind = 'security' AND category IN ('misconfiguration', 'vulnerability')) "
    "OR (kind = 'informational' AND category IN ('detection', 'hardening', 'technology')))"
)


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column(
            "category", sa.String(32), server_default=sa.text("'unclassified'"), nullable=False
        ),
    )
    op.alter_column("findings", "category", server_default=None)
    op.create_check_constraint(op.f(_CHECK), "findings", _CONDITION)
    op.execute("UPDATE findings SET needs_review = true WHERE NOT needs_review")


def downgrade() -> None:
    op.drop_constraint(op.f(_CHECK), "findings", type_="check")
    op.drop_column("findings", "category")
