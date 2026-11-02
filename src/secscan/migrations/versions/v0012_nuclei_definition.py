"""放寬 profile_definition_valid 讓 nuclei 也能記定義 sha256（T18；docs/DECISIONS.md §20.2、§23）。

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-01 12:00:00+00:00

升降級說明：
- upgrade：把 scanner_runs 的 CHECK ck_scanner_runs_profile_definition_valid 從 engine = 'zap'
  放寬成 engine IN ('zap', 'nuclei')。Postgres 不能就地改 CHECK，先 drop 再以放寬後的條件 create。
  其餘條件不變（sha256 格式、要和 plan_hash 一起）。既有資料列不受影響（zap 的仍合法，nuclei 的
  之前都是 null）。凍結用的 trigger scanner_runs_plan_once 與引擎無關，不動。
- downgrade：改回只允許 engine = 'zap'。若已有 nuclei 的 profile_definition_sha256，重建 CHECK 會
  失敗而中止（那些資料列違反收緊後的條件）；因為 scanner_runs_plan_once trigger 會擋住把已寫入的
  欄位清成 null，實務上得先停掉該 trigger 再清，只用於開發與測試。
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0012"
down_revision: str | Sequence[str] | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# 和 scans/models.py 相同的內容（migration 不 import 應用程式的程式）。
_SHA256_HEX = "^[0-9a-f]{64}$"
_NAME = "profile_definition_valid"
_ZAP_ONLY = (
    "profile_definition_sha256 IS NULL "
    f"OR (profile_definition_sha256 ~ '{_SHA256_HEX}' AND engine = 'zap' "
    "AND plan_hash IS NOT NULL)"
)
_ZAP_AND_NUCLEI = (
    "profile_definition_sha256 IS NULL "
    f"OR (profile_definition_sha256 ~ '{_SHA256_HEX}' AND engine IN ('zap', 'nuclei') "
    "AND plan_hash IS NOT NULL)"
)


def _replace_constraint(condition: str) -> None:
    op.drop_constraint(op.f(f"ck_scanner_runs_{_NAME}"), "scanner_runs", type_="check")
    op.create_check_constraint(op.f(f"ck_scanner_runs_{_NAME}"), "scanner_runs", condition)


def upgrade() -> None:
    _replace_constraint(_ZAP_AND_NUCLEI)


def downgrade() -> None:
    _replace_constraint(_ZAP_ONLY)
