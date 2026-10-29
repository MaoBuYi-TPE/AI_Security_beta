"""共享預算：scanner_runs 分到的請求數與實際用量（T12；docs/DECISIONS.md §16.4）。

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-29 09:00:00+00:00

升降級說明：
- upgrade：scanner_runs 新增四個可為 null 的非負整數欄位：
  - requests_allotted：run 開始時分到的請求數（scan 的上限減去之前的 run 用掉的）。
  - requests_sent、requests_denied：guard 的 telemetry 記下的轉送與拒絕數（run 結束前寫入）。
  - traffic_seconds：容器啟動到停止的秒數。
  CHECK：都不可為負數；有 requests_sent 就一定有 requests_allotted，而且不超過它。
  既有的資料列都是 null，符合所有 CHECK（之後的 run 把 null 的用量當成 0）。
- downgrade：刪除四欄與 CHECK，**已記錄的用量會消失**；只用於開發與測試。
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | Sequence[str] | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COLUMNS = ("requests_allotted", "requests_sent", "requests_denied", "traffic_seconds")
# 和 scans/models.py 相同的內容（migration 不 import 應用程式的程式）。
_CHECKS = (
    (
        "usage_not_negative",
        "(requests_allotted IS NULL OR requests_allotted >= 0) "
        "AND (requests_sent IS NULL OR requests_sent >= 0) "
        "AND (requests_denied IS NULL OR requests_denied >= 0) "
        "AND (traffic_seconds IS NULL OR traffic_seconds >= 0)",
    ),
    (
        "sent_within_allotment",
        "requests_sent IS NULL OR (requests_allotted IS NOT NULL "
        "AND requests_sent <= requests_allotted)",
    ),
)


def upgrade() -> None:
    for column in _COLUMNS:
        op.add_column("scanner_runs", sa.Column(column, sa.Integer(), nullable=True))
    for name, condition in _CHECKS:
        op.create_check_constraint(op.f(f"ck_scanner_runs_{name}"), "scanner_runs", condition)


def downgrade() -> None:
    for name, _ in reversed(_CHECKS):
        op.drop_constraint(op.f(f"ck_scanner_runs_{name}"), "scanner_runs", type_="check")
    for column in reversed(_COLUMNS):
        op.drop_column("scanner_runs", column)
