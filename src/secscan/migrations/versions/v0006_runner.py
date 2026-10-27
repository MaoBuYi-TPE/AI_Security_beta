"""runner：scanner_runs 的容器與映像、runner_instances（T10）。

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-27 09:00:00+00:00

升降級說明：
- upgrade：
  - scanner_runs 新增 container_name、image_ref（可為 null：in-process 的 fake runner 沒有容器）。
    CHECK：名稱一定是 secscan-run-<id>、映像有 tag 與 digest、兩者同時有值或同時為 null、
    排隊中與 preparing 沒有容器。既有的資料列兩欄都是 null，符合所有 CHECK。
  - trigger scanner_runs_container_guard（docs/DECISIONS.md §14.6）：兩欄只能在 preparing → running
    的那一次從 null 寫入，之後不能改，也不能清除。
  - 建立 runner_instances（runner 與 worker 的心跳與能力，owner 唯一）。
- downgrade：刪除 runner_instances、trigger 與函式、scanner_runs 的兩欄及其 CHECK，**已記錄的容器
  名稱與映像、所有心跳列都會消失**。只用於開發與測試，正式環境不要 downgrade。
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006"
down_revision: str | Sequence[str] | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# 和 scans/models.py、scanners/models.py 相同的內容（migration 不 import 應用程式的程式）。
_IMAGE_REF_PATTERN = (
    "^[a-z0-9][a-z0-9._/:-]{0,180}:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}@sha256:[0-9a-f]{64}$"
)
_RUN_CHECKS = (
    (
        "container_matches_run",
        "container_name IS NULL OR container_name = 'secscan-run-' || id::text",
    ),
    ("image_ref_valid", f"image_ref IS NULL OR image_ref ~ '{_IMAGE_REF_PATTERN}'"),
    ("container_with_image", "(container_name IS NULL) = (image_ref IS NULL)"),
    (
        "container_after_start",
        "container_name IS NULL OR status NOT IN ('queued', 'preparing')",
    ),
)

# 不用 RAISE 的 % 格式字串（SQLAlchemy 會跳脫文字 SQL 裡的 %）；固定 search_path。
_CREATE_CONTAINER_GUARD = """
CREATE FUNCTION scanner_runs_container_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF (NEW.container_name, NEW.image_ref) IS NOT DISTINCT FROM (OLD.container_name, OLD.image_ref)
    THEN
        RETURN NEW;
    END IF;
    IF OLD.container_name IS NULL AND OLD.image_ref IS NULL
        AND OLD.status = 'preparing' AND NEW.status = 'running'
    THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION USING
        ERRCODE = 'integrity_constraint_violation',
        MESSAGE = 'scanner_runs: container_name and image_ref can only be recorded once, '
            || 'when the run starts';
END;
$$
"""


def upgrade() -> None:
    op.add_column("scanner_runs", sa.Column("container_name", sa.String(length=64), nullable=True))
    op.add_column("scanner_runs", sa.Column("image_ref", sa.String(length=255), nullable=True))
    for name, condition in _RUN_CHECKS:
        op.create_check_constraint(op.f(f"ck_scanner_runs_{name}"), "scanner_runs", condition)
    op.execute(_CREATE_CONTAINER_GUARD)
    # BEFORE trigger 依名稱的字母順序執行：這個在 scanner_runs_guard_rows 之前。
    op.execute(
        "CREATE TRIGGER scanner_runs_container_guard BEFORE UPDATE ON scanner_runs "
        "FOR EACH ROW EXECUTE FUNCTION scanner_runs_container_guard()"
    )
    op.create_table(
        "runner_instances",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("owner", sa.String(length=128), nullable=False),
        sa.Column("software_version", sa.String(length=64), nullable=False),
        sa.Column("capabilities", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "role IN ('runner', 'worker')", name=op.f("ck_runner_instances_role_valid")
        ),
        sa.CheckConstraint(
            "char_length(btrim(owner)) > 0", name=op.f("ck_runner_instances_owner_not_blank")
        ),
        sa.CheckConstraint(
            "char_length(btrim(software_version)) > 0",
            name=op.f("ck_runner_instances_software_version_not_blank"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(capabilities) = 'object' AND octet_length(capabilities::text) <= 4096",
            name=op.f("ck_runner_instances_capabilities_valid"),
        ),
        sa.CheckConstraint("heartbeat_at >= created_at", name=op.f("ck_runner_instances_times")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_runner_instances")),
        sa.UniqueConstraint("owner", name=op.f("uq_runner_instances_owner")),
    )
    op.create_index(
        "ix_runner_instances_role_heartbeat_at",
        "runner_instances",
        ["role", "heartbeat_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_runner_instances_role_heartbeat_at", table_name="runner_instances")
    op.drop_table("runner_instances")
    op.execute("DROP TRIGGER scanner_runs_container_guard ON scanner_runs")
    op.execute("DROP FUNCTION scanner_runs_container_guard()")
    for name, _condition in reversed(_RUN_CHECKS):
        op.drop_constraint(op.f(f"ck_scanner_runs_{name}"), "scanner_runs", type_="check")
    op.drop_column("scanner_runs", "image_ref")
    op.drop_column("scanner_runs", "container_name")
