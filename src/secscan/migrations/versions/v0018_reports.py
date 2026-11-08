"""平台產生的報告：worker 佇列與 DB 保存的內容（T21；docs/DECISIONS.md §28.5）。

Revision ID: 0018
Revises: 0017
Create Date: 2026-11-08 18:00:00+00:00

升降級說明：
- upgrade：
  - reports：queued → generating（認領，attempts +1、寫入 lease）→ generating（心跳）／queued（lease
    過期）／succeeded／failed。終止的列不可修改；不能刪除或 TRUNCATE。每個狀態有各自的欄位 CHECK。
    (project_id, idempotency_key) 唯一；queue_position 是 identity（FIFO）。
  - report_contents：內容（bytea，1 byte 到 8 MiB），只能在父列 generating 時寫入一次、
    之後不可修改。
  - report_contents 帶著寫入時的 attempt 與 lease_owner（DB 層的 fencing token）：只有目前持有
    未過期 lease 的那一次嘗試能寫入；心跳不能換 owner。
  - deferred constraint trigger 雙向核對：succeeded ⇒ 有這一次嘗試的內容，而且 SQL 算出的 sha256
    與大小等於 metadata；有內容 ⇒ commit 時父列是 succeeded。
  - T21 不刪除報告；T23a 以新的 migration 開放「只刪除到期報告」的路徑（report.create 的 audit
    保留）。
- downgrade：刪除兩張表、trigger 與函式；所有報告會消失，只用於開發與測試。
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0018"
down_revision: str | Sequence[str] | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

MAX_REPORT_BYTES = 8_388_608
_MUTABLE = (
    "status",
    "attempts",
    "lease_owner",
    "lease_expires_at",
    "heartbeat_at",
    "error_code",
    "data_as_of",
    "generated_at",
    "size_bytes",
    "sha256",
    "truncated",
    "omitted_findings",
    "finished_at",
)
_RESULT_NULL = (
    "data_as_of IS NULL AND generated_at IS NULL AND size_bytes IS NULL AND sha256 IS NULL "
    "AND truncated IS NULL AND omitted_findings IS NULL"
)
_LEASE_NULL = "lease_owner IS NULL AND lease_expires_at IS NULL AND heartbeat_at IS NULL"
_CHECKS = {
    "format_valid": "format IN ('json', 'markdown')",
    "schema_version_valid": "schema_version = 1",
    "status_valid": "status IN ('queued', 'generating', 'succeeded', 'failed')",
    "attempts_valid": "attempts >= 0 AND attempts <= 3",
    "idempotency_key_valid": "idempotency_key ~ '^[A-Za-z0-9_-]{16,128}$'",
    "request_sha256_length": "octet_length(request_sha256) = 32",
    # 單獨看不 NULL 安全；和各狀態的 shape CHECK 一起才完整（新增狀態時要補 shape）。
    "result_valid": (
        f"size_bytes IS NULL OR (size_bytes >= 1 AND size_bytes <= {MAX_REPORT_BYTES} "
        "AND sha256 ~ '^[0-9a-f]{64}$' AND omitted_findings >= 0 "
        "AND truncated = (omitted_findings > 0))"
    ),
    "queued_shape": (
        f"status <> 'queued' OR ({_LEASE_NULL} AND {_RESULT_NULL} "
        "AND error_code IS NULL AND finished_at IS NULL AND attempts < 3)"
    ),
    "generating_shape": (
        "status <> 'generating' OR (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL "
        f"AND attempts >= 1 AND {_RESULT_NULL} AND error_code IS NULL AND finished_at IS NULL)"
    ),
    "succeeded_shape": (
        f"status <> 'succeeded' OR ({_LEASE_NULL} AND data_as_of IS NOT NULL "
        "AND generated_at IS NOT NULL AND size_bytes IS NOT NULL AND sha256 IS NOT NULL "
        "AND truncated IS NOT NULL AND omitted_findings IS NOT NULL AND error_code IS NULL "
        "AND finished_at IS NOT NULL)"
    ),
    "failed_shape": (
        f"status <> 'failed' OR ({_LEASE_NULL} AND {_RESULT_NULL} "
        "AND error_code IS NOT NULL AND error_code ~ '^[A-Z][A-Z0-9_]{1,63}$' "
        "AND finished_at IS NOT NULL)"
    ),
}

_COLUMNS = ", ".join(f"'{column}'" for column in _MUTABLE)
_GUARD = (
    """
CREATE FUNCTION reports_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'queued' OR NEW.attempts <> 0 THEN
            RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
                MESSAGE = 'reports: new rows start queued with no attempts';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP <> 'UPDATE' THEN
        RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'reports rows cannot be removed (' || TG_OP || ' blocked)';
    END IF;
    IF (to_jsonb(NEW) - ARRAY["""
    + _COLUMNS
    + """]) IS DISTINCT FROM (to_jsonb(OLD) - ARRAY["""
    + _COLUMNS
    + """]) THEN
        RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'reports: only the status, lease and result can change';
    END IF;
    IF OLD.status IN ('succeeded', 'failed') THEN
        RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'reports: finished reports are immutable';
    END IF;
    IF OLD.status = 'queued' AND NEW.status = 'generating'
        AND NEW.attempts = OLD.attempts + 1 THEN
        RETURN NEW;
    END IF;
    -- 心跳不能換 owner：同一次嘗試的 lease 只屬於認領它的 worker。
    IF OLD.status = 'generating' AND NEW.status = 'generating'
        AND NEW.attempts = OLD.attempts AND NEW.lease_owner = OLD.lease_owner THEN
        RETURN NEW;
    END IF;
    IF OLD.status = 'generating' AND NEW.attempts = OLD.attempts
        AND NEW.status IN ('queued', 'succeeded', 'failed') THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
        MESSAGE = 'reports: transition not allowed';
END;
$$
"""
)
# DB 層的 fencing token：內容必須帶著目前這一次嘗試的 attempt 與 lease_owner，而且 lease 未過期。
# 被重新認領的舊 worker 即使繞過程式的 FOR UPDATE，也寫不進內容。
_CONTENT_INSERT = """
CREATE FUNCTION report_contents_insert_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM public.reports AS report
        WHERE report.id = NEW.report_id AND report.status = 'generating'
            AND report.attempts = NEW.attempt AND report.lease_owner = NEW.lease_owner
            AND report.lease_expires_at > clock_timestamp()
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'report_contents: content is written once by the current lease holder';
    END IF;
    RETURN NEW;
END;
$$
"""
_SUCCEEDED_CHECK = """
CREATE FUNCTION reports_content_check() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM public.report_contents AS stored
        WHERE stored.report_id = NEW.id
            AND stored.attempt = NEW.attempts
            AND encode(sha256(stored.content), 'hex') = NEW.sha256
            AND octet_length(stored.content) = NEW.size_bytes
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'reports: succeeded reports need content matching sha256 and size';
    END IF;
    RETURN NULL;
END;
$$
"""
_PARENT_CHECK = """
CREATE FUNCTION report_contents_parent_check() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM public.reports AS report
        WHERE report.id = NEW.report_id AND report.status = 'succeeded'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'report_contents: content needs a succeeded report at commit';
    END IF;
    RETURN NULL;
END;
$$
"""
_TRIGGERS = (
    "CREATE TRIGGER reports_guard BEFORE INSERT OR UPDATE OR DELETE ON reports "
    "FOR EACH ROW EXECUTE FUNCTION reports_guard()",
    "CREATE TRIGGER reports_no_truncate BEFORE TRUNCATE ON reports "
    "FOR EACH STATEMENT EXECUTE FUNCTION scan_records_guard()",
    "CREATE TRIGGER report_contents_insert_guard BEFORE INSERT ON report_contents "
    "FOR EACH ROW EXECUTE FUNCTION report_contents_insert_guard()",
    "CREATE TRIGGER report_contents_immutable BEFORE UPDATE OR DELETE ON report_contents "
    "FOR EACH ROW EXECUTE FUNCTION scan_records_guard()",
    "CREATE TRIGGER report_contents_no_truncate BEFORE TRUNCATE ON report_contents "
    "FOR EACH STATEMENT EXECUTE FUNCTION scan_records_guard()",
    "CREATE CONSTRAINT TRIGGER reports_content_check AFTER UPDATE ON reports "
    "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.status = 'succeeded') "
    "EXECUTE FUNCTION reports_content_check()",
    "CREATE CONSTRAINT TRIGGER report_contents_parent_check AFTER INSERT ON report_contents "
    "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION report_contents_parent_check()",
)
_FUNCTIONS = (
    "reports_guard",
    "report_contents_insert_guard",
    "reports_content_check",
    "report_contents_parent_check",
)


def upgrade() -> None:
    op.create_table(
        "reports",
        sa.Column("id", sa.Uuid(), server_default=sa.func.gen_random_uuid(), nullable=False),
        sa.Column("queue_position", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("format", sa.String(16), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("request_sha256", sa.LargeBinary(), nullable=False),
        sa.Column("requested_by_key_id", sa.Uuid(), nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("lease_owner", sa.String(128)),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True)),
        sa.Column("error_code", sa.String(64)),
        sa.Column("data_as_of", sa.DateTime(timezone=True)),
        sa.Column("generated_at", sa.DateTime(timezone=True)),
        sa.Column("size_bytes", sa.Integer()),
        sa.Column("sha256", sa.String(64)),
        sa.Column("truncated", sa.Boolean()),
        sa.Column("omitted_findings", sa.Integer()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_reports")),
        sa.UniqueConstraint("queue_position", name=op.f("uq_reports_queue_position")),
        sa.UniqueConstraint(
            "project_id", "idempotency_key", name=op.f("uq_reports_project_id_idempotency_key")
        ),
        sa.ForeignKeyConstraint(
            ["scan_id", "target_id", "project_id"],
            ["scans.id", "scans.target_id", "scans.project_id"],
            name=op.f("fk_reports_scan_id_target_id_project_id_scans"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_key_id"],
            ["api_keys.id"],
            name=op.f("fk_reports_requested_by_key_id_api_keys"),
            ondelete="RESTRICT",
        ),
        *(
            sa.CheckConstraint(condition, name=op.f(f"ck_reports_{name}"))
            for name, condition in _CHECKS.items()
        ),
    )
    op.create_index(op.f("ix_reports_scan_id"), "reports", ["scan_id"])
    op.create_index(op.f("ix_reports_requested_by_key_id"), "reports", ["requested_by_key_id"])
    op.create_index(
        "ix_reports_active_queue",
        "reports",
        ["queue_position"],
        postgresql_where=sa.text("status IN ('queued', 'generating')"),
    )
    op.create_table(
        "report_contents",
        sa.Column("report_id", sa.Uuid(), nullable=False),
        sa.Column("attempt", sa.SmallInteger(), nullable=False),
        sa.Column("lease_owner", sa.String(128), nullable=False),
        sa.Column("content", sa.LargeBinary(), nullable=False),
        sa.PrimaryKeyConstraint("report_id", name=op.f("pk_report_contents")),
        sa.ForeignKeyConstraint(
            ["report_id"],
            ["reports.id"],
            name=op.f("fk_report_contents_report_id_reports"),
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            f"octet_length(content) >= 1 AND octet_length(content) <= {MAX_REPORT_BYTES}",
            name=op.f("ck_report_contents_content_size"),
        ),
    )
    for function in (_GUARD, _CONTENT_INSERT, _SUCCEEDED_CHECK, _PARENT_CHECK):
        op.execute(function)
    for trigger in _TRIGGERS:
        op.execute(trigger)


def downgrade() -> None:
    op.drop_table("report_contents")
    op.drop_index("ix_reports_active_queue", table_name="reports")
    op.drop_index(op.f("ix_reports_requested_by_key_id"), table_name="reports")
    op.drop_index(op.f("ix_reports_scan_id"), table_name="reports")
    op.drop_table("reports")
    for function in _FUNCTIONS:
        op.execute(f"DROP FUNCTION {function}()")
