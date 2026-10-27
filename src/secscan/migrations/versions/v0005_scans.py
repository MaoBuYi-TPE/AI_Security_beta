"""scan 與工作佇列：scans、scanner_runs、scan_events、scan_operations（T09）。

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-26 09:00:00+00:00

升降級說明：
- upgrade：
  - 既有的資料表加上唯一約束，給 scan 的複合 FK 引用：targets (id, project_id)、
    scope_grants (id, target_id)、api_specs (id, target_id)、
    auth_profiles (id, target_id, role_label)。
    這些欄位組合本來就唯一（id 是主鍵），加上約束不會失敗。
  - 建立四張資料表及其 FK／unique／check，部分唯一索引 uq_scans_active_target（一個 target 同時
    只有一個進行中的 scan），以及認領與對帳用的部分索引。
  - trigger（docs/DECISIONS.md §13）：
    - scans：UPDATE 只能改 status、cancel_requested_at、finished_at；終止之後不能再改；
      cancel_requested_at 設定之後不能改；DELETE 與 TRUNCATE 一律拒絕。
    - scanner_runs：INSERT 必須是 queued、沒有 lease，而且只能在建立 scan 的 transaction 中；
      id、scan_id、engine、sequence、created_at 不能改；終止之後不能再改；DELETE 與 TRUNCATE
      一律拒絕。
    - scan_events、scan_operations：UPDATE、DELETE 與 TRUNCATE 一律拒絕（append-only）；
      scan_operations 的 INSERT 也只能在建立 scan 的 transaction 中。
- downgrade：刪除這四張資料表、trigger 函式與上述唯一約束，**所有 scan、run、事件與凍結的
  operation 都會消失**。只用於開發與測試，正式環境不要 downgrade。
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: str | Sequence[str] | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# 和 scans/models.py 相同的清單（migration 不 import 應用程式的程式，內容固定在這個版本）。
_SCAN_STATUSES = (
    "'queued', 'preparing', 'running', 'collecting', 'normalizing', 'cancelling', "
    "'completed', 'partially_completed', 'failed', 'timed_out', 'cancelled', 'interrupted'"
)
_TERMINAL_SCANS = (
    "'cancelled', 'completed', 'failed', 'interrupted', 'partially_completed', 'timed_out'"
)
_ACTIVE_SCANS = "'cancelling', 'collecting', 'normalizing', 'preparing', 'queued', 'running'"
_RUN_STATUSES = (
    "'queued', 'preparing', 'running', 'collecting', 'collected', 'normalizing', "
    "'succeeded', 'failed', 'timed_out', 'cancelling', 'cancelled', 'interrupted'"
)
_TERMINAL_RUNS = "'cancelled', 'failed', 'interrupted', 'succeeded', 'timed_out'"
_LEASED_RUNS = "'cancelling', 'collecting', 'normalizing', 'preparing', 'running'"
_ERROR_RUNS = "'failed', 'interrupted', 'timed_out'"
_ENGINES = "'zap', 'nuclei', 'schemathesis', 'fake'"
_PROFILES = "'api_active_lab', 'web_active_lab'"
_EVENT_TYPES = "'scan.created', 'scan.status', 'scan.cancel_requested', 'run.status'"
_REASONS = "'PATH_EXCLUDED', 'METHOD_NOT_AUTHORIZED', 'PATH_NOT_AUTHORIZED'"
_METHODS = "'GET', 'PUT', 'POST', 'DELETE', 'OPTIONS', 'HEAD', 'PATCH', 'TRACE'"

# scans 建立後不能改的欄位（只有 status、cancel_requested_at、finished_at 可以改）。
_SCAN_COLUMNS = (
    "id",
    "queue_position",
    "project_id",
    "target_id",
    "target_origin",
    "scope_grant_id",
    "api_spec_id",
    "auth_profile_id",
    "auth_profile_version",
    "auth_role",
    "scan_profile",
    "requests_per_second",
    "max_requests",
    "max_duration_seconds",
    "idempotency_key",
    "request_sha256",
    "created_by_key_id",
    "created_at",
)
_RUN_COLUMNS = ("id", "scan_id", "engine", "sequence", "created_at")

# 既有資料表新增的唯一約束：(資料表, 約束名稱, 欄位)。
_REFERENCED_KEYS = (
    ("targets", "uq_targets_id_project_id", ["id", "project_id"]),
    ("scope_grants", "uq_scope_grants_id_target_id", ["id", "target_id"]),
    ("api_specs", "uq_api_specs_id_target_id", ["id", "target_id"]),
    (
        "auth_profiles",
        "uq_auth_profiles_id_target_id_role_label",
        ["id", "target_id", "role_label"],
    ),
)


def _row(prefix: str, columns: Sequence[str]) -> str:
    return "(" + ", ".join(f"{prefix}.{column}" for column in columns) + ")"


# 不用 RAISE 的 % 格式字串：SQLAlchemy 會把文字 SQL 裡的 % 跳脫，改用字串串接。
# 固定 search_path，函式不受呼叫端 search_path 影響（避免被同名物件劫持）。
_CREATE_SCANS_GUARD = f"""
CREATE FUNCTION scans_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP = 'UPDATE'
        AND {_row("NEW", _SCAN_COLUMNS)} IS NOT DISTINCT FROM {_row("OLD", _SCAN_COLUMNS)}
        AND OLD.status NOT IN ({_TERMINAL_SCANS})
        AND (OLD.cancel_requested_at IS NULL
            OR NEW.cancel_requested_at IS NOT DISTINCT FROM OLD.cancel_requested_at)
    THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION USING
        ERRCODE = 'integrity_constraint_violation',
        MESSAGE = 'scans: ' || TG_OP || ' blocked; only the status, cancel_requested_at and '
            || 'finished_at of an unfinished scan can change';
END;
$$
"""

# run 與凍結的 operation 只能在建立 scan 的 transaction 中新增（審查後補上）：scan 的 created_at
# 是建立它的 transaction 開始的時間（now()），之後的 transaction 的 now() 不同。事後加入的 run
# 會被認領、加入的 operation 會改變 coverage 的分母。search_path 固定為 pg_catalog，
# 所以寫明 public。
_CREATED_IN_THIS_TRANSACTION = (
    "EXISTS (SELECT 1 FROM public.scans AS parent "
    "WHERE parent.id = NEW.scan_id AND parent.created_at = now())"
)

_CREATE_RUNS_GUARD = f"""
CREATE FUNCTION scanner_runs_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
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
    END IF;
    IF TG_OP = 'UPDATE'
        AND {_row("NEW", _RUN_COLUMNS)} IS NOT DISTINCT FROM {_row("OLD", _RUN_COLUMNS)}
        AND OLD.status NOT IN ({_TERMINAL_RUNS})
    THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION USING
        ERRCODE = 'integrity_constraint_violation',
        MESSAGE = 'scanner_runs: ' || TG_OP || ' blocked; only an unfinished run can change '
            || 'and its identity is fixed';
END;
$$
"""

_CREATE_RECORDS_GUARD = """
CREATE FUNCTION scan_records_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = 'integrity_constraint_violation',
        MESSAGE = TG_TABLE_NAME || ' rows are immutable (' || TG_OP || ' blocked)';
END;
$$
"""

_CREATE_OPERATIONS_INSERT_GUARD = f"""
CREATE FUNCTION scan_operations_insert_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF {_CREATED_IN_THIS_TRANSACTION} THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION USING
        ERRCODE = 'integrity_constraint_violation',
        MESSAGE = 'scan_operations: operations can only be added while creating their scan';
END;
$$
"""

_EVERY_WRITE = "BEFORE INSERT OR UPDATE OR DELETE"
_CHANGES = "BEFORE UPDATE OR DELETE"
_TRUNCATE = "BEFORE TRUNCATE"
# (trigger 名稱, 資料表, 時機, 層級, 函式)
_TRIGGERS = (
    ("scans_guard_rows", "scans", "BEFORE UPDATE OR DELETE", "ROW", "scans_guard"),
    ("scans_no_truncate", "scans", "BEFORE TRUNCATE", "STATEMENT", "scans_guard"),
    ("scanner_runs_guard_rows", "scanner_runs", _EVERY_WRITE, "ROW", "scanner_runs_guard"),
    ("scanner_runs_no_truncate", "scanner_runs", _TRUNCATE, "STATEMENT", "scanner_runs_guard"),
    ("scan_events_immutable", "scan_events", _CHANGES, "ROW", "scan_records_guard"),
    ("scan_events_no_truncate", "scan_events", _TRUNCATE, "STATEMENT", "scan_records_guard"),
    ("scan_operations_immutable", "scan_operations", _CHANGES, "ROW", "scan_records_guard"),
    (
        "scan_operations_added_with_scan",
        "scan_operations",
        "BEFORE INSERT",
        "ROW",
        "scan_operations_insert_guard",
    ),
    (
        "scan_operations_no_truncate",
        "scan_operations",
        _TRUNCATE,
        "STATEMENT",
        "scan_records_guard",
    ),
)


def upgrade() -> None:
    for table, name, columns in _REFERENCED_KEYS:
        op.create_unique_constraint(op.f(name), table, columns)
    _create_scans()
    _create_scanner_runs()
    _create_scan_events()
    _create_scan_operations()
    op.execute(_CREATE_SCANS_GUARD)
    op.execute(_CREATE_RUNS_GUARD)
    op.execute(_CREATE_RECORDS_GUARD)
    op.execute(_CREATE_OPERATIONS_INSERT_GUARD)
    for name, table, timing, level, function in _TRIGGERS:
        op.execute(
            f"CREATE TRIGGER {name} {timing} ON {table} "
            f"FOR EACH {level} EXECUTE FUNCTION {function}()"
        )


def downgrade() -> None:
    # 刪除資料表會一併刪除它的 trigger 與索引；函式與既有資料表的約束要另外刪。
    op.drop_table("scan_operations")
    op.drop_table("scan_events")
    op.drop_table("scanner_runs")
    op.drop_table("scans")
    op.execute("DROP FUNCTION scan_operations_insert_guard()")
    op.execute("DROP FUNCTION scan_records_guard()")
    op.execute("DROP FUNCTION scanner_runs_guard()")
    op.execute("DROP FUNCTION scans_guard()")
    for table, name, _columns in reversed(_REFERENCED_KEYS):
        op.drop_constraint(op.f(name), table, type_="unique")


def _create_scans() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("queue_position", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("target_origin", sa.String(length=256), nullable=False),
        sa.Column("scope_grant_id", sa.Uuid(), nullable=False),
        sa.Column("api_spec_id", sa.Uuid(), nullable=True),
        sa.Column("auth_profile_id", sa.Uuid(), nullable=True),
        sa.Column("auth_profile_version", sa.Integer(), nullable=True),
        sa.Column("auth_role", sa.String(length=64), nullable=False),
        sa.Column("scan_profile", sa.String(length=32), nullable=False),
        sa.Column("requests_per_second", sa.Integer(), nullable=False),
        sa.Column("max_requests", sa.Integer(), nullable=False),
        sa.Column("max_duration_seconds", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("request_sha256", sa.LargeBinary(), nullable=False),
        sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_key_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(f"status IN ({_SCAN_STATUSES})", name=op.f("ck_scans_status_valid")),
        sa.CheckConstraint(
            f"scan_profile IN ({_PROFILES})", name=op.f("ck_scans_scan_profile_valid")
        ),
        sa.CheckConstraint(
            "requests_per_second > 0 AND max_requests > 0 AND max_duration_seconds > 0",
            name=op.f("ck_scans_budget_positive"),
        ),
        sa.CheckConstraint(
            "idempotency_key ~ '^[A-Za-z0-9_-]{16,128}$'",
            name=op.f("ck_scans_idempotency_key_valid"),
        ),
        sa.CheckConstraint(
            "octet_length(request_sha256) = 32", name=op.f("ck_scans_request_sha256_length")
        ),
        sa.CheckConstraint(
            "(auth_profile_id IS NULL) = (auth_profile_version IS NULL) "
            "AND (auth_profile_id IS NULL) = (auth_role = 'anonymous')",
            name=op.f("ck_scans_auth_consistent"),
        ),
        sa.CheckConstraint(
            "auth_role ~ '^[a-z][a-z0-9_]{0,63}$'", name=op.f("ck_scans_auth_role_valid")
        ),
        sa.CheckConstraint(
            "CASE scan_profile WHEN 'api_active_lab' "
            "THEN api_spec_id IS NOT NULL ELSE api_spec_id IS NULL END",
            name=op.f("ck_scans_spec_matches_profile"),
        ),
        sa.CheckConstraint(
            "target_origin ~ '^http://[a-z0-9.-]+(:[1-9][0-9]{0,4})?$'",
            name=op.f("ck_scans_origin_canonical"),
        ),
        sa.CheckConstraint(
            f"(status IN ({_TERMINAL_SCANS})) = (finished_at IS NOT NULL)",
            name=op.f("ck_scans_finished_matches_status"),
        ),
        sa.CheckConstraint(
            "status NOT IN ('cancelling', 'cancelled') OR cancel_requested_at IS NOT NULL",
            name=op.f("ck_scans_cancel_matches_status"),
        ),
        sa.CheckConstraint(
            "(cancel_requested_at IS NULL OR cancel_requested_at >= created_at) "
            "AND (finished_at IS NULL OR finished_at >= created_at)",
            name=op.f("ck_scans_times"),
        ),
        sa.ForeignKeyConstraint(
            ["target_id", "project_id"],
            ["targets.id", "targets.project_id"],
            name="fk_scans_target_project",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["scope_grant_id", "target_id"],
            ["scope_grants.id", "scope_grants.target_id"],
            name="fk_scans_grant_target",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["api_spec_id", "target_id"],
            ["api_specs.id", "api_specs.target_id"],
            name="fk_scans_spec_target",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["auth_profile_id", "target_id", "auth_role"],
            ["auth_profiles.id", "auth_profiles.target_id", "auth_profiles.role_label"],
            name="fk_scans_profile_target_role",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["auth_profile_id", "auth_profile_version"],
            ["auth_profile_versions.profile_id", "auth_profile_versions.version"],
            name="fk_scans_profile_version",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_key_id"],
            ["api_keys.id"],
            name=op.f("fk_scans_created_by_key_id_api_keys"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scans")),
        sa.UniqueConstraint(
            "project_id", "idempotency_key", name=op.f("uq_scans_project_id_idempotency_key")
        ),
        sa.UniqueConstraint("queue_position", name=op.f("uq_scans_queue_position")),
    )
    op.create_index(
        "uq_scans_active_target",
        "scans",
        ["target_id"],
        unique=True,
        postgresql_where=sa.text(f"status IN ({_ACTIVE_SCANS})"),
    )
    op.create_index("ix_scans_target_id_created_at", "scans", ["target_id", "created_at"])
    op.create_index("ix_scans_project_id_created_at", "scans", ["project_id", "created_at"])


def _create_scanner_runs() -> None:
    op.create_table(
        "scanner_runs",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("engine", sa.String(length=16), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("lease_owner", sa.String(length=128), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(f"engine IN ({_ENGINES})", name=op.f("ck_scanner_runs_engine_valid")),
        sa.CheckConstraint(
            f"status IN ({_RUN_STATUSES})", name=op.f("ck_scanner_runs_status_valid")
        ),
        sa.CheckConstraint("sequence BETWEEN 1 AND 4", name=op.f("ck_scanner_runs_sequence_valid")),
        sa.CheckConstraint(
            "(lease_owner IS NULL) = (lease_expires_at IS NULL) "
            "AND (lease_owner IS NULL) = (heartbeat_at IS NULL) "
            f"AND (lease_owner IS NOT NULL) = (status IN ({_LEASED_RUNS}))",
            name=op.f("ck_scanner_runs_lease_matches_status"),
        ),
        sa.CheckConstraint(
            "lease_owner IS NULL OR char_length(btrim(lease_owner)) > 0",
            name=op.f("ck_scanner_runs_lease_owner_not_blank"),
        ),
        sa.CheckConstraint(
            f"(status IN ({_TERMINAL_RUNS})) = (finished_at IS NOT NULL)",
            name=op.f("ck_scanner_runs_finished_matches_status"),
        ),
        sa.CheckConstraint(
            f"(status IN ({_ERROR_RUNS})) = (error_code IS NOT NULL)",
            name=op.f("ck_scanner_runs_error_code_matches_status"),
        ),
        sa.CheckConstraint(
            "error_code IS NULL OR error_code ~ '^[A-Z][A-Z0-9_]{0,63}$'",
            name=op.f("ck_scanner_runs_error_code_valid"),
        ),
        sa.CheckConstraint(
            "CASE status WHEN 'queued' THEN started_at IS NULL "
            "WHEN 'cancelled' THEN true ELSE started_at IS NOT NULL END",
            name=op.f("ck_scanner_runs_started_matches_status"),
        ),
        sa.CheckConstraint(
            "(started_at IS NULL OR started_at >= created_at) "
            "AND (finished_at IS NULL OR finished_at >= coalesce(started_at, created_at)) "
            "AND (heartbeat_at IS NULL OR heartbeat_at >= started_at)",
            name=op.f("ck_scanner_runs_times"),
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            name=op.f("fk_scanner_runs_scan_id_scans"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scanner_runs")),
        sa.UniqueConstraint("id", "scan_id", name=op.f("uq_scanner_runs_id_scan_id")),
        sa.UniqueConstraint("scan_id", "engine", name=op.f("uq_scanner_runs_scan_id_engine")),
        sa.UniqueConstraint("scan_id", "sequence", name=op.f("uq_scanner_runs_scan_id_sequence")),
    )
    op.create_index(
        "ix_scanner_runs_claimable",
        "scanner_runs",
        ["status", "engine"],
        postgresql_where=sa.text("status IN ('queued', 'collected')"),
    )
    op.create_index(
        "ix_scanner_runs_lease_expires_at",
        "scanner_runs",
        ["lease_expires_at"],
        postgresql_where=sa.text("lease_owner IS NOT NULL"),
    )


def _create_scan_events() -> None:
    op.create_table(
        "scan_events",
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("sequence", sa.Integer(), autoincrement=False, nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("scanner_run_id", sa.Uuid(), nullable=True),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("clock_timestamp()"),
            nullable=False,
        ),
        sa.CheckConstraint("sequence > 0", name=op.f("ck_scan_events_sequence_positive")),
        sa.CheckConstraint(
            f"event_type IN ({_EVENT_TYPES})", name=op.f("ck_scan_events_event_type_valid")
        ),
        sa.CheckConstraint(
            "(event_type = 'run.status') = (scanner_run_id IS NOT NULL)",
            name=op.f("ck_scan_events_run_matches_type"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(payload) = 'object' AND octet_length(payload::text) <= 1024",
            name=op.f("ck_scan_events_payload_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            name=op.f("fk_scan_events_scan_id_scans"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["scanner_run_id", "scan_id"],
            ["scanner_runs.id", "scanner_runs.scan_id"],
            name="fk_scan_events_run_scan",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("scan_id", "sequence", name=op.f("pk_scan_events")),
    )


def _create_scan_operations() -> None:
    op.create_table(
        "scan_operations",
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("ordinal", sa.Integer(), autoincrement=False, nullable=False),
        sa.Column("method", sa.String(length=7), nullable=False),
        sa.Column("path", sa.String(length=512), nullable=False),
        sa.Column("operation_id", sa.String(length=200), nullable=True),
        sa.Column("ineligible_reason", sa.String(length=32), nullable=True),
        sa.CheckConstraint(f"method IN ({_METHODS})", name=op.f("ck_scan_operations_method_valid")),
        sa.CheckConstraint("left(path, 1) = '/'", name=op.f("ck_scan_operations_path_valid")),
        sa.CheckConstraint(
            "ordinal >= 0 AND ordinal < 1000", name=op.f("ck_scan_operations_ordinal_valid")
        ),
        sa.CheckConstraint(
            "operation_id IS NULL OR char_length(btrim(operation_id)) > 0",
            name=op.f("ck_scan_operations_operation_id_not_blank"),
        ),
        sa.CheckConstraint(
            f"ineligible_reason IS NULL OR ineligible_reason IN ({_REASONS})",
            name=op.f("ck_scan_operations_reason_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            name=op.f("fk_scan_operations_scan_id_scans"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("scan_id", "ordinal", name=op.f("pk_scan_operations")),
        sa.UniqueConstraint(
            "scan_id", "method", "path", name=op.f("uq_scan_operations_scan_id_method_path")
        ),
    )
