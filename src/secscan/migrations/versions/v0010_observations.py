"""run 的解析結果、artifacts 與 observations（T15；docs/DECISIONS.md §19.6）。

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-31 12:00:00+00:00

升降級說明：
- upgrade：
  - scanner_runs 新增 results_recorded（預設 false）、parser_version、engine_version、exit_code、
    observation_count、result_details（JSONB，≤ 4 KiB）。既有的資料列都沒有結果，符合 CHECK；
    run 結束之後由 0009 的 trigger 凍結（以 to_jsonb 比較，新的欄位也包含在內）。
  - 建立 artifacts（run 的輸入與輸出檔的 metadata）與 observations（工具的單次觀察）。兩張表都只以
    複合 FK 引用 scanner_runs，不直接引用 scans（對帳先鎖 scans 再鎖 run）；資料列不可修改、刪除
    或 TRUNCATE（沿用 scan_records_guard）。
- downgrade：刪除兩張表與新欄位，**已解析的結果會消失**，已經 succeeded 的 run 仍是 succeeded，
  但觀察不見了。只用於開發與測試，正式環境不要 downgrade。
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0010"
down_revision: str | Sequence[str] | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# 和 scans/models.py 相同的內容（migration 不 import 應用程式的程式）。
_SHA256_HEX = "^[0-9a-f]{64}$"
_METHODS = "'CONNECT', 'DELETE', 'GET', 'HEAD', 'OPTIONS', 'PATCH', 'POST', 'PUT', 'TRACE'"
_MAX_DETAILS_BYTES = 4096
_ROLE_PATTERN = "^[a-z][a-z0-9_]{0,63}$"
_RUN_CHECKS = {
    "results_consistent": (
        "results_recorded = (parser_version IS NOT NULL) "
        "AND results_recorded = (observation_count IS NOT NULL) "
        "AND results_recorded = (result_details IS NOT NULL) "
        "AND (results_recorded OR (engine_version IS NULL AND exit_code IS NULL))"
    ),
    "result_counts_valid": (
        "(observation_count IS NULL OR observation_count >= 0) "
        "AND (exit_code IS NULL OR exit_code BETWEEN 0 AND 255)"
    ),
    "result_details_valid": (
        "result_details IS NULL OR (jsonb_typeof(result_details) = 'object' "
        f"AND octet_length(result_details::text) <= {_MAX_DETAILS_BYTES})"
    ),
}
_APPEND_ONLY = ("artifacts", "observations")


def _timestamps() -> sa.Column[Any]:
    return sa.Column(
        "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
    )


def _id() -> sa.Column[Any]:
    return sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False)


def _run_key(table: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["scanner_run_id", "scan_id"],
        ["scanner_runs.id", "scanner_runs.scan_id"],
        name=op.f(f"fk_{table}_scanner_run_id_scanner_runs"),
        ondelete="RESTRICT",
    )


def upgrade() -> None:
    _add_run_columns()
    _create_artifacts()
    _create_observations()
    for table in _APPEND_ONLY:
        op.execute(
            f"CREATE TRIGGER {table}_immutable BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION scan_records_guard()"
        )
        op.execute(
            f"CREATE TRIGGER {table}_no_truncate BEFORE TRUNCATE ON {table} "
            "FOR EACH STATEMENT EXECUTE FUNCTION scan_records_guard()"
        )


def _add_run_columns() -> None:
    op.add_column(
        "scanner_runs",
        sa.Column(
            "results_recorded", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
    )
    op.add_column("scanner_runs", sa.Column("parser_version", sa.String(64), nullable=True))
    op.add_column("scanner_runs", sa.Column("engine_version", sa.String(64), nullable=True))
    op.add_column("scanner_runs", sa.Column("exit_code", sa.Integer(), nullable=True))
    op.add_column("scanner_runs", sa.Column("observation_count", sa.Integer(), nullable=True))
    op.add_column("scanner_runs", sa.Column("result_details", postgresql.JSONB(), nullable=True))
    for name, condition in _RUN_CHECKS.items():
        op.create_check_constraint(op.f(f"ck_scanner_runs_{name}"), "scanner_runs", condition)


def _create_artifacts() -> None:
    op.create_table(
        "artifacts",
        _id(),
        sa.Column("scanner_run_id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("path", sa.String(2048), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size", sa.BigInteger(), nullable=False),
        sa.Column("redactions", sa.Integer(), nullable=False),
        sa.Column("classification", sa.String(32), nullable=False),
        sa.Column("encrypted", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("storage_key", sa.String(2200), nullable=False),
        _timestamps(),
        sa.CheckConstraint(
            "(kind = 'output' AND classification = 'masked') "
            "OR (kind = 'input' AND classification = 'input')",
            name=op.f("ck_artifacts_classification_matches_kind"),
        ),
        sa.CheckConstraint(f"sha256 ~ '{_SHA256_HEX}'", name=op.f("ck_artifacts_sha256_valid")),
        sa.CheckConstraint(
            "size >= 0 AND redactions >= 0", name=op.f("ck_artifacts_counts_not_negative")
        ),
        sa.CheckConstraint(
            "char_length(btrim(path)) > 0", name=op.f("ck_artifacts_path_not_blank")
        ),
        sa.CheckConstraint(
            "char_length(btrim(storage_key)) > 0", name=op.f("ck_artifacts_storage_key_not_blank")
        ),
        _run_key("artifacts"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_artifacts")),
        sa.UniqueConstraint(
            "scanner_run_id", "kind", "path", name=op.f("uq_artifacts_scanner_run_id_kind_path")
        ),
        sa.UniqueConstraint("id", "scanner_run_id", name=op.f("uq_artifacts_id_scanner_run_id")),
    )
    op.create_index("ix_artifacts_scan_id", "artifacts", ["scan_id"], unique=False)


def _create_observations() -> None:
    op.create_table(
        "observations",
        _id(),
        sa.Column("scanner_run_id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("ordinal", sa.Integer(), autoincrement=False, nullable=False),
        sa.Column("source_event_id", sa.String(64), nullable=False),
        sa.Column("source_index", sa.Integer(), nullable=False),
        sa.Column("source_rule", sa.String(64), nullable=False),
        sa.Column("rule_variant", sa.String(64), nullable=True),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("raw_severity", sa.String(32), nullable=False),
        sa.Column("severity_label", sa.String(32), nullable=False),
        sa.Column("raw_confidence", sa.String(32), nullable=False),
        sa.Column("confidence_label", sa.String(32), nullable=False),
        sa.Column("cwe_id", sa.Integer(), nullable=True),
        sa.Column("wasc_id", sa.Integer(), nullable=True),
        sa.Column("method", sa.String(7), nullable=False),
        sa.Column("path", sa.String(2048), nullable=False),
        sa.Column("query", sa.String(2048), nullable=True),
        sa.Column("parameter", sa.String(512), nullable=True),
        sa.Column("parameter_location", sa.String(32), nullable=False),
        sa.Column("attack", sa.String(4096), nullable=True),
        sa.Column("evidence", sa.String(4096), nullable=True),
        sa.Column("other_info", sa.String(4096), nullable=True),
        sa.Column("auth_role", sa.String(64), nullable=False),
        sa.Column("report_artifact_id", sa.Uuid(), nullable=True),
        sa.Column("parser_version", sa.String(64), nullable=False),
        _timestamps(),
        sa.CheckConstraint("ordinal >= 1", name=op.f("ck_observations_ordinal_valid")),
        sa.CheckConstraint("source_index >= 0", name=op.f("ck_observations_source_index_valid")),
        sa.CheckConstraint(
            f"source_event_id ~ '{_SHA256_HEX}'", name=op.f("ck_observations_source_event_id_valid")
        ),
        sa.CheckConstraint(
            "char_length(btrim(source_rule)) > 0",
            name=op.f("ck_observations_source_rule_not_blank"),
        ),
        sa.CheckConstraint(
            "char_length(btrim(title)) > 0", name=op.f("ck_observations_title_not_blank")
        ),
        sa.CheckConstraint(
            "char_length(btrim(raw_severity)) > 0",
            name=op.f("ck_observations_raw_severity_not_blank"),
        ),
        sa.CheckConstraint(
            "char_length(btrim(raw_confidence)) > 0",
            name=op.f("ck_observations_raw_confidence_not_blank"),
        ),
        sa.CheckConstraint(
            "cwe_id IS NULL OR cwe_id > 0", name=op.f("ck_observations_cwe_positive")
        ),
        sa.CheckConstraint(
            "wasc_id IS NULL OR wasc_id > 0", name=op.f("ck_observations_wasc_positive")
        ),
        sa.CheckConstraint(f"method IN ({_METHODS})", name=op.f("ck_observations_method_valid")),
        sa.CheckConstraint("left(path, 1) = '/'", name=op.f("ck_observations_path_valid")),
        sa.CheckConstraint(
            "parameter_location IN ('query', 'unknown')",
            name=op.f("ck_observations_parameter_location_valid"),
        ),
        sa.CheckConstraint(
            f"auth_role ~ '{_ROLE_PATTERN}'", name=op.f("ck_observations_auth_role_valid")
        ),
        sa.CheckConstraint(
            "char_length(btrim(parser_version)) > 0",
            name=op.f("ck_observations_parser_version_not_blank"),
        ),
        _run_key("observations"),
        sa.ForeignKeyConstraint(
            ["report_artifact_id", "scanner_run_id"],
            ["artifacts.id", "artifacts.scanner_run_id"],
            name=op.f("fk_observations_report_artifact_id_artifacts"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_observations")),
        sa.UniqueConstraint(
            "scanner_run_id",
            "source_event_id",
            name=op.f("uq_observations_scanner_run_id_source_event_id"),
        ),
        sa.UniqueConstraint(
            "scanner_run_id", "ordinal", name=op.f("uq_observations_scanner_run_id_ordinal")
        ),
    )
    op.create_index(
        "ix_observations_scan_id_scanner_run_id_ordinal",
        "observations",
        ["scan_id", "scanner_run_id", "ordinal"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_table("observations")
    op.drop_table("artifacts")
    for name in reversed(_RUN_CHECKS):
        op.drop_constraint(op.f(f"ck_scanner_runs_{name}"), "scanner_runs", type_="check")
    for column in (
        "result_details",
        "observation_count",
        "exit_code",
        "engine_version",
        "parser_version",
        "results_recorded",
    ):
        op.drop_column("scanner_runs", column)
