"""T22：凍結 run 的複掃來源版本；既有 run 保持未知。

Revision ID: 0016
Revises: 0015

降級會刪除全部比較快照、逐位置摘要及 run 的複掃來源版本／覆蓋標記，
不保留這些歷史證據，只適合已備份的開發與測試資料庫。
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0016"
down_revision: str | Sequence[str] | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_RULE_SET = (
    "(rule_set IS NULL AND rule_set_sha256 IS NULL) OR "
    "(rule_set IS NOT NULL AND jsonb_typeof(rule_set) = 'array' "
    "AND octet_length(rule_set::text) <= 262144 "
    "AND rule_set_sha256 IS NOT NULL AND rule_set_sha256 ~ '^[0-9a-f]{64}$' "
    "AND plan_hash IS NOT NULL)"
)
_LINK = (
    "(link_mapping_version IS NULL AND link_taxonomy_sha256 IS NULL) OR "
    "(link_mapping_version IS NOT NULL AND char_length(btrim(link_mapping_version)) > 0 "
    "AND link_taxonomy_sha256 IS NOT NULL AND link_taxonomy_sha256 ~ '^[0-9a-f]{64}$')"
)
_CHECKS = {
    "rule_set_valid": _RULE_SET,
    "link_provenance_valid": _LINK,
    "locations_provenance_required": "NOT locations_recorded OR link_mapping_version IS NOT NULL",
}

_ONCE = """
CREATE FUNCTION scanner_runs_comparison_once() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.rule_set IS NOT NULL OR NEW.rule_set_sha256 IS NOT NULL
            OR NEW.link_mapping_version IS NOT NULL OR NEW.link_taxonomy_sha256 IS NOT NULL
            OR NEW.locations_recorded
        THEN
            RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
                MESSAGE = 'scanner_runs: new runs cannot contain comparison provenance';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.plan_hash IS NOT NULL AND (
        NEW.rule_set IS DISTINCT FROM OLD.rule_set OR
        NEW.rule_set_sha256 IS DISTINCT FROM OLD.rule_set_sha256
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'scanner_runs: rule set must be recorded with the plan and only once';
    END IF;
    IF OLD.link_mapping_version IS NOT NULL AND (
        NEW.link_mapping_version IS DISTINCT FROM OLD.link_mapping_version OR
        NEW.link_taxonomy_sha256 IS DISTINCT FROM OLD.link_taxonomy_sha256 OR
        NEW.locations_recorded IS DISTINCT FROM OLD.locations_recorded
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'scanner_runs: comparison provenance can only be recorded once';
    END IF;
    RETURN NEW;
END;
$$
"""


def upgrade() -> None:
    op.add_column("scanner_runs", sa.Column("rule_set", postgresql.JSONB(), nullable=True))
    op.add_column("scanner_runs", sa.Column("rule_set_sha256", sa.String(64), nullable=True))
    op.add_column("scanner_runs", sa.Column("link_mapping_version", sa.String(64), nullable=True))
    op.add_column("scanner_runs", sa.Column("link_taxonomy_sha256", sa.String(64), nullable=True))
    op.add_column(
        "scanner_runs",
        sa.Column(
            "locations_recorded", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
    )
    for name, condition in _CHECKS.items():
        op.create_check_constraint(op.f(f"ck_scanner_runs_{name}"), "scanner_runs", condition)
    op.execute(_ONCE)
    op.execute(
        "CREATE TRIGGER scanner_runs_comparison_once BEFORE INSERT OR UPDATE ON scanner_runs "
        "FOR EACH ROW EXECUTE FUNCTION scanner_runs_comparison_once()"
    )
    _create_locations()
    _create_comparisons()


def downgrade() -> None:
    op.drop_table("scan_comparison_findings")
    op.drop_table("scan_comparisons")
    op.execute("DROP FUNCTION scan_comparison_finding_insert_guard()")
    op.execute("DROP FUNCTION scan_comparison_guard()")
    op.execute("DROP FUNCTION scan_comparison_sealed_check()")
    op.drop_constraint(op.f("uq_findings_id_target_id"), "findings", type_="unique")
    op.drop_constraint(op.f("uq_scans_id_target_id_project_id"), "scans", type_="unique")
    op.drop_table("run_rule_locations")
    op.drop_table("run_locations")
    op.execute("DROP FUNCTION run_locations_insert_guard()")
    op.execute("DROP TRIGGER scanner_runs_comparison_once ON scanner_runs")
    op.execute("DROP FUNCTION scanner_runs_comparison_once()")
    for name in reversed(_CHECKS):
        op.drop_constraint(op.f(f"ck_scanner_runs_{name}"), "scanner_runs", type_="check")
    for column in (
        "locations_recorded",
        "link_taxonomy_sha256",
        "link_mapping_version",
        "rule_set_sha256",
        "rule_set",
    ):
        op.drop_column("scanner_runs", column)


_LOCATION_INSERT_GUARD = """
CREATE FUNCTION run_locations_insert_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
    recorded boolean;
    run_status text;
BEGIN
    SELECT locations_recorded, status INTO recorded, run_status
    FROM public.scanner_runs WHERE id = NEW.scanner_run_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'location parent must be visible in this transaction';
    END IF;
    IF recorded OR run_status IN
        ('cancelled', 'failed', 'interrupted', 'succeeded', 'timed_out') THEN
        RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'run locations cannot be added after coverage or run completion';
    END IF;
    RETURN NEW;
END;
$$
"""


def _create_locations() -> None:
    method = "method IN ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS')"
    path_sha256 = "path_sha256 ~ '^[0-9a-f]{64}$'"
    op.create_table(
        "run_locations",
        sa.Column("scanner_run_id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("method", sa.String(7), nullable=False),
        sa.Column("path_sha256", sa.String(64), nullable=False),
        sa.Column("answered", sa.Boolean(), nullable=False),
        sa.Column("discovery_answered", sa.Boolean(), nullable=False),
        sa.Column("authenticated", sa.Boolean(), nullable=False),
        sa.Column("unanswered", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint(
            "scanner_run_id", "method", "path_sha256", name=op.f("pk_run_locations")
        ),
        sa.ForeignKeyConstraint(
            ["scanner_run_id", "scan_id"],
            ["scanner_runs.id", "scanner_runs.scan_id"],
            name=op.f("fk_run_locations_scanner_run_id_scan_id_scanner_runs"),
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(method, name=op.f("ck_run_locations_method_valid")),
        sa.CheckConstraint(path_sha256, name=op.f("ck_run_locations_path_sha256_valid")),
        sa.CheckConstraint(
            "(NOT discovery_answered OR answered) AND (NOT authenticated OR answered)",
            name=op.f("ck_run_locations_answers_consistent"),
        ),
    )
    op.create_table(
        "run_rule_locations",
        sa.Column("scanner_run_id", sa.Uuid(), nullable=False),
        sa.Column("method", sa.String(7), nullable=False),
        sa.Column("path_sha256", sa.String(64), nullable=False),
        sa.Column("rule", sa.String(6), nullable=False),
        sa.Column("answered", sa.Boolean(), nullable=False),
        sa.Column("parameters_unknown", sa.Boolean(), nullable=False),
        sa.Column("parameters_truncated", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint(
            "scanner_run_id", "method", "path_sha256", "rule", name=op.f("pk_run_rule_locations")
        ),
        sa.ForeignKeyConstraint(
            ["scanner_run_id", "method", "path_sha256"],
            ["run_locations.scanner_run_id", "run_locations.method", "run_locations.path_sha256"],
            name=op.f("fk_run_rule_locations_scanner_run_id_method_path_sha256_run_locations"),
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("rule ~ '^[0-9]{1,6}$'", name=op.f("ck_run_rule_locations_rule_valid")),
        sa.CheckConstraint(
            "parameters_unknown", name=op.f("ck_run_rule_locations_parameters_unknown_required")
        ),
    )
    op.execute(_LOCATION_INSERT_GUARD)
    for table in ("run_locations", "run_rule_locations"):
        op.execute(
            f"CREATE TRIGGER {table}_insert_guard BEFORE INSERT ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION run_locations_insert_guard()"
        )
        op.execute(
            f"CREATE TRIGGER {table}_immutable BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION scan_records_guard()"
        )
        op.execute(
            f"CREATE TRIGGER {table}_no_truncate BEFORE TRUNCATE ON {table} "
            "FOR EACH STATEMENT EXECUTE FUNCTION scan_records_guard()"
        )


_COMPARISON_GUARD = """
CREATE FUNCTION scan_comparison_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.sealed THEN
            RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
                MESSAGE = 'comparison must be created unsealed';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND NOT OLD.sealed AND NEW.sealed
       AND (to_jsonb(OLD) - 'sealed') = (to_jsonb(NEW) - 'sealed') THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
        MESSAGE = 'comparison snapshots cannot be modified';
END;
$$
"""
_COMPARISON_ROW_GUARD = """
CREATE FUNCTION scan_comparison_finding_insert_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE frozen boolean;
BEGIN
    SELECT sealed INTO frozen FROM public.scan_comparisons WHERE id = NEW.comparison_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'comparison parent must be visible in this transaction';
    END IF;
    IF frozen THEN
        RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'cannot append to a sealed comparison';
    END IF;
    RETURN NEW;
END;
$$
"""
_COMPARISON_SEALED = """
CREATE FUNCTION scan_comparison_sealed_check() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.scan_comparisons WHERE id = NEW.id AND NOT sealed) THEN
        RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'comparison must be sealed in its creation transaction';
    END IF;
    RETURN NULL;
END;
$$
"""


def _create_comparisons() -> None:
    op.create_unique_constraint(
        op.f("uq_scans_id_target_id_project_id"), "scans", ["id", "target_id", "project_id"]
    )
    op.create_unique_constraint(op.f("uq_findings_id_target_id"), "findings", ["id", "target_id"])
    op.create_table(
        "scan_comparisons",
        sa.Column("id", sa.Uuid(), server_default=sa.func.gen_random_uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("baseline_scan_id", sa.Uuid(), nullable=False),
        sa.Column("current_scan_id", sa.Uuid(), nullable=False),
        sa.Column("algorithm_version", sa.Integer(), nullable=False),
        sa.Column("comparability", sa.String(32), nullable=False),
        sa.Column("reasons", postgresql.JSONB(), nullable=False),
        sa.Column("manual_review_required", sa.Boolean(), nullable=False),
        sa.Column("sealed", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_comparisons")),
        sa.UniqueConstraint(
            "baseline_scan_id",
            "current_scan_id",
            "algorithm_version",
            name=op.f("uq_scan_comparisons_baseline_scan_id_current_scan_id_algorithm_version"),
        ),
        sa.UniqueConstraint("id", "target_id", name=op.f("uq_scan_comparisons_id_target_id")),
        sa.ForeignKeyConstraint(
            ["baseline_scan_id", "target_id", "project_id"],
            ["scans.id", "scans.target_id", "scans.project_id"],
            name=op.f("fk_scan_comparisons_baseline_scan_id_target_id_project_id_scans"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["current_scan_id", "target_id", "project_id"],
            ["scans.id", "scans.target_id", "scans.project_id"],
            name=op.f("fk_scan_comparisons_current_scan_id_target_id_project_id_scans"),
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "baseline_scan_id <> current_scan_id", name=op.f("ck_scan_comparisons_different_scans")
        ),
        sa.CheckConstraint(
            "algorithm_version > 0", name=op.f("ck_scan_comparisons_algorithm_version_positive")
        ),
        sa.CheckConstraint(
            "comparability IN ('comparable', 'different', 'not_comparable')",
            name=op.f("ck_scan_comparisons_comparability_valid"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(reasons) = 'array' AND octet_length(reasons::text) <= 16384",
            name=op.f("ck_scan_comparisons_reasons_valid"),
        ),
    )
    op.create_table(
        "scan_comparison_findings",
        sa.Column("comparison_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("classification", sa.String(32), nullable=False),
        sa.Column("reasons", postgresql.JSONB(), nullable=False),
        sa.Column("evidence", postgresql.JSONB(), nullable=False),
        sa.Column("manual_review_required", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint(
            "comparison_id", "finding_id", name=op.f("pk_scan_comparison_findings")
        ),
        sa.ForeignKeyConstraint(
            ["comparison_id", "target_id"],
            ["scan_comparisons.id", "scan_comparisons.target_id"],
            name=op.f("fk_scan_comparison_findings_comparison_id_target_id_scan_comparisons"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id", "target_id"],
            ["findings.id", "findings.target_id"],
            name=op.f("fk_scan_comparison_findings_finding_id_target_id_findings"),
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "classification IN ('persistent', 'new', 'not_observed', "
            "'inconclusive', 'not_comparable')",
            name=op.f("ck_scan_comparison_findings_classification_valid"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(reasons) = 'array' AND octet_length(reasons::text) <= 16384",
            name=op.f("ck_scan_comparison_findings_reasons_valid"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(evidence) = 'object' AND octet_length(evidence::text) <= 16384",
            name=op.f("ck_scan_comparison_findings_evidence_valid"),
        ),
    )
    op.execute(_COMPARISON_GUARD)
    op.execute(_COMPARISON_ROW_GUARD)
    op.execute(_COMPARISON_SEALED)
    op.execute(
        "CREATE TRIGGER scan_comparison_guard BEFORE INSERT OR UPDATE OR DELETE "
        "ON scan_comparisons "
        "FOR EACH ROW EXECUTE FUNCTION scan_comparison_guard()"
    )
    op.execute(
        "CREATE TRIGGER scan_comparison_no_truncate BEFORE TRUNCATE ON scan_comparisons "
        "FOR EACH STATEMENT EXECUTE FUNCTION scan_records_guard()"
    )
    op.execute(
        "CREATE CONSTRAINT TRIGGER scan_comparison_sealed_check AFTER INSERT ON scan_comparisons "
        "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION scan_comparison_sealed_check()"
    )
    op.execute(
        "CREATE TRIGGER scan_comparison_finding_insert_guard BEFORE INSERT "
        "ON scan_comparison_findings "
        "FOR EACH ROW EXECUTE FUNCTION scan_comparison_finding_insert_guard()"
    )
    op.execute(
        "CREATE TRIGGER scan_comparison_findings_immutable BEFORE UPDATE OR DELETE "
        "ON scan_comparison_findings FOR EACH ROW EXECUTE FUNCTION scan_records_guard()"
    )
    op.execute(
        "CREATE TRIGGER scan_comparison_findings_no_truncate BEFORE TRUNCATE "
        "ON scan_comparison_findings "
        "FOR EACH STATEMENT EXECUTE FUNCTION scan_records_guard()"
    )
