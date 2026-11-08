"""人工 triage 與生命週期、不可修改的事件與人工複測摘錄（T21；docs/DECISIONS.md §28）。

Revision ID: 0017
Revises: 0016
Create Date: 2026-11-08 12:00:00+00:00

升降級說明：
- upgrade：
  - 先鎖住 findings，核對既有的 finding 都是 unreviewed／open（v0013 起只能如此）；有例外就**升級
    失敗**，由人處理。升級前先停 worker 與 api。
  - findings 新增 `triage_version`（每次 triage 或 lifecycle 變更恰好 +1）、`resolved_scan_position`
    與 `resolved_link_count`（只有 resolved 時有值；由 trigger 寫入，不採用 app 給的值）。
    CHECK：resolved ⇒ confirmed；resolved ⇔ 兩個欄位都有值；resolved_link_count ≤ 連結數。
  - findings_guard 改版（保留 v0015 的規則）：新的 finding 版本是 0；triage 欄位只在版本恰好 +1、
    而且 triage 與 lifecycle 恰好改一個時才能改；lifecycle 只允許 open／reopened → resolved 與
    resolved → reopened；resolved 時不能改 triage。轉成 resolved 時以**單一查詢**取得 target 所有
    scan 的最大 queue_position 並確認沒有進行中的 scan（有的話以 findings_resolve_target_busy
    拒絕），
    寫入 watermark 與 `resolved_link_count = observations_linked`；離開 resolved 時清除兩者。
    新的 scan 必須先取得 target 的列鎖才寫入、queue_position 的 cache 是 1，所以這個查詢看不到的
    scan 位置一定比 watermark 大（自動重開的 R3）。
  - finding_triage_events（append-only，scan_records_guard）：PK (finding_id, sequence)。BEFORE
    INSERT 檢查事件鏈（sequence 等於 finding 目前的版本、previous 等於上一筆的新值、新值等於 finding
    目前的狀態），所以先 UPDATE finding、再 INSERT 事件；deferred constraint trigger 在 commit 時
    確認每次升版都有事件。系統事件只能是 resolved → reopened（自動重開），引用 scanner_runs，不直接
    引用 scans（避免與對帳的 scan → run 鎖序形成死鎖，同 v0013）。
  - finding_triage_excerpts：人工複測的遮罩摘錄，與事件分開存放（事件只存 sha256 與長度）。寫入時
    核對雜湊與長度、commit 時 manual_retest 的事件必須恰好有兩段；不可修改。T23a 加上加密與到期清除
    時只改這張表，事件不變。
- downgrade：刪除兩張表、trigger、函式、CHECK 與欄位，恢復 v0015 的 findings_guard，並把 finding
  重設為 unreviewed／open（暫停 guard，同一個 transaction 內恢復）。triage 歷史會消失，只用於開發與
  測試。
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0017"
down_revision: str | Sequence[str] | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# 和 v0015 相同的內容（migration 不 import 應用程式或其他 migration 的程式）。
_SEVERITY_ARRAY = "ARRAY['info', 'low', 'medium', 'high', 'critical']"
_MUTABLE_V15 = (
    "last_seen_run_id",
    "last_seen_scan_id",
    "last_seen_at",
    "normalized_severity",
    "severity_conflict",
    "needs_review",
    "observations_linked",
)
_TRIAGE_COLUMNS = (
    "triage_state",
    "lifecycle_state",
    "triage_version",
    "resolved_scan_position",
    "resolved_link_count",
)
_INTEGRITY = "ERRCODE = 'integrity_constraint_violation'"
_TRIAGE = "'unreviewed', 'confirmed', 'false_positive', 'accepted_risk'"
_LIFECYCLE = "'open', 'resolved', 'reopened'"
_EVIDENCE_KEYS = "ARRAY['classification', 'reasons', 'attestation', 'observation_ids', 'links']"
REASON_MAX_LENGTH = 2000
EVIDENCE_MAX_BYTES = 32768
REQUEST_EXCERPT_MAX_BYTES = 4096
RESPONSE_EXCERPT_MAX_BYTES = 8192
REQUEST_ID_MAX_LENGTH = 64

_SEEN_TARGETS = """
    IF EXISTS (
        SELECT 1 FROM public.scans AS seen
        WHERE seen.id IN (NEW.first_seen_scan_id, NEW.last_seen_scan_id)
            AND seen.target_id <> NEW.target_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'findings: the first and last seen scans belong to the finding''s target';
    END IF;
"""

_TRIAGE_RULES = """
    IF NEW.triage_version IS DISTINCT FROM OLD.triage_version
        OR NEW.triage_state IS DISTINCT FROM OLD.triage_state
        OR NEW.lifecycle_state IS DISTINCT FROM OLD.lifecycle_state
    THEN
        IF NEW.triage_version <> OLD.triage_version + 1 THEN
            RAISE EXCEPTION USING
                ERRCODE = 'integrity_constraint_violation',
                MESSAGE = 'findings: each triage change bumps triage_version by exactly one';
        END IF;
        IF (NEW.triage_state = OLD.triage_state) = (NEW.lifecycle_state = OLD.lifecycle_state) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'integrity_constraint_violation',
                MESSAGE = 'findings: a triage change changes exactly one of triage_state and '
                    || 'lifecycle_state';
        END IF;
        IF NEW.lifecycle_state <> OLD.lifecycle_state AND NOT (
            (OLD.lifecycle_state IN ('open', 'reopened') AND NEW.lifecycle_state = 'resolved')
            OR (OLD.lifecycle_state = 'resolved' AND NEW.lifecycle_state = 'reopened')
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'integrity_constraint_violation',
                MESSAGE = 'findings: lifecycle transition not allowed';
        END IF;
        IF NEW.triage_state <> OLD.triage_state AND OLD.lifecycle_state = 'resolved' THEN
            RAISE EXCEPTION USING
                ERRCODE = 'integrity_constraint_violation',
                MESSAGE = 'findings: triage cannot change while resolved';
        END IF;
        IF NEW.lifecycle_state = 'resolved' THEN
            -- 單一查詢：在兩個 statement 之間提交的 scan 會落在 watermark 之內、永遠不會重開。
            SELECT max(scan.queue_position),
                count(*) FILTER (WHERE scan.status NOT IN (
                    'completed', 'partially_completed', 'failed', 'timed_out', 'cancelled',
                    'interrupted'
                ))
            INTO watermark, active
            FROM public.scans AS scan
            WHERE scan.target_id = NEW.target_id;
            IF active > 0 OR watermark IS NULL THEN
                RAISE EXCEPTION USING
                    ERRCODE = 'integrity_constraint_violation',
                    CONSTRAINT = 'findings_resolve_target_busy',
                    MESSAGE = 'findings: cannot resolve while the target has an active scan';
            END IF;
            NEW.resolved_scan_position := watermark;
            NEW.resolved_link_count := NEW.observations_linked;
        ELSE
            NEW.resolved_scan_position := NULL;
            NEW.resolved_link_count := NULL;
        END IF;
    ELSIF NEW.resolved_scan_position IS DISTINCT FROM OLD.resolved_scan_position
        OR NEW.resolved_link_count IS DISTINCT FROM OLD.resolved_link_count
    THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'findings: the resolution watermark only changes with a lifecycle change';
    END IF;
"""


def _guard(*, triage: bool) -> str:
    """findings_guard：v0015 的內容；triage 時加上 v0017 的規則。"""
    mutable = (*_MUTABLE_V15, *_TRIAGE_COLUMNS) if triage else _MUTABLE_V15
    columns = ", ".join(f"'{column}'" for column in mutable)
    start = (
        "NEW.triage_state <> 'unreviewed' OR NEW.lifecycle_state <> 'open' "
        "OR NEW.triage_version <> 0 OR NEW.resolved_scan_position IS NOT NULL "
        "OR NEW.resolved_link_count IS NOT NULL"
        if triage
        else "NEW.triage_state <> 'unreviewed' OR NEW.lifecycle_state <> 'open'"
    )
    declare = "DECLARE\n    watermark bigint;\n    active bigint;\n" if triage else ""
    rules = _TRIAGE_RULES if triage else ""
    seen = _SEEN_TARGETS
    return f"""
CREATE OR REPLACE FUNCTION findings_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
{declare}BEGIN
    IF TG_OP = 'INSERT' THEN
        IF {start} THEN
            RAISE EXCEPTION USING
                {_INTEGRITY},
                MESSAGE = 'findings: new rows start unreviewed and open';
        END IF;{seen}
        RETURN NEW;
    END IF;
    IF TG_OP <> 'UPDATE' THEN
        RAISE EXCEPTION USING
            {_INTEGRITY},
            MESSAGE = 'findings rows cannot be removed (' || TG_OP || ' blocked)';
    END IF;
    IF (to_jsonb(NEW) - ARRAY[{columns}]) IS DISTINCT FROM (to_jsonb(OLD) - ARRAY[{columns}])
    THEN
        RAISE EXCEPTION USING
            {_INTEGRITY},
            MESSAGE = 'findings: only the last seen run and the aggregates can change';
    END IF;
    IF array_position({_SEVERITY_ARRAY}, NEW.normalized_severity)
            < array_position({_SEVERITY_ARRAY}, OLD.normalized_severity)
        OR NEW.severity_conflict < OLD.severity_conflict
        OR NEW.needs_review < OLD.needs_review
        OR NEW.last_seen_at < OLD.last_seen_at
        OR NEW.observations_linked < OLD.observations_linked
    THEN
        RAISE EXCEPTION USING
            {_INTEGRITY},
            MESSAGE = 'findings: aggregates only move upwards';
    END IF;
    IF NEW.last_seen_scan_id IS DISTINCT FROM OLD.last_seen_scan_id THEN{seen}    END IF;{rules}
    RETURN NEW;
END;
$$
"""


_LOGGED = """
CREATE FUNCTION findings_triage_logged() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM public.finding_triage_events AS event
        WHERE event.finding_id = NEW.id AND event.sequence = NEW.triage_version
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'findings: every triage_version needs exactly one triage event';
    END IF;
    RETURN NULL;
END;
$$
"""

_CHAIN = """
CREATE FUNCTION finding_triage_events_chain() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
    current_triage text;
    current_lifecycle text;
    current_version bigint;
    previous_triage text;
    previous_lifecycle text;
BEGIN
    SELECT finding.triage_state, finding.lifecycle_state, finding.triage_version
    INTO current_triage, current_lifecycle, current_version
    FROM public.findings AS finding
    WHERE finding.id = NEW.finding_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'foreign_key_violation',
            MESSAGE = 'finding_triage_events: the finding does not exist';
    END IF;
    IF NEW.sequence <> current_version THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'finding_triage_events: sequence must equal the finding''s triage_version '
                || '(update the finding first)';
    END IF;
    IF NEW.scan_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM public.scans AS scan
        WHERE scan.id = NEW.scan_id AND scan.target_id = NEW.target_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'finding_triage_events: the run belongs to another target';
    END IF;
    IF NEW.triage_state <> current_triage OR NEW.lifecycle_state <> current_lifecycle THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'finding_triage_events: the new states must equal the finding';
    END IF;
    IF NEW.sequence = 1 THEN
        previous_triage := 'unreviewed';
        previous_lifecycle := 'open';
    ELSE
        SELECT event.triage_state, event.lifecycle_state
        INTO previous_triage, previous_lifecycle
        FROM public.finding_triage_events AS event
        WHERE event.finding_id = NEW.finding_id AND event.sequence = NEW.sequence - 1;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = 'integrity_constraint_violation',
                MESSAGE = 'finding_triage_events: the previous event is missing';
        END IF;
    END IF;
    IF NEW.previous_triage_state <> previous_triage
        OR NEW.previous_lifecycle_state <> previous_lifecycle
    THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'finding_triage_events: the previous states must equal the last event';
    END IF;
    RETURN NEW;
END;
$$
"""

_EXCERPT_INSERT = """
CREATE FUNCTION finding_triage_excerpts_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
    basis text;
    expected_sha text;
    expected_bytes text;
BEGIN
    SELECT event.resolution_basis,
        event.evidence -> 'attestation' ->> (NEW.kind || '_excerpt_sha256'),
        event.evidence -> 'attestation' ->> (NEW.kind || '_excerpt_bytes')
    INTO basis, expected_sha, expected_bytes
    FROM public.finding_triage_events AS event
    WHERE event.finding_id = NEW.finding_id AND event.sequence = NEW.sequence;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'foreign_key_violation',
            MESSAGE = 'finding_triage_excerpts: the triage event does not exist';
    END IF;
    IF basis IS DISTINCT FROM 'manual_retest' THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'finding_triage_excerpts: only manual_retest events have excerpts';
    END IF;
    IF encode(sha256(convert_to(NEW.content, 'UTF8')), 'hex') IS DISTINCT FROM expected_sha
        OR octet_length(NEW.content)::text IS DISTINCT FROM expected_bytes
    THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'finding_triage_excerpts: content does not match the recorded hash';
    END IF;
    RETURN NEW;
END;
$$
"""

_EXCERPTS_COMPLETE = """
CREATE FUNCTION finding_triage_excerpts_complete() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF (
        SELECT count(*) FROM public.finding_triage_excerpts AS excerpt
        WHERE excerpt.finding_id = NEW.finding_id AND excerpt.sequence = NEW.sequence
    ) <> 2 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'finding_triage_events: a manual_retest event needs both excerpts';
    END IF;
    RETURN NULL;
END;
$$
"""

_EVENT_CHECKS = {
    "sequence_positive": "sequence >= 1",
    "actor_kind_valid": "actor_kind IN ('key', 'system')",
    "states_valid": (
        f"previous_triage_state IN ({_TRIAGE}) AND triage_state IN ({_TRIAGE}) "
        f"AND previous_lifecycle_state IN ({_LIFECYCLE}) AND lifecycle_state IN ({_LIFECYCLE})"
    ),
    "one_change": (
        "(previous_triage_state = triage_state) <> (previous_lifecycle_state = lifecycle_state)"
    ),
    "reason_code_valid": "reason_code IN ('manual', 'auto_reopen_new_observation')",
    "reason_valid": (
        f"char_length(btrim(reason)) > 0 AND char_length(reason) <= {REASON_MAX_LENGTH}"
    ),
    "basis_valid": (
        "resolution_basis IS NULL OR resolution_basis IN ('rescan_not_observed', 'manual_retest')"
    ),
    "evidence_valid": (
        f"jsonb_typeof(evidence) = 'object' AND octet_length(evidence::text) <= "
        f"{EVIDENCE_MAX_BYTES} AND (evidence - {_EVIDENCE_KEYS}) = jsonb_build_object()"
    ),
    "actor_valid": "(actor_kind = 'key') = (actor_key_id IS NOT NULL)",
    "system_valid": (
        "(actor_kind = 'system') = (run_id IS NOT NULL) AND (run_id IS NULL) = (scan_id IS NULL) "
        "AND (actor_kind = 'system') = (reason_code = 'auto_reopen_new_observation') "
        "AND (actor_kind <> 'system' OR (previous_lifecycle_state = 'resolved' "
        "AND lifecycle_state = 'reopened'))"
    ),
    "resolution_valid": (
        "(lifecycle_state = 'resolved' AND previous_lifecycle_state <> 'resolved') "
        "= (comparison_id IS NOT NULL) AND (comparison_id IS NULL) = (resolution_basis IS NULL)"
    ),
    "attestation_valid": (
        "(resolution_basis IS NOT DISTINCT FROM 'manual_retest') = (evidence ? 'attestation') "
        "AND (resolution_basis IS DISTINCT FROM 'manual_retest' "
        "OR COALESCE(jsonb_typeof(evidence -> 'attestation') = 'object' "
        "AND evidence -> 'attestation' ->> 'provenance' = 'operator_supplied', false))"
    ),
}
_FINDING_CHECKS = {
    "triage_version_valid": "triage_version >= 0",
    "resolution_confirmed": "lifecycle_state <> 'resolved' OR triage_state = 'confirmed'",
    "resolution_watermark": (
        "(lifecycle_state = 'resolved') = (resolved_scan_position IS NOT NULL) "
        "AND (resolved_scan_position IS NULL) = (resolved_link_count IS NULL) "
        "AND (resolved_link_count IS NULL OR resolved_link_count <= observations_linked)"
    ),
}
_VERIFY = """
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM findings WHERE triage_state <> 'unreviewed' OR lifecycle_state <> 'open'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'v0017: existing findings are not unreviewed and open; fix them first';
    END IF;
END
$$
"""
_IMMUTABLE = ("finding_triage_events", "finding_triage_excerpts")


def upgrade() -> None:
    # 一開始就取 ACCESS EXCLUSIVE：ADD COLUMN 也要它，先取較弱的鎖再升級可能與讀取者死鎖。
    op.execute("LOCK TABLE findings IN ACCESS EXCLUSIVE MODE")
    op.execute(_VERIFY)
    op.add_column(
        "findings",
        sa.Column("triage_version", sa.BigInteger(), server_default="0", nullable=False),
    )
    op.add_column("findings", sa.Column("resolved_scan_position", sa.BigInteger()))
    op.add_column("findings", sa.Column("resolved_link_count", sa.BigInteger()))
    for name, condition in _FINDING_CHECKS.items():
        op.create_check_constraint(op.f(f"ck_findings_{name}"), "findings", condition)
    op.execute(_guard(triage=True))
    _create_events()
    _create_excerpts()
    op.execute(_LOGGED)
    op.execute(
        "CREATE CONSTRAINT TRIGGER findings_triage_logged AFTER UPDATE ON findings "
        "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW "
        "WHEN (NEW.triage_version IS DISTINCT FROM OLD.triage_version) "
        "EXECUTE FUNCTION findings_triage_logged()"
    )


def _create_events() -> None:
    op.create_table(
        "finding_triage_events",
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("actor_kind", sa.String(16), nullable=False),
        sa.Column("actor_key_id", sa.Uuid()),
        sa.Column("request_id", sa.String(REQUEST_ID_MAX_LENGTH)),
        sa.Column("previous_triage_state", sa.String(32), nullable=False),
        sa.Column("triage_state", sa.String(32), nullable=False),
        sa.Column("previous_lifecycle_state", sa.String(32), nullable=False),
        sa.Column("lifecycle_state", sa.String(32), nullable=False),
        sa.Column("reason_code", sa.String(32), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("comparison_id", sa.Uuid()),
        sa.Column("resolution_basis", sa.String(32)),
        sa.Column("run_id", sa.Uuid()),
        sa.Column("scan_id", sa.Uuid()),
        sa.Column(
            "evidence",
            postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("clock_timestamp()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("finding_id", "sequence", name=op.f("pk_finding_triage_events")),
        sa.ForeignKeyConstraint(
            ["finding_id", "target_id"],
            ["findings.id", "findings.target_id"],
            name=op.f("fk_finding_triage_events_finding_id_target_id_findings"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["actor_key_id"],
            ["api_keys.id"],
            name=op.f("fk_finding_triage_events_actor_key_id_api_keys"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["comparison_id", "target_id"],
            ["scan_comparisons.id", "scan_comparisons.target_id"],
            name=op.f("fk_finding_triage_events_comparison_id_target_id_scan_comparisons"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["run_id", "scan_id"],
            ["scanner_runs.id", "scanner_runs.scan_id"],
            name=op.f("fk_finding_triage_events_run_id_scan_id_scanner_runs"),
            ondelete="RESTRICT",
        ),
        # 引用的比較快照必須含有這個 finding 的那一列（證據門檻也檢查；DB 再擋一次）。
        sa.ForeignKeyConstraint(
            ["comparison_id", "finding_id"],
            ["scan_comparison_findings.comparison_id", "scan_comparison_findings.finding_id"],
            name=op.f("fk_finding_triage_events_comparison_id_finding_id_scan_comparison_findings"),
            ondelete="RESTRICT",
        ),
        *(
            sa.CheckConstraint(condition, name=op.f(f"ck_finding_triage_events_{name}"))
            for name, condition in _EVENT_CHECKS.items()
        ),
    )
    for columns in (["actor_key_id"], ["comparison_id", "target_id"], ["run_id", "scan_id"]):
        op.create_index(
            op.f(f"ix_finding_triage_events_{'_'.join(columns)}"),
            "finding_triage_events",
            columns,
        )
    op.execute(_CHAIN)
    op.execute(
        "CREATE TRIGGER finding_triage_events_chain BEFORE INSERT ON finding_triage_events "
        "FOR EACH ROW EXECUTE FUNCTION finding_triage_events_chain()"
    )


def _create_excerpts() -> None:
    op.create_table(
        "finding_triage_excerpts",
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint(
            "finding_id", "sequence", "kind", name=op.f("pk_finding_triage_excerpts")
        ),
        sa.ForeignKeyConstraint(
            ["finding_id", "sequence"],
            ["finding_triage_events.finding_id", "finding_triage_events.sequence"],
            name=op.f("fk_finding_triage_excerpts_finding_id_sequence_finding_triage_events"),
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "kind IN ('request', 'response')", name=op.f("ck_finding_triage_excerpts_kind_valid")
        ),
        sa.CheckConstraint(
            f"octet_length(content) >= 1 AND octet_length(content) <= CASE kind "
            f"WHEN 'request' THEN {REQUEST_EXCERPT_MAX_BYTES} "
            f"ELSE {RESPONSE_EXCERPT_MAX_BYTES} END",
            name=op.f("ck_finding_triage_excerpts_content_size"),
        ),
    )
    op.execute(_EXCERPT_INSERT)
    op.execute(
        "CREATE TRIGGER finding_triage_excerpts_insert BEFORE INSERT ON finding_triage_excerpts "
        "FOR EACH ROW EXECUTE FUNCTION finding_triage_excerpts_insert()"
    )
    op.execute(_EXCERPTS_COMPLETE)
    op.execute(
        "CREATE CONSTRAINT TRIGGER finding_triage_excerpts_complete "
        "AFTER INSERT ON finding_triage_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW "
        "WHEN (NEW.resolution_basis = 'manual_retest') "
        "EXECUTE FUNCTION finding_triage_excerpts_complete()"
    )
    for table in _IMMUTABLE:
        op.execute(
            f"CREATE TRIGGER {table}_immutable BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION scan_records_guard()"
        )
        op.execute(
            f"CREATE TRIGGER {table}_no_truncate BEFORE TRUNCATE ON {table} "
            "FOR EACH STATEMENT EXECUTE FUNCTION scan_records_guard()"
        )


def downgrade() -> None:
    op.execute("DROP TRIGGER findings_triage_logged ON findings")
    op.execute("DROP FUNCTION findings_triage_logged()")
    op.drop_table("finding_triage_excerpts")
    op.drop_table("finding_triage_events")
    for function in (
        "finding_triage_excerpts_complete",
        "finding_triage_excerpts_insert",
        "finding_triage_events_chain",
    ):
        op.execute(f"DROP FUNCTION {function}()")
    op.execute(_guard(triage=False))
    op.execute("ALTER TABLE findings DISABLE TRIGGER findings_guard_rows")
    op.execute(
        "UPDATE findings SET triage_state = 'unreviewed', lifecycle_state = 'open', "
        "triage_version = 0, resolved_scan_position = NULL, resolved_link_count = NULL"
    )
    op.execute("ALTER TABLE findings ENABLE TRIGGER findings_guard_rows")
    for name in _FINDING_CHECKS:
        op.drop_constraint(op.f(f"ck_findings_{name}"), "findings", type_="check")
    op.drop_column("findings", "resolved_link_count")
    op.drop_column("findings", "resolved_scan_position")
    op.drop_column("findings", "triage_version")
