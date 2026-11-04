"""finding 的連結序號與跨表的 target 一致性（T20；docs/DECISIONS.md §26）。

Revision ID: 0015
Revises: 0014
Create Date: 2026-11-04 18:00:00+00:00

升降級說明：
- upgrade：
  - 先鎖住 findings 與 finding_observations，再核對既有資料：連結的觀察與 finding 屬於不同
    target、或 first／last seen 的 scan 不屬於 finding 的 target 時**升級失敗**（fail closed，由人
    處理；不靜默排除）。升級前先停 worker。
  - findings 新增 `observations_linked`（已連結的觀察數，只會增加）；finding_observations 新增
    `link_sequence`（這個 finding 的第幾個連結，1 起算、不重複）。既有的連結依
    (created_at, observation_id) 回填序號：這是基準順序，不是原本 commit 的時間。回填時暫停兩張表
    的不可變 trigger（同一個 transaction 內，結束前恢復）。
  - 配號：linker 持有 finding 的列鎖（新增或 FOR UPDATE），每個 finding 每個 transaction 以一次
    `observations_linked + k` 保留 k 個序號，連結帶著這些序號寫入。trigger finding_observations_link
    （BEFORE INSERT）檢查序號不超過這個 transaction 看得到的連結數、觀察所屬 scan 的 target 等於
    finding 的 target；deferred 的 constraint trigger 在 commit 時核對連結數等於這個 finding 的連結
    筆數（配合 (finding_id, link_sequence) unique 與序號 > 0，序號恰好是 1..連結數，不留空號）。
    同一個 finding 的配號以列鎖排隊，所以連結依序號的順序提交：讀取時以
    `link_sequence <= observations_linked` 取得一致的快照（追溯 API 的分頁）。不逐列更新 finding
    （同一列在一個 transaction 中更新上萬次是二次方的成本，量測見 §26.4）。
  - findings_guard 改版：observations_linked 只能增加；first／last seen 的 scan 必須屬於 finding 的
    target（找不到 scan 時交給 FK）。只用不加鎖的 SELECT：被讀的 target_id、scan_id 都不可修改
    （scans_guard、append-only）。
  - ix_finding_observations_finding_id 由 (finding_id, link_sequence) 的 unique 取代。
- downgrade：恢復 v0014 的 findings_guard 與索引，刪除 trigger、函式、兩個欄位與約束；序號與連結
  數會消失（連結本身保留）。只用於開發與測試。
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str | Sequence[str] | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# 和 v0013 相同的內容（migration 不 import 應用程式或其他 migration 的程式）。
_SEVERITY_ARRAY = "ARRAY['info', 'low', 'medium', 'high', 'critical']"
_MUTABLE_V13 = (
    "last_seen_run_id",
    "last_seen_scan_id",
    "last_seen_at",
    "normalized_severity",
    "severity_conflict",
    "needs_review",
)
_MUTABLE_V15 = (*_MUTABLE_V13, "observations_linked")
_INTEGRITY = "ERRCODE = 'integrity_constraint_violation'"
_SEEN_TARGETS = """
    IF EXISTS (
        SELECT 1 FROM public.scans AS seen
        WHERE seen.id IN (NEW.first_seen_scan_id, NEW.last_seen_scan_id)
            AND seen.target_id <> NEW.target_id
    ) THEN
        RAISE EXCEPTION USING
            {integrity},
            MESSAGE = 'findings: the first and last seen scans belong to the finding''s target';
    END IF;
"""


def _guard(mutable: Sequence[str], *, provenance: bool) -> str:
    """findings_guard：v0013 的內容；provenance 時加上連結數與 target 的檢查（v0015）。"""
    columns = ", ".join(f"'{column}'" for column in mutable)
    seen = _SEEN_TARGETS.format(integrity=_INTEGRITY) if provenance else ""
    increasing = (
        "\n        OR NEW.observations_linked < OLD.observations_linked" if provenance else ""
    )
    seen_on_update = (
        f"""
    IF NEW.last_seen_scan_id IS DISTINCT FROM OLD.last_seen_scan_id THEN{seen}    END IF;"""
        if provenance
        else ""
    )
    return f"""
CREATE OR REPLACE FUNCTION findings_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.triage_state <> 'unreviewed' OR NEW.lifecycle_state <> 'open' THEN
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
        OR NEW.last_seen_at < OLD.last_seen_at{increasing}
    THEN
        RAISE EXCEPTION USING
            {_INTEGRITY},
            MESSAGE = 'findings: aggregates only move upwards';
    END IF;{seen_on_update}
    RETURN NEW;
END;
$$
"""


# 連結的序號必須已由這個 transaction 保留（不超過看得到的連結數；其他 transaction 保留、還沒提交的
# 序號看不到，所以也不能用）。找不到 finding 時以 FK 的錯誤碼拒絕；找不到觀察時交給 FK。
_CREATE_LINK_FUNCTION = """
CREATE FUNCTION finding_observations_link() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
    observed_target uuid;
    finding_target uuid;
    reserved bigint;
BEGIN
    SELECT scan.target_id INTO observed_target
    FROM public.observations AS observation
    JOIN public.scans AS scan ON scan.id = observation.scan_id
    WHERE observation.id = NEW.observation_id;
    SELECT finding.target_id, finding.observations_linked INTO finding_target, reserved
    FROM public.findings AS finding
    WHERE finding.id = NEW.finding_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'foreign_key_violation',
            MESSAGE = 'finding_observations: the finding does not exist';
    END IF;
    IF observed_target IS NOT NULL AND observed_target <> finding_target THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'finding_observations: the observation and the finding belong to '
                || 'different targets';
    END IF;
    IF NEW.link_sequence > reserved THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'finding_observations: link_sequence was not reserved on the finding';
    END IF;
    RETURN NEW;
END;
$$
"""

# commit 時：保留的序號都有連結（連結數等於筆數）。每個 finding 每個 transaction 一次 count。
_CREATE_COMPLETE_FUNCTION = """
CREATE FUNCTION findings_links_complete() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF (SELECT finding.observations_linked FROM public.findings AS finding
            WHERE finding.id = NEW.id)
        <> (SELECT count(*) FROM public.finding_observations AS link
            WHERE link.finding_id = NEW.id)
    THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'findings: observations_linked does not match the linked observations';
    END IF;
    RETURN NULL;
END;
$$
"""
_COMPLETE_TRIGGERS = (
    "CREATE CONSTRAINT TRIGGER findings_links_complete_insert AFTER INSERT ON findings "
    "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION findings_links_complete()",
    "CREATE CONSTRAINT TRIGGER findings_links_complete_update AFTER UPDATE ON findings "
    "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW "
    "WHEN (NEW.observations_linked IS DISTINCT FROM OLD.observations_linked) "
    "EXECUTE FUNCTION findings_links_complete()",
)

# 升級前的核對：任何一列不一致就停止。以 SQL 執行，離線模式（alembic --sql）也一樣會產生。
_VERIFY_TARGETS = """
DO $$
DECLARE
    mixed_links bigint;
    mixed_seen bigint;
BEGIN
    SELECT count(*) INTO mixed_links FROM finding_observations AS link
    JOIN findings AS finding ON finding.id = link.finding_id
    JOIN observations AS observation ON observation.id = link.observation_id
    JOIN scans AS scan ON scan.id = observation.scan_id
    WHERE scan.target_id <> finding.target_id;
    SELECT count(*) INTO mixed_seen FROM findings AS finding
    JOIN scans AS seen ON seen.id IN (finding.first_seen_scan_id, finding.last_seen_scan_id)
    WHERE seen.target_id <> finding.target_id;
    IF mixed_links > 0 OR mixed_seen > 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'v0015: existing rows mix targets (links ' || mixed_links
                || ', first or last seen ' || mixed_seen || '); fix them before upgrading';
    END IF;
END
$$
"""
_BACKFILL_SEQUENCES = """
UPDATE finding_observations AS link SET link_sequence = ordered.sequence
FROM (
    SELECT observation_id,
        row_number() OVER (PARTITION BY finding_id ORDER BY created_at, observation_id) AS sequence
    FROM finding_observations
) AS ordered
WHERE ordered.observation_id = link.observation_id
"""
_BACKFILL_COUNTS = """
UPDATE findings AS finding SET observations_linked = counted.linked
FROM (
    SELECT finding_id, count(*) AS linked FROM finding_observations GROUP BY finding_id
) AS counted
WHERE counted.finding_id = finding.id
"""


def upgrade() -> None:
    op.execute("LOCK TABLE findings, finding_observations IN SHARE ROW EXCLUSIVE MODE")
    op.execute(_VERIFY_TARGETS)
    op.add_column(
        "findings",
        sa.Column("observations_linked", sa.BigInteger(), server_default="0", nullable=False),
    )
    op.add_column("finding_observations", sa.Column("link_sequence", sa.BigInteger()))
    op.execute("ALTER TABLE findings DISABLE TRIGGER findings_guard_rows")
    op.execute("ALTER TABLE finding_observations DISABLE TRIGGER finding_observations_immutable")
    op.execute(_BACKFILL_SEQUENCES)
    op.execute(_BACKFILL_COUNTS)
    op.execute("ALTER TABLE finding_observations ENABLE TRIGGER finding_observations_immutable")
    op.execute("ALTER TABLE findings ENABLE TRIGGER findings_guard_rows")
    op.alter_column("finding_observations", "link_sequence", nullable=False)
    op.create_check_constraint(
        op.f("ck_findings_observations_linked_valid"), "findings", "observations_linked >= 0"
    )
    op.create_check_constraint(
        op.f("ck_finding_observations_link_sequence_valid"),
        "finding_observations",
        "link_sequence > 0",
    )
    op.drop_index("ix_finding_observations_finding_id", table_name="finding_observations")
    op.create_unique_constraint(
        op.f("uq_finding_observations_finding_id_link_sequence"),
        "finding_observations",
        ["finding_id", "link_sequence"],
    )
    op.execute(_guard(_MUTABLE_V15, provenance=True))
    op.execute(_CREATE_LINK_FUNCTION)
    op.execute(
        "CREATE TRIGGER finding_observations_link BEFORE INSERT ON finding_observations "
        "FOR EACH ROW EXECUTE FUNCTION finding_observations_link()"
    )
    op.execute(_CREATE_COMPLETE_FUNCTION)
    for statement in _COMPLETE_TRIGGERS:
        op.execute(statement)


def downgrade() -> None:
    op.execute("DROP TRIGGER findings_links_complete_update ON findings")
    op.execute("DROP TRIGGER findings_links_complete_insert ON findings")
    op.execute("DROP FUNCTION findings_links_complete()")
    op.execute("DROP TRIGGER finding_observations_link ON finding_observations")
    op.execute("DROP FUNCTION finding_observations_link()")
    op.execute(_guard(_MUTABLE_V13, provenance=False))
    op.drop_constraint(
        op.f("uq_finding_observations_finding_id_link_sequence"),
        "finding_observations",
        type_="unique",
    )
    op.create_index(
        "ix_finding_observations_finding_id", "finding_observations", ["finding_id"], unique=False
    )
    op.drop_constraint(
        op.f("ck_finding_observations_link_sequence_valid"), "finding_observations", type_="check"
    )
    op.drop_constraint(op.f("ck_findings_observations_linked_valid"), "findings", type_="check")
    op.drop_column("finding_observations", "link_sequence")
    op.drop_column("findings", "observations_linked")
