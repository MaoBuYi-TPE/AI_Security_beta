"""報告內容與人工複測摘錄的加密、到期與清除（T23a；docs/DECISIONS.md §30.4、§30.5）。

Revision ID: 0022
Revises: 0021
Create Date: 2026-11-09 18:00:00+00:00

升降級說明：
- 先停 api 與 worker；升級需要 CONTENT_ENCRYPTION_KEYS（只有在已經有報告或摘錄時才需要：
  migrations/env.py 由設定放進 config.attributes，不讀 os.environ）。所有 ALTER TABLE 都在資料的
  UPDATE 之前，最後才加上 CHECK 與 NOT NULL（之間沒有 deferred trigger 的 pending event）。
- reports：
  - 新增 expires_at（只在 generating → succeeded 時寫入）與 content_purged_at（只能寫一次，必須已
    到期、其他欄位都不變）。改寫 reports_guard。
  - reports_content_check 改成只在轉為 succeeded 時觸發，只核對這一次嘗試的內容存在：內容是密文，
    明文的 sha256 與大小改由 worker 寫入、下載時解密後核對（app 層）。
  - CHECK：succeeded ⇔ 有 expires_at；content_purged_at 不早於 expires_at。
- report_contents：改用自己的 report_contents_guard（不再用共用的 scan_records_guard）：只允許換版時
  更新 content（其他欄位不變、報告未清除），以及報告寫入 content_purged_at 之後刪除。內容的 CHECK
  改成 Fernet token 的形狀（gAAAAA 開頭）與密文的上限。
- finding_triage_excerpts：content（TEXT）換成 sealed_content（bytea，可為 NULL），加上 expires_at
  與 purged_at；改用自己的 finding_triage_excerpts_guard：只允許換版（密文換密文）與只能一次的清除
  （sealed_content 變成 NULL、寫入 purged_at、必須已到期）。不能刪除：留下 tombstone，「每個人工
  複測事件恰好兩筆」不變。新增時的 trigger 保留事件的檢查，拿掉明文雜湊的檢查（改由 api 核對）。
- 既有的資料（同一個 transaction）：
  - 既有的報告與摘錄 expires_at 一律是升級時間加 30 天（不會一升級就清除）；
  - 舊的明文在核對 sha256 與大小之後加密（context 和 app 相同：`report:<id>`、
    `excerpt:<finding>:<sequence>:<kind>`）；核對不符或缺少金鑰就停止，整個升級回滾。
  - 例外：這個 migration import secscan.security（加密元件；理由見 docs/DECISIONS.md §30.4）。
- 離線模式（--sql）：不在 Python 中加密；產生的 SQL 先以 DO 區塊確認沒有既有的報告內容與摘錄，有就
  報錯（請改用線上升級）。
- downgrade：還有報告內容或摘錄時拒絕（舊版本只認得明文）；否則還原 0018、0017 的 trigger、函式、
  CHECK 與欄位。只用於開發與測試。
"""

import hashlib
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op
from pydantic import SecretStr
from sqlalchemy.engine import Connection

from secscan.security.blob_cipher import BlobCipher
from secscan.security.key_rings import CONTENT_SETTING, content_cipher

revision: str = "0022"
down_revision: str | Sequence[str] | None = "0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# 和 secscan.migrations.CONTENT_KEYS_ATTRIBUTE 相同（env.py 由設定放入）。
KEYS_ATTRIBUTE = "content_encryption_keys"
MAX_REPORT_BYTES = 8_388_608
REQUEST_EXCERPT_MAX_BYTES = 4096
RESPONSE_EXCERPT_MAX_BYTES = 8192
# 密文的上限（security.blob_cipher.max_sealed_blob_bytes；context 最長 43 與 80 個字元）。
MAX_SEALED_REPORT_BYTES = 11_184_972
MAX_SEALED_REQUEST_BYTES = 5_688
MAX_SEALED_RESPONSE_BYTES = 11_148
_FERNET_SHAPE = "substring({column} FROM 1 FOR 6) = 'gAAAAA'::bytea"

# 和 v0018 相同的可變欄位，加上 expires_at（content_purged_at 只能由清除的路徑寫入）。
_MUTABLE_V18 = (
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


def _columns(names: Sequence[str]) -> str:
    return ", ".join(f"'{name}'" for name in names)


_REPORT_CHECKS = {
    "expires_matches_status": "(status = 'succeeded') = (expires_at IS NOT NULL)",
    "purged_after_expiry": (
        "content_purged_at IS NULL OR (status = 'succeeded' AND content_purged_at >= expires_at)"
    ),
}
_CONTENT_CHECK = (
    f"octet_length(content) >= 1 AND octet_length(content) <= {MAX_SEALED_REPORT_BYTES} "
    f"AND {_FERNET_SHAPE.format(column='content')}"
)
_EXCERPT_CHECKS = {
    "purged_matches_content": "(sealed_content IS NULL) = (purged_at IS NOT NULL)",
    "sealed_content_valid": (
        "sealed_content IS NULL OR ("
        f"{_FERNET_SHAPE.format(column='sealed_content')} "
        "AND octet_length(sealed_content) <= CASE kind "
        f"WHEN 'request' THEN {MAX_SEALED_REQUEST_BYTES} ELSE {MAX_SEALED_RESPONSE_BYTES} END)"
    ),
    "purged_after_expiry": "purged_at IS NULL OR purged_at >= expires_at",
}

# 不用 RAISE 的 % 格式字串（SQLAlchemy 會跳脫文字 SQL 裡的 %）；固定 search_path（同 0009）。
_REPORTS_GUARD = (
    """
CREATE OR REPLACE FUNCTION reports_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'queued' OR NEW.attempts <> 0 OR NEW.expires_at IS NOT NULL
            OR NEW.content_purged_at IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
                MESSAGE = 'reports: new rows start queued with no attempts';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP <> 'UPDATE' THEN
        RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'reports rows cannot be removed (' || TG_OP || ' blocked)';
    END IF;
    -- 到期清除（v0022）：已完成的報告只能寫入一次 content_purged_at，其他欄位不變。
    IF OLD.status = 'succeeded' AND OLD.content_purged_at IS NULL
        AND NEW.content_purged_at IS NOT NULL AND OLD.expires_at <= clock_timestamp()
        AND (to_jsonb(NEW) - 'content_purged_at') = (to_jsonb(OLD) - 'content_purged_at') THEN
        RETURN NEW;
    END IF;
    IF OLD.status IN ('succeeded', 'failed') THEN
        RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'reports: finished reports are immutable except the purge after expiry';
    END IF;
    IF (to_jsonb(NEW) - ARRAY["""
    + _columns((*_MUTABLE_V18, "expires_at"))
    + """]) IS DISTINCT FROM (to_jsonb(OLD) - ARRAY["""
    + _columns((*_MUTABLE_V18, "expires_at"))
    + """]) THEN
        RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'reports: only the status, lease and result can change';
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
_CONTENT_CHECK_FUNCTION = """
CREATE OR REPLACE FUNCTION reports_content_check() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM public.report_contents AS stored
        WHERE stored.report_id = NEW.id AND stored.attempt = NEW.attempts
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'reports: succeeded reports need content from the same attempt';
    END IF;
    RETURN NULL;
END;
$$
"""
_CONTENT_CHECK_TRIGGER = (
    "CREATE CONSTRAINT TRIGGER reports_content_check AFTER UPDATE ON reports "
    "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW "
    "WHEN (OLD.status IS DISTINCT FROM 'succeeded' AND NEW.status = 'succeeded') "
    "EXECUTE FUNCTION reports_content_check()"
)
_CONTENTS_GUARD = """
CREATE FUNCTION report_contents_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
    parent_status text;
    parent_purged timestamptz;
BEGIN
    SELECT report.status, report.content_purged_at INTO parent_status, parent_purged
    FROM public.reports AS report WHERE report.id = OLD.report_id;
    IF TG_OP = 'UPDATE' THEN
        -- 換版：只有內容（密文）可以換，報告必須是 succeeded 而且還沒清除。
        IF NEW.report_id = OLD.report_id AND NEW.attempt = OLD.attempt
            AND NEW.lease_owner = OLD.lease_owner
            AND parent_status = 'succeeded' AND parent_purged IS NULL THEN
            RETURN NEW;
        END IF;
    ELSIF TG_OP = 'DELETE' THEN
        -- 到期清除：報告已寫入 content_purged_at（同一個 transaction 先寫）。
        IF parent_purged IS NOT NULL THEN
            RETURN OLD;
        END IF;
    END IF;
    RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
        MESSAGE = 'report_contents: ' || TG_OP || ' blocked; only rotation and purge after expiry';
END;
$$
"""
_EXCERPT_INSERT = """
CREATE OR REPLACE FUNCTION finding_triage_excerpts_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
    basis text;
BEGIN
    SELECT event.resolution_basis INTO basis
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
    IF NEW.sealed_content IS NULL OR NEW.purged_at IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'finding_triage_excerpts: new excerpts must be sealed';
    END IF;
    RETURN NEW;
END;
$$
"""
_EXCERPTS_GUARD = """
CREATE FUNCTION finding_triage_excerpts_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        -- 換版：密文換成新的密文，其他欄位不變。
        IF OLD.purged_at IS NULL AND NEW.purged_at IS NULL
            AND OLD.sealed_content IS NOT NULL AND NEW.sealed_content IS NOT NULL
            AND (to_jsonb(NEW) - 'sealed_content') = (to_jsonb(OLD) - 'sealed_content') THEN
            RETURN NEW;
        END IF;
        -- 到期清除：只能一次（留下 tombstone）。
        IF OLD.purged_at IS NULL AND NEW.purged_at IS NOT NULL AND NEW.sealed_content IS NULL
            AND OLD.expires_at <= clock_timestamp()
            AND (to_jsonb(NEW) - 'sealed_content' - 'purged_at')
                = (to_jsonb(OLD) - 'sealed_content' - 'purged_at') THEN
            RETURN NEW;
        END IF;
    END IF;
    RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
        MESSAGE = 'finding_triage_excerpts: ' || TG_OP || ' blocked; only rotation and purge';
END;
$$
"""
_REFUSE_OFFLINE = """
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM report_contents) OR EXISTS (SELECT 1 FROM finding_triage_excerpts) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'object_in_use',
            MESSAGE = 'v0022: existing reports or excerpts must be encrypted; run the upgrade '
                || 'online with CONTENT_ENCRYPTION_KEYS instead of --sql';
    END IF;
END;
$$
"""
_REFUSE_DOWNGRADE = """
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM report_contents) OR EXISTS (SELECT 1 FROM finding_triage_excerpts)
        OR EXISTS (SELECT 1 FROM reports WHERE content_purged_at IS NOT NULL) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'object_in_use',
            MESSAGE = 'v0022: encrypted or purged content exists; the previous version only '
                || 'reads plaintext';
    END IF;
END;
$$
"""


def upgrade() -> None:
    if context.is_offline_mode():
        op.execute(_REFUSE_OFFLINE)
    _alter_reports()
    _alter_excerpts()
    if not context.is_offline_mode():
        _migrate_existing(op.get_bind())
    _finish()


def _alter_reports() -> None:
    op.add_column("reports", sa.Column("expires_at", sa.DateTime(timezone=True)))
    op.add_column("reports", sa.Column("content_purged_at", sa.DateTime(timezone=True)))
    op.execute(_REPORTS_GUARD)
    op.execute("DROP TRIGGER reports_content_check ON reports")
    op.execute(_CONTENT_CHECK_FUNCTION)
    op.execute(_CONTENT_CHECK_TRIGGER)
    op.drop_constraint(op.f("ck_report_contents_content_size"), "report_contents", type_="check")
    op.execute("DROP TRIGGER report_contents_immutable ON report_contents")
    op.execute(_CONTENTS_GUARD)
    op.execute(
        "CREATE TRIGGER report_contents_guard BEFORE UPDATE OR DELETE ON report_contents "
        "FOR EACH ROW EXECUTE FUNCTION report_contents_guard()"
    )


def _alter_excerpts() -> None:
    table = "finding_triage_excerpts"
    op.add_column(table, sa.Column("sealed_content", sa.LargeBinary()))
    op.add_column(table, sa.Column("expires_at", sa.DateTime(timezone=True)))
    op.add_column(table, sa.Column("purged_at", sa.DateTime(timezone=True)))
    op.drop_constraint(op.f("ck_finding_triage_excerpts_content_size"), table, type_="check")
    op.execute(f"DROP TRIGGER {table}_immutable ON {table}")
    op.execute(_EXCERPTS_GUARD)
    op.execute(
        f"CREATE TRIGGER {table}_guard BEFORE UPDATE OR DELETE ON {table} "
        f"FOR EACH ROW EXECUTE FUNCTION {table}_guard()"
    )


def _migrate_existing(connection: Connection) -> None:
    """既有的報告與摘錄：期限是升級時間加 30 天；明文核對之後加密。"""
    reports = connection.execute(sa.text("SELECT report_id FROM report_contents")).scalars().all()
    excerpts = connection.execute(
        sa.text("SELECT finding_id, sequence, kind FROM finding_triage_excerpts")
    ).all()
    connection.execute(sa.text("ALTER TABLE reports DISABLE TRIGGER reports_guard"))
    connection.execute(
        sa.text(
            "UPDATE reports SET expires_at = statement_timestamp() + interval '30 days' "
            "WHERE status = 'succeeded'"
        )
    )
    connection.execute(sa.text("ALTER TABLE reports ENABLE TRIGGER reports_guard"))
    if not reports and not excerpts:
        return
    cipher = _cipher()
    for report_id in reports:
        _seal_report(connection, cipher, report_id)
    guard = "finding_triage_excerpts_guard"
    connection.execute(sa.text(f"ALTER TABLE finding_triage_excerpts DISABLE TRIGGER {guard}"))
    for finding_id, sequence, kind in excerpts:
        _seal_excerpt(connection, cipher, finding_id, sequence, kind)
    connection.execute(sa.text(f"ALTER TABLE finding_triage_excerpts ENABLE TRIGGER {guard}"))


def _cipher() -> BlobCipher:
    keys = context.config.attributes.get(KEYS_ATTRIBUTE)
    value = keys.get_secret_value() if isinstance(keys, SecretStr) else keys
    if not isinstance(value, str):
        raise RuntimeError(
            f"已有報告或人工複測摘錄需要加密：請先執行 make env 產生 {CONTENT_SETTING}，"
            "再執行 make migrate（升級沒有進行）"
        )
    return content_cipher(value)


def _seal_report(connection: Connection, cipher: BlobCipher, report_id: object) -> None:
    row = connection.execute(
        sa.text(
            "SELECT stored.content, report.sha256, report.size_bytes "
            "FROM report_contents AS stored JOIN reports AS report ON report.id = stored.report_id "
            "WHERE stored.report_id = :id"
        ),
        {"id": report_id},
    ).one()
    content = bytes(row.content)
    if hashlib.sha256(content).hexdigest() != row.sha256 or len(content) != row.size_bytes:
        raise RuntimeError("既有的報告內容和它的 sha256 不符：升級沒有進行，請先檢查資料")
    token = cipher.seal(content, context=f"report:{report_id}", max_bytes=MAX_REPORT_BYTES)
    connection.execute(
        sa.text("UPDATE report_contents SET content = :token WHERE report_id = :id"),
        {"token": token, "id": report_id},
    )


def _seal_excerpt(
    connection: Connection, cipher: BlobCipher, finding_id: object, sequence: int, kind: str
) -> None:
    key = {"finding": finding_id, "sequence": sequence, "kind": kind}
    content = connection.execute(
        sa.text(
            "SELECT content FROM finding_triage_excerpts "
            "WHERE finding_id = :finding AND sequence = :sequence AND kind = :kind"
        ),
        key,
    ).scalar_one()
    limit = REQUEST_EXCERPT_MAX_BYTES if kind == "request" else RESPONSE_EXCERPT_MAX_BYTES
    token = cipher.seal(
        str(content).encode("utf-8"),
        context=f"excerpt:{finding_id}:{sequence}:{kind}",
        max_bytes=limit,
    )
    connection.execute(
        sa.text(
            "UPDATE finding_triage_excerpts SET sealed_content = :token, "
            "expires_at = statement_timestamp() + interval '30 days' "
            "WHERE finding_id = :finding AND sequence = :sequence AND kind = :kind"
        ),
        {**key, "token": token},
    )


def _finish() -> None:
    table = "finding_triage_excerpts"
    op.execute(_EXCERPT_INSERT)
    op.drop_column(table, "content")
    op.alter_column(table, "expires_at", nullable=False)
    for name, condition in _EXCERPT_CHECKS.items():
        op.create_check_constraint(op.f(f"ck_{table}_{name}"), table, condition)
    for name, condition in _REPORT_CHECKS.items():
        op.create_check_constraint(op.f(f"ck_reports_{name}"), "reports", condition)
    op.create_check_constraint(
        op.f("ck_report_contents_content_sealed"), "report_contents", _CONTENT_CHECK
    )


# --- downgrade：還原 0018、0017 的內容（migration 是當時的快照，不引用其他 migration）---------

_V18_REPORTS_GUARD = (
    """
CREATE OR REPLACE FUNCTION reports_guard() RETURNS trigger
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
    + _columns(_MUTABLE_V18)
    + """]) IS DISTINCT FROM (to_jsonb(OLD) - ARRAY["""
    + _columns(_MUTABLE_V18)
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
_V18_CONTENT_CHECK = """
CREATE OR REPLACE FUNCTION reports_content_check() RETURNS trigger
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
_V17_EXCERPT_INSERT = """
CREATE OR REPLACE FUNCTION finding_triage_excerpts_insert() RETURNS trigger
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


def downgrade() -> None:
    op.execute(_REFUSE_DOWNGRADE)
    table = "finding_triage_excerpts"
    for name in _EXCERPT_CHECKS:
        op.drop_constraint(op.f(f"ck_{table}_{name}"), table, type_="check")
    for name in _REPORT_CHECKS:
        op.drop_constraint(op.f(f"ck_reports_{name}"), "reports", type_="check")
    op.drop_constraint(op.f("ck_report_contents_content_sealed"), "report_contents", type_="check")
    op.execute(f"DROP TRIGGER {table}_guard ON {table}")
    op.execute(f"DROP FUNCTION {table}_guard()")
    op.add_column(table, sa.Column("content", sa.Text(), nullable=False))
    for column in ("purged_at", "expires_at", "sealed_content"):
        op.drop_column(table, column)
    op.create_check_constraint(
        op.f(f"ck_{table}_content_size"),
        table,
        f"octet_length(content) >= 1 AND octet_length(content) <= CASE kind "
        f"WHEN 'request' THEN {REQUEST_EXCERPT_MAX_BYTES} "
        f"ELSE {RESPONSE_EXCERPT_MAX_BYTES} END",
    )
    op.execute(_V17_EXCERPT_INSERT)
    op.execute(
        f"CREATE TRIGGER {table}_immutable BEFORE UPDATE OR DELETE ON {table} "
        "FOR EACH ROW EXECUTE FUNCTION scan_records_guard()"
    )
    op.execute("DROP TRIGGER report_contents_guard ON report_contents")
    op.execute("DROP FUNCTION report_contents_guard()")
    op.execute(
        "CREATE TRIGGER report_contents_immutable BEFORE UPDATE OR DELETE ON report_contents "
        "FOR EACH ROW EXECUTE FUNCTION scan_records_guard()"
    )
    op.create_check_constraint(
        op.f("ck_report_contents_content_size"),
        "report_contents",
        f"octet_length(content) >= 1 AND octet_length(content) <= {MAX_REPORT_BYTES}",
    )
    op.execute("DROP TRIGGER reports_content_check ON reports")
    op.execute(_V18_CONTENT_CHECK)
    op.execute(
        "CREATE CONSTRAINT TRIGGER reports_content_check AFTER UPDATE ON reports "
        "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.status = 'succeeded') "
        "EXECUTE FUNCTION reports_content_check()"
    )
    op.execute(_V18_REPORTS_GUARD)
    op.drop_column("reports", "content_purged_at")
    op.drop_column("reports", "expires_at")
