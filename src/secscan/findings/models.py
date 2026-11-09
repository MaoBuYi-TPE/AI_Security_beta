"""findings 與 finding_observations 資料表（docs/DECISIONS.md §25.8）。

- findings：target 層級的議題，(target_id, fingerprint) 唯一。身分欄位與對應不可修改；只有最後看到
  的 run、最高等級、衝突與需要確認可以更新，而且只會往上（migration 的 trigger）。不能刪除。
  first／last seen 以複合 FK 引用 scanner_runs，不直接引用 scans：worker 持有 run 的鎖時檢查
  scans 的 FK（KEY SHARE）會和對帳的 scans FOR UPDATE → run 形成死鎖（同 observations）。
- finding_observations：觀察連結到哪個 finding（每個觀察最多一次），以及連結時的正規化值與 taxonomy
  的 sha256；append-only。觀察本身不修改（它有 append-only 的 trigger）。v0015：連結有序號（在
  finding 上保留、commit 時核對），觀察與 finding 必須屬於同一個 target（first／last seen 的 scan
  也是）。
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    LargeBinary,
    PrimaryKeyConstraint,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from secscan.audit.domain import REQUEST_ID_MAX_LENGTH
from secscan.auth_profiles.domain.model import ROLE_LABEL_MAX_LENGTH
from secscan.core.db import Base, CreatedAtMixin, UuidPrimaryKeyMixin
from secscan.core.json_types import JsonObject
from secscan.findings.domain.fingerprint import RouteSource
from secscan.findings.domain.model import LifecycleState, MappingSource, TriageState
from secscan.findings.domain.normalization import Confidence, Severity
from secscan.findings.domain.taxonomy import (
    KIND_CATEGORIES,
    RULE_GROUP_MAX_LENGTH,
    TITLE_MAX_LENGTH,
    CweSource,
    FindingCategory,
    FindingKind,
)
from secscan.findings.domain.triage import (
    EVIDENCE_MAX_BYTES,
    MAX_SEALED_EXCERPT_BYTES,
    REASON_MAX_LENGTH,
    ExcerptKind,
)
from secscan.scans.domain.observation import (
    OBSERVATION_METHODS,
    PARAMETER_MAX_LENGTH,
    POSITION_MAX_LENGTH,
    ParameterLocation,
)

LABEL_MAX_LENGTH = 32
METHOD_MAX_LENGTH = 7
SHA256_HEX_LENGTH = 64
MAPPING_VERSION_MAX_LENGTH = 64
OWASP_ID_MAX_LENGTH = 16
# fingerprint 與 sha256 都是小寫十六進位。
_SHA256_HEX = "^[0-9a-f]{64}$"
# CHECK 的文字經 SQLAlchemy 的 text()：`:2025` 會被當成 bind 參數（渲染成 NULL），冒號要跳脫。
TOP10_2025_PATTERN = r"^A(0[1-9]|10)\:2025$"
API_2023_PATTERN = r"^API([1-9]|10)\:2023$"


def _in_list(values: list[str]) -> str:
    return ", ".join(f"'{value}'" for value in values)


_KINDS = _in_list([kind.value for kind in FindingKind])
_CATEGORIES = _in_list([category.value for category in FindingCategory])
# kind 與 category 一致（unclassified 是 fallback，任何 kind 都可以；docs/DECISIONS.md §25.14）。
_KIND_CATEGORY = " OR ".join(
    [f"category = '{FindingCategory.UNCLASSIFIED.value}'"]
    + [
        f"(kind = '{kind.value}' AND category IN "
        f"({_in_list(sorted(category.value for category in categories))}))"
        for kind, categories in KIND_CATEGORIES.items()
    ]
)
_SEVERITIES = _in_list([severity.value for severity in Severity])
_CONFIDENCES = _in_list([confidence.value for confidence in Confidence])
_ROUTE_SOURCES = _in_list([source.value for source in RouteSource])
_LOCATIONS = _in_list([location.value for location in ParameterLocation])
_METHODS = _in_list(sorted(OBSERVATION_METHODS))
_CWE_SOURCES = _in_list([source.value for source in CweSource])
_TRIAGE = _in_list([state.value for state in TriageState])
_LIFECYCLE = _in_list([state.value for state in LifecycleState])
_ROLE_PATTERN = rf"^[a-z][a-z0-9_]{{0,{ROLE_LABEL_MAX_LENGTH - 1}}}$"
_OFFICIAL, _CURATED, _NONE = (
    MappingSource.OFFICIAL.value,
    MappingSource.CURATED.value,
    MappingSource.NONE.value,
)


class FindingModel(UuidPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("target_id", "fingerprint"),
        UniqueConstraint("id", "target_id"),
        ForeignKeyConstraint(
            ["first_seen_run_id", "first_seen_scan_id"],
            ["scanner_runs.id", "scanner_runs.scan_id"],
            name="fk_findings_first_seen_run",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["last_seen_run_id", "last_seen_scan_id"],
            ["scanner_runs.id", "scanner_runs.scan_id"],
            name="fk_findings_last_seen_run",
            ondelete="RESTRICT",
        ),
        CheckConstraint(f"fingerprint ~ '{_SHA256_HEX}'", name="fingerprint_valid"),
        CheckConstraint(f"kind IN ({_KINDS})", name="kind_valid"),
        CheckConstraint(
            f"category IN ({_CATEGORIES}) AND ({_KIND_CATEGORY})", name="category_valid"
        ),
        CheckConstraint("char_length(btrim(rule_group)) > 0", name="rule_group_not_blank"),
        CheckConstraint("char_length(btrim(title)) > 0", name="title_not_blank"),
        CheckConstraint(f"method IN ({_METHODS})", name="method_valid"),
        CheckConstraint(
            f"left(route, 1) = '/' AND route_source IN ({_ROUTE_SOURCES})", name="route_valid"
        ),
        CheckConstraint(
            "(parameter_location IS NULL) = (parameter_name IS NULL) "
            f"AND (parameter_location IS NULL OR parameter_location IN ({_LOCATIONS}))",
            name="parameter_valid",
        ),
        CheckConstraint("resource IS NULL OR left(resource, 1) = '/'", name="resource_valid"),
        CheckConstraint(f"auth_role ~ '{_ROLE_PATTERN}'", name="auth_role_valid"),
        CheckConstraint(f"normalized_severity IN ({_SEVERITIES})", name="severity_valid"),
        CheckConstraint(
            "(cwe_id IS NULL) = (cwe_source IS NULL) AND (cwe_id IS NULL OR cwe_id > 0) "
            f"AND (cwe_source IS NULL OR cwe_source IN ({_CWE_SOURCES}))",
            name="cwe_valid",
        ),
        CheckConstraint(
            f"CASE WHEN owasp_top10_2025 IS NULL THEN owasp_top10_2025_source = '{_NONE}' "
            f"ELSE owasp_top10_2025 ~ '{TOP10_2025_PATTERN}' "
            f"AND owasp_top10_2025_source = '{_OFFICIAL}' END",
            name="owasp_top10_2025_valid",
        ),
        CheckConstraint(
            f"CASE WHEN owasp_api_2023 IS NULL THEN owasp_api_2023_source = '{_NONE}' "
            f"ELSE owasp_api_2023 ~ '{API_2023_PATTERN}' "
            f"AND owasp_api_2023_source = '{_CURATED}' END",
            name="owasp_api_2023_valid",
        ),
        CheckConstraint(
            "char_length(btrim(mapping_version)) > 0", name="mapping_version_not_blank"
        ),
        CheckConstraint(f"taxonomy_sha256 ~ '{_SHA256_HEX}'", name="taxonomy_sha256_valid"),
        CheckConstraint(f"triage_state IN ({_TRIAGE})", name="triage_state_valid"),
        CheckConstraint(f"lifecycle_state IN ({_LIFECYCLE})", name="lifecycle_state_valid"),
        CheckConstraint("last_seen_at >= created_at", name="times"),
        CheckConstraint("observations_linked >= 0", name="observations_linked_valid"),
        # T21（v0017）：resolved ⇒ confirmed；resolved ⇔ watermark 與連結數都有值（trigger 寫入）。
        CheckConstraint("triage_version >= 0", name="triage_version_valid"),
        CheckConstraint(
            "lifecycle_state <> 'resolved' OR triage_state = 'confirmed'",
            name="resolution_confirmed",
        ),
        CheckConstraint(
            "(lifecycle_state = 'resolved') = (resolved_scan_position IS NOT NULL) "
            "AND (resolved_scan_position IS NULL) = (resolved_link_count IS NULL) "
            "AND (resolved_link_count IS NULL OR resolved_link_count <= observations_linked)",
            name="resolution_watermark",
        ),
    )

    target_id: Mapped[UUID] = mapped_column(ForeignKey("targets.id", ondelete="RESTRICT"))
    # 由下面的身分欄位算出（FingerprintInputs）；欄位都在表中，可以重算，不另存一份 JSON。
    fingerprint: Mapped[str] = mapped_column(String(SHA256_HEX_LENGTH))
    kind: Mapped[str] = mapped_column(String(LABEL_MAX_LENGTH))
    # kind 之下的分類（v0014）；和身分一樣不可修改。
    category: Mapped[str] = mapped_column(String(LABEL_MAX_LENGTH))
    rule_group: Mapped[str] = mapped_column(String(RULE_GROUP_MAX_LENGTH))
    title: Mapped[str] = mapped_column(String(TITLE_MAX_LENGTH))
    method: Mapped[str] = mapped_column(String(METHOD_MAX_LENGTH))
    route: Mapped[str] = mapped_column(String(POSITION_MAX_LENGTH))
    route_source: Mapped[str] = mapped_column(String(LABEL_MAX_LENGTH))
    parameter_location: Mapped[str | None] = mapped_column(String(LABEL_MAX_LENGTH))
    parameter_name: Mapped[str | None] = mapped_column(String(PARAMETER_MAX_LENGTH))
    resource: Mapped[str | None] = mapped_column(String(POSITION_MAX_LENGTH))
    auth_role: Mapped[str] = mapped_column(String(ROLE_LABEL_MAX_LENGTH))
    auth_verified: Mapped[bool]
    normalized_severity: Mapped[str] = mapped_column(String(LABEL_MAX_LENGTH))
    severity_conflict: Mapped[bool]
    needs_review: Mapped[bool]
    cwe_id: Mapped[int | None]
    cwe_source: Mapped[str | None] = mapped_column(String(LABEL_MAX_LENGTH))
    owasp_top10_2025: Mapped[str | None] = mapped_column(String(OWASP_ID_MAX_LENGTH))
    owasp_top10_2025_source: Mapped[str] = mapped_column(String(LABEL_MAX_LENGTH))
    owasp_api_2023: Mapped[str | None] = mapped_column(String(OWASP_ID_MAX_LENGTH))
    owasp_api_2023_source: Mapped[str] = mapped_column(String(LABEL_MAX_LENGTH))
    mapping_version: Mapped[str] = mapped_column(String(MAPPING_VERSION_MAX_LENGTH))
    taxonomy_sha256: Mapped[str] = mapped_column(String(SHA256_HEX_LENGTH))
    triage_state: Mapped[str] = mapped_column(
        String(LABEL_MAX_LENGTH), server_default=text(f"'{TriageState.UNREVIEWED.value}'")
    )
    lifecycle_state: Mapped[str] = mapped_column(
        String(LABEL_MAX_LENGTH), server_default=text(f"'{LifecycleState.OPEN.value}'")
    )
    first_seen_run_id: Mapped[UUID]
    first_seen_scan_id: Mapped[UUID]
    last_seen_run_id: Mapped[UUID]
    last_seen_scan_id: Mapped[UUID]
    last_seen_at: Mapped[datetime] = mapped_column(server_default=func.now())
    # 已連結的觀察數（v0015）：linker 持有列鎖時一次保留一批序號，commit 時 DB 核對它等於連結的
    # 筆數。讀取時以 link_sequence <= observations_linked 取得一致的快照（追溯 API 的分頁）。
    observations_linked: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    # T21（v0017）：每次 triage 或 lifecycle 變更恰好 +1，並有恰好一筆事件。
    triage_version: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    # resolve 時由 trigger 寫入：target 所有 scan 的最大 queue_position（R3）與當時的連結數。
    resolved_scan_position: Mapped[int | None] = mapped_column(BigInteger)
    resolved_link_count: Mapped[int | None] = mapped_column(BigInteger)


class FindingObservationModel(Base):
    """一個觀察連結到的 finding（每個觀察最多一次）；不可修改或刪除。"""

    __tablename__ = "finding_observations"
    __table_args__ = (
        UniqueConstraint("finding_id", "link_sequence"),
        CheckConstraint("link_sequence > 0", name="link_sequence_valid"),
        CheckConstraint(f"normalized_severity IN ({_SEVERITIES})", name="severity_valid"),
        CheckConstraint(f"normalized_confidence IN ({_CONFIDENCES})", name="confidence_valid"),
        CheckConstraint(f"taxonomy_sha256 ~ '{_SHA256_HEX}'", name="taxonomy_sha256_valid"),
    )

    observation_id: Mapped[UUID] = mapped_column(
        ForeignKey("observations.id", ondelete="RESTRICT"), primary_key=True
    )
    finding_id: Mapped[UUID] = mapped_column(ForeignKey("findings.id", ondelete="RESTRICT"))
    normalized_severity: Mapped[str] = mapped_column(String(LABEL_MAX_LENGTH))
    normalized_confidence: Mapped[str] = mapped_column(String(LABEL_MAX_LENGTH))
    needs_review: Mapped[bool]
    taxonomy_sha256: Mapped[str] = mapped_column(String(SHA256_HEX_LENGTH))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    # 這個 finding 的第幾個連結（v0015）：必須是這個 transaction 在 finding 上保留的序號。
    link_sequence: Mapped[int] = mapped_column(BigInteger)


_EVENT_KEYS = "ARRAY['classification', 'reasons', 'attestation', 'observation_ids', 'links']"


class FindingTriageEventModel(Base):
    """triage 或 lifecycle 的一次變更（append-only，v0017）；先 UPDATE finding、再 INSERT 事件。

    系統事件只有自動重開（resolved → reopened），以複合 FK 引用 scanner_runs，不直接引用 scans。
    """

    __tablename__ = "finding_triage_events"
    __table_args__ = (
        PrimaryKeyConstraint("finding_id", "sequence"),
        ForeignKeyConstraint(
            ["finding_id", "target_id"], ["findings.id", "findings.target_id"], ondelete="RESTRICT"
        ),
        ForeignKeyConstraint(
            ["comparison_id", "target_id"],
            ["scan_comparisons.id", "scan_comparisons.target_id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["run_id", "scan_id"], ["scanner_runs.id", "scanner_runs.scan_id"], ondelete="RESTRICT"
        ),
        ForeignKeyConstraint(
            ["comparison_id", "finding_id"],
            ["scan_comparison_findings.comparison_id", "scan_comparison_findings.finding_id"],
            ondelete="RESTRICT",
        ),
        Index(None, "actor_key_id"),
        Index(None, "comparison_id", "target_id"),
        Index(None, "run_id", "scan_id"),
        CheckConstraint("sequence >= 1", name="sequence_positive"),
        CheckConstraint("actor_kind IN ('key', 'system')", name="actor_kind_valid"),
        CheckConstraint(
            f"previous_triage_state IN ({_TRIAGE}) AND triage_state IN ({_TRIAGE}) "
            f"AND previous_lifecycle_state IN ({_LIFECYCLE}) AND lifecycle_state IN ({_LIFECYCLE})",
            name="states_valid",
        ),
        CheckConstraint(
            "(previous_triage_state = triage_state) "
            "<> (previous_lifecycle_state = lifecycle_state)",
            name="one_change",
        ),
        CheckConstraint(
            "reason_code IN ('manual', 'auto_reopen_new_observation')", name="reason_code_valid"
        ),
        CheckConstraint(
            f"char_length(btrim(reason)) > 0 AND char_length(reason) <= {REASON_MAX_LENGTH}",
            name="reason_valid",
        ),
        CheckConstraint(
            "resolution_basis IS NULL OR resolution_basis IN "
            "('rescan_not_observed', 'manual_retest')",
            name="basis_valid",
        ),
        CheckConstraint(
            f"jsonb_typeof(evidence) = 'object' AND octet_length(evidence::text) <= "
            f"{EVIDENCE_MAX_BYTES} AND (evidence - {_EVENT_KEYS}) = jsonb_build_object()",
            name="evidence_valid",
        ),
        CheckConstraint("(actor_kind = 'key') = (actor_key_id IS NOT NULL)", name="actor_valid"),
        CheckConstraint(
            "(actor_kind = 'system') = (run_id IS NOT NULL) "
            "AND (run_id IS NULL) = (scan_id IS NULL) "
            "AND (actor_kind = 'system') = (reason_code = 'auto_reopen_new_observation') "
            "AND (actor_kind <> 'system' OR (previous_lifecycle_state = 'resolved' "
            "AND lifecycle_state = 'reopened'))",
            name="system_valid",
        ),
        CheckConstraint(
            "(lifecycle_state = 'resolved' AND previous_lifecycle_state <> 'resolved') "
            "= (comparison_id IS NOT NULL) "
            "AND (comparison_id IS NULL) = (resolution_basis IS NULL)",
            name="resolution_valid",
        ),
        CheckConstraint(
            "(resolution_basis IS NOT DISTINCT FROM 'manual_retest') = (evidence ? 'attestation') "
            "AND (resolution_basis IS DISTINCT FROM 'manual_retest' "
            "OR COALESCE(jsonb_typeof(evidence -> 'attestation') = 'object' "
            "AND evidence -> 'attestation' ->> 'provenance' = 'operator_supplied', false))",
            name="attestation_valid",
        ),
    )

    finding_id: Mapped[UUID]
    target_id: Mapped[UUID]
    sequence: Mapped[int] = mapped_column(BigInteger)
    actor_kind: Mapped[str] = mapped_column(String(16))
    actor_key_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("api_keys.id", ondelete="RESTRICT")
    )
    request_id: Mapped[str | None] = mapped_column(String(REQUEST_ID_MAX_LENGTH))
    previous_triage_state: Mapped[str] = mapped_column(String(LABEL_MAX_LENGTH))
    triage_state: Mapped[str] = mapped_column(String(LABEL_MAX_LENGTH))
    previous_lifecycle_state: Mapped[str] = mapped_column(String(LABEL_MAX_LENGTH))
    lifecycle_state: Mapped[str] = mapped_column(String(LABEL_MAX_LENGTH))
    reason_code: Mapped[str] = mapped_column(String(LABEL_MAX_LENGTH))
    reason: Mapped[str] = mapped_column(Text)
    comparison_id: Mapped[UUID | None]
    resolution_basis: Mapped[str | None] = mapped_column(String(LABEL_MAX_LENGTH))
    run_id: Mapped[UUID | None]
    scan_id: Mapped[UUID | None]
    evidence: Mapped[JsonObject] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.clock_timestamp())


class FindingTriageExcerptModel(Base):
    """人工複測的遮罩摘錄（v0017）：和事件分開存放，加密與清除時不必修改事件（v0022）。

    sealed_content 是 CONTENT_ENCRYPTION_KEYS 加密的 Fernet token；到期清除時改成 NULL、寫入
    purged_at（tombstone，「每個人工複測事件恰好兩筆」不變）。明文的雜湊與長度在事件的 evidence。
    """

    __tablename__ = "finding_triage_excerpts"
    __table_args__ = (
        PrimaryKeyConstraint("finding_id", "sequence", "kind"),
        ForeignKeyConstraint(
            ["finding_id", "sequence"],
            ["finding_triage_events.finding_id", "finding_triage_events.sequence"],
            ondelete="RESTRICT",
        ),
        CheckConstraint("kind IN ('request', 'response')", name="kind_valid"),
        CheckConstraint(
            "(sealed_content IS NULL) = (purged_at IS NOT NULL)", name="purged_matches_content"
        ),
        CheckConstraint(
            "sealed_content IS NULL OR (substring(sealed_content FROM 1 FOR 6) = 'gAAAAA'::bytea "
            "AND octet_length(sealed_content) <= CASE kind "
            f"WHEN 'request' THEN {MAX_SEALED_EXCERPT_BYTES[ExcerptKind.REQUEST]} "
            f"ELSE {MAX_SEALED_EXCERPT_BYTES[ExcerptKind.RESPONSE]} END)",
            name="sealed_content_valid",
        ),
        CheckConstraint("purged_at IS NULL OR purged_at >= expires_at", name="purged_after_expiry"),
        # 到期清除（T23a，v0022）：還沒清除的摘錄依期限排序。
        Index(
            "ix_finding_triage_excerpts_expiry",
            "expires_at",
            postgresql_where=text("purged_at IS NULL"),
        ),
    )

    finding_id: Mapped[UUID]
    sequence: Mapped[int] = mapped_column(BigInteger)
    kind: Mapped[str] = mapped_column(String(16))
    sealed_content: Mapped[bytes | None] = mapped_column(LargeBinary)
    expires_at: Mapped[datetime]
    purged_at: Mapped[datetime | None]
