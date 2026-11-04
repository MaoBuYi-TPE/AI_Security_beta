"""findings 與 finding_observations 資料表（docs/DECISIONS.md §25.8）。

- findings：target 層級的議題，(target_id, fingerprint) 唯一。身分欄位與對應不可修改；只有最後看到
  的 run、最高等級、衝突與需要確認可以更新，而且只會往上（migration 的 trigger）。不能刪除。
  first／last seen 以複合 FK 引用 scanner_runs，不直接引用 scans：worker 持有 run 的鎖時檢查
  scans 的 FK（KEY SHARE）會和對帳的 scans FOR UPDATE → run 形成死鎖（同 observations）。
- finding_observations：觀察連結到哪個 finding（每個觀察最多一次），以及連結時的正規化值與 taxonomy
  的 sha256；append-only。觀察本身不修改（它有 append-only 的 trigger）。
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from secscan.auth_profiles.domain.model import ROLE_LABEL_MAX_LENGTH
from secscan.core.db import Base, CreatedAtMixin, UuidPrimaryKeyMixin
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


class FindingObservationModel(Base):
    """一個觀察連結到的 finding（每個觀察最多一次）；不可修改或刪除。"""

    __tablename__ = "finding_observations"
    __table_args__ = (
        Index("ix_finding_observations_finding_id", "finding_id"),
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
