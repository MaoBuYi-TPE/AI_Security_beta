"""scans、scanner_runs、scan_events、scan_operations 資料表（docs/DECISIONS.md §13）。

- scans：快照以複合 FK 引用 target（含 project）、grant、規格與 auth profile 的版本，DB 保證它們
  屬於同一個 target；建立後只有狀態、取消與結束的時間可以改，終止之後完全不可變
  （migration 的 trigger）。
- scanner_runs：佇列的單位；lease 的欄位只在持有 lease 的狀態有值。
- scan_events、scan_operations：append-only。
- artifacts、observations（docs/DECISIONS.md §19.6）：append-only；只以複合 FK 引用 scanner_runs，
  不直接引用 scans（對帳先鎖 scans 再鎖 run，worker 持有 run 的鎖時檢查 scans 的 FK 可能死鎖）。
"""

from collections.abc import Iterable
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Identity,
    Index,
    LargeBinary,
    PrimaryKeyConstraint,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from secscan.auth_profiles.domain.model import ROLE_LABEL_MAX_LENGTH
from secscan.core.db import Base, CreatedAtMixin, UuidPrimaryKeyMixin
from secscan.core.json_types import JsonObject
from secscan.grants.domain.matching import IneligibleReason
from secscan.grants.domain.scope import PATH_MAX_LENGTH
from secscan.scans.domain.catalog import Engine, ScanProfile
from secscan.scans.domain.lifecycle import (
    ACTIVE_SCAN_STATUSES,
    ERROR_REQUIRED_RUN_STATUSES,
    LEASED_RUN_STATUSES,
    TERMINAL_RUN_STATUSES,
    TERMINAL_SCAN_STATUSES,
    RunStatus,
    ScanStatus,
)
from secscan.scans.domain.model import (
    ANONYMOUS_ROLE,
    CONTAINER_NAME_PREFIX,
    MAX_EVENT_PAYLOAD_BYTES,
    EventType,
)
from secscan.scans.domain.observation import (
    ARTIFACT_PATH_MAX_LENGTH,
    MAX_DETAILS_BYTES,
    OBSERVATION_METHODS,
    PARAMETER_MAX_LENGTH,
    POSITION_MAX_LENGTH,
    RAW_LEVEL_MAX_LENGTH,
    RULE_MAX_LENGTH,
    TEXT_MAX_LENGTH,
    TITLE_MAX_LENGTH,
    VERSION_MAX_LENGTH,
    ArtifactClassification,
    ArtifactKind,
    ParameterLocation,
)
from secscan.scans.domain.preflight import PreflightResult
from secscan.scans.domain.request import IDEMPOTENCY_KEY_MAX_LENGTH, IDEMPOTENCY_KEY_MIN_LENGTH
from secscan.specs.domain.openapi import MAX_OPERATIONS, OPERATION_ID_MAX_LENGTH, OPERATION_METHODS
from secscan.targets.domain import ORIGIN_MAX_LENGTH
from secscan.targets.models import CANONICAL_ORIGIN_PATTERN

LABEL_MAX_LENGTH = 32
ENGINE_MAX_LENGTH = 16
METHOD_MAX_LENGTH = 7
LEASE_OWNER_MAX_LENGTH = 128
ERROR_CODE_MAX_LENGTH = 64
EVENT_TYPE_MAX_LENGTH = 64
SHA256_BYTES = 32
CONTAINER_NAME_MAX_LENGTH = 64
IMAGE_REF_MAX_LENGTH = 255
PREFLIGHT_RESULT_MAX_LENGTH = 32
ARTIFACT_STORAGE_KEY_MAX_LENGTH = 2500
# repo:tag@sha256:<64 hex>（完整的文法在 scanners.domain.plan；DB 是最後一道防線）。
IMAGE_REF_PATTERN = (
    "^[a-z0-9][a-z0-9._/:-]{0,180}:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}@sha256:[0-9a-f]{64}$"
)


def _in_list(members: Iterable[str]) -> str:
    """SQL 的 IN 清單。enum 依宣告的順序，集合先排序：migration 中的清單是同樣的順序。"""
    return ", ".join(f"'{member}'" for member in members)


def _sorted(statuses: Iterable[StrEnum]) -> list[str]:
    return sorted(status.value for status in statuses)


_SCAN_STATUSES = _in_list(status.value for status in ScanStatus)
_TERMINAL_SCANS = _in_list(_sorted(TERMINAL_SCAN_STATUSES))
_ACTIVE_SCANS = _in_list(_sorted(ACTIVE_SCAN_STATUSES))
_RUN_STATUSES = _in_list(status.value for status in RunStatus)
_TERMINAL_RUNS = _in_list(_sorted(TERMINAL_RUN_STATUSES))
_LEASED_RUNS = _in_list(_sorted(LEASED_RUN_STATUSES))
_ERROR_RUNS = _in_list(_sorted(ERROR_REQUIRED_RUN_STATUSES))
_ENGINES = _in_list(engine.value for engine in Engine)
_PROFILES = _in_list(profile.value for profile in ScanProfile)
_EVENT_TYPES = _in_list(event.value for event in EventType)
_REASONS = _in_list(reason.value for reason in IneligibleReason)
_PREFLIGHT_RESULTS = _in_list(result.value for result in PreflightResult)
_METHODS = _in_list(method.upper() for method in OPERATION_METHODS)
_OBSERVATION_METHODS = _in_list(sorted(OBSERVATION_METHODS))
_PARAMETER_LOCATIONS = _in_list(location.value for location in ParameterLocation)
_SHA256_HEX = "^[0-9a-f]{64}$"


class ScanModel(UuidPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "scans"
    __table_args__ = (
        # 快照：引用的資料都屬於同一個 target（與 project）。可為 NULL 的欄位是 NULL 時不檢查
        # （MATCH SIMPLE，[S82]）。
        ForeignKeyConstraint(
            ["target_id", "project_id"],
            ["targets.id", "targets.project_id"],
            name="fk_scans_target_project",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["scope_grant_id", "target_id"],
            ["scope_grants.id", "scope_grants.target_id"],
            name="fk_scans_grant_target",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["api_spec_id", "target_id"],
            ["api_specs.id", "api_specs.target_id"],
            name="fk_scans_spec_target",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["auth_profile_id", "target_id", "auth_role"],
            ["auth_profiles.id", "auth_profiles.target_id", "auth_profiles.role_label"],
            name="fk_scans_profile_target_role",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["auth_profile_id", "auth_profile_version"],
            ["auth_profile_versions.profile_id", "auth_profile_versions.version"],
            name="fk_scans_profile_version",
            ondelete="RESTRICT",
        ),
        # Idempotency-Key 的範圍是 project（docs/DECISIONS.md §13.2）。
        UniqueConstraint("project_id", "idempotency_key"),
        # 一個 target 同時只有一個進行中的 scan（ARCHITECTURE.md §6.1）。
        Index(
            "uq_scans_active_target",
            "target_id",
            unique=True,
            postgresql_where=text(f"status IN ({_ACTIVE_SCANS})"),
        ),
        Index("ix_scans_target_id_created_at", "target_id", "created_at"),
        Index("ix_scans_project_id_created_at", "project_id", "created_at"),
        CheckConstraint(f"status IN ({_SCAN_STATUSES})", name="status_valid"),
        CheckConstraint(f"scan_profile IN ({_PROFILES})", name="scan_profile_valid"),
        CheckConstraint(
            "requests_per_second > 0 AND max_requests > 0 AND max_duration_seconds > 0",
            name="budget_positive",
        ),
        CheckConstraint(
            "idempotency_key ~ "
            f"'^[A-Za-z0-9_-]{{{IDEMPOTENCY_KEY_MIN_LENGTH},{IDEMPOTENCY_KEY_MAX_LENGTH}}}$'",
            name="idempotency_key_valid",
        ),
        CheckConstraint(
            f"octet_length(request_sha256) = {SHA256_BYTES}", name="request_sha256_length"
        ),
        # 有 profile 就有版本；只有沒有 profile 時是 anonymous（contract §7）。
        CheckConstraint(
            "(auth_profile_id IS NULL) = (auth_profile_version IS NULL) "
            f"AND (auth_profile_id IS NULL) = (auth_role = '{ANONYMOUS_ROLE}')",
            name="auth_consistent",
        ),
        CheckConstraint(
            rf"auth_role ~ '^[a-z][a-z0-9_]{{0,{ROLE_LABEL_MAX_LENGTH - 1}}}$'",
            name="auth_role_valid",
        ),
        CheckConstraint(
            f"CASE scan_profile WHEN '{ScanProfile.API_ACTIVE_LAB.value}' "
            "THEN api_spec_id IS NOT NULL ELSE api_spec_id IS NULL END",
            name="spec_matches_profile",
        ),
        CheckConstraint(f"target_origin ~ '{CANONICAL_ORIGIN_PATTERN}'", name="origin_canonical"),
        CheckConstraint(
            f"(status IN ({_TERMINAL_SCANS})) = (finished_at IS NOT NULL)",
            name="finished_matches_status",
        ),
        CheckConstraint(
            f"status NOT IN ('{ScanStatus.CANCELLING.value}', '{ScanStatus.CANCELLED.value}') "
            "OR cancel_requested_at IS NOT NULL",
            name="cancel_matches_status",
        ),
        CheckConstraint(
            "(cancel_requested_at IS NULL OR cancel_requested_at >= created_at) "
            "AND (finished_at IS NULL OR finished_at >= created_at)",
            name="times",
        ),
    )

    # 佇列的先後（commit 的順序無關；created_at 是 transaction 開始的時間，不能代表先後）。
    queue_position: Mapped[int] = mapped_column(
        BigInteger, Identity(always=True), unique=True, sort_order=-1
    )
    project_id: Mapped[UUID]
    target_id: Mapped[UUID]
    # 凍結的 origin：targets 沒有 trigger，建立 scan 之後 origin 不可能隨之改變。
    target_origin: Mapped[str] = mapped_column(String(ORIGIN_MAX_LENGTH))
    scope_grant_id: Mapped[UUID]
    api_spec_id: Mapped[UUID | None]
    auth_profile_id: Mapped[UUID | None]
    auth_profile_version: Mapped[int | None]
    auth_role: Mapped[str] = mapped_column(String(ROLE_LABEL_MAX_LENGTH))
    scan_profile: Mapped[str] = mapped_column(String(LABEL_MAX_LENGTH))
    requests_per_second: Mapped[int]
    max_requests: Mapped[int]
    max_duration_seconds: Mapped[int]
    status: Mapped[str] = mapped_column(String(LABEL_MAX_LENGTH))
    idempotency_key: Mapped[str] = mapped_column(String(IDEMPOTENCY_KEY_MAX_LENGTH))
    request_sha256: Mapped[bytes] = mapped_column(LargeBinary)
    cancel_requested_at: Mapped[datetime | None]
    created_by_key_id: Mapped[UUID] = mapped_column(ForeignKey("api_keys.id", ondelete="RESTRICT"))
    finished_at: Mapped[datetime | None]


class ScannerRunModel(UuidPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "scanner_runs"
    __table_args__ = (
        UniqueConstraint("scan_id", "sequence"),
        UniqueConstraint("scan_id", "engine"),
        # 事件以 (scanner_run_id, scan_id) 引用 run：事件的 run 一定屬於同一個 scan。
        UniqueConstraint("id", "scan_id"),
        # 認領：只掃描等待中的 run。
        Index(
            "ix_scanner_runs_claimable",
            "status",
            "engine",
            postgresql_where=text(
                f"status IN ('{RunStatus.QUEUED.value}', '{RunStatus.COLLECTED.value}')"
            ),
        ),
        # 對帳：找 lease 過期的 run。
        Index(
            "ix_scanner_runs_lease_expires_at",
            "lease_expires_at",
            postgresql_where=text("lease_owner IS NOT NULL"),
        ),
        # 容器的對帳（docs/DECISIONS.md §17.2）：找還沒確認刪除的容器。
        Index(
            "ix_scanner_runs_pending_containers",
            "created_at",
            postgresql_where=text("container_name IS NOT NULL AND container_removed_at IS NULL"),
        ),
        CheckConstraint(f"engine IN ({_ENGINES})", name="engine_valid"),
        CheckConstraint(f"status IN ({_RUN_STATUSES})", name="status_valid"),
        CheckConstraint(f"sequence BETWEEN 1 AND {len(Engine)}", name="sequence_valid"),
        # lease 的三個欄位同時有值，而且只在持有 lease 的狀態有值。
        CheckConstraint(
            "(lease_owner IS NULL) = (lease_expires_at IS NULL) "
            "AND (lease_owner IS NULL) = (heartbeat_at IS NULL) "
            f"AND (lease_owner IS NOT NULL) = (status IN ({_LEASED_RUNS}))",
            name="lease_matches_status",
        ),
        CheckConstraint(
            "lease_owner IS NULL OR char_length(btrim(lease_owner)) > 0",
            name="lease_owner_not_blank",
        ),
        CheckConstraint(
            f"(status IN ({_TERMINAL_RUNS})) = (finished_at IS NOT NULL)",
            name="finished_matches_status",
        ),
        # 錯誤碼的清單在 domain（M2 新增時不必改 migration）；DB 只檢查格式。
        CheckConstraint(
            f"(status IN ({_ERROR_RUNS})) = (error_code IS NOT NULL)",
            name="error_code_matches_status",
        ),
        CheckConstraint(
            "error_code IS NULL OR "
            f"error_code ~ '^[A-Z][A-Z0-9_]{{0,{ERROR_CODE_MAX_LENGTH - 1}}}$'",
            name="error_code_valid",
        ),
        # 排隊中沒有開始的時間；從排隊中直接取消的 run 也沒有；其他狀態都已經開始過。
        CheckConstraint(
            f"CASE status WHEN '{RunStatus.QUEUED.value}' THEN started_at IS NULL "
            f"WHEN '{RunStatus.CANCELLED.value}' THEN true ELSE started_at IS NOT NULL END",
            name="started_matches_status",
        ),
        CheckConstraint(
            "(started_at IS NULL OR started_at >= created_at) "
            "AND (finished_at IS NULL OR finished_at >= coalesce(started_at, created_at)) "
            "AND (heartbeat_at IS NULL OR heartbeat_at >= started_at)",
            name="times",
        ),
        # 容器版的 runner 在 run 開始時記下容器與映像（docs/DECISIONS.md §14.6）；in-process 的
        # fake runner 沒有容器。只能在 preparing → running 的那一次寫入（migration 的 trigger）。
        CheckConstraint(
            f"container_name IS NULL OR container_name = '{CONTAINER_NAME_PREFIX}' || id::text",
            name="container_matches_run",
        ),
        CheckConstraint(
            f"image_ref IS NULL OR image_ref ~ '{IMAGE_REF_PATTERN}'", name="image_ref_valid"
        ),
        CheckConstraint(
            "(container_name IS NULL) = (image_ref IS NULL)", name="container_with_image"
        ),
        CheckConstraint(
            "container_name IS NULL OR status NOT IN "
            f"('{RunStatus.QUEUED.value}', '{RunStatus.PREPARING.value}')",
            name="container_after_start",
        ),
        # 容器確認不存在的時間（docs/DECISIONS.md §17.3）：只能寫入一次（migration 的 trigger）。
        CheckConstraint(
            "container_removed_at IS NULL "
            "OR (container_name IS NOT NULL AND container_removed_at >= started_at)",
            name="container_removed_after_start",
        ),
        # 共享預算（docs/DECISIONS.md §16.4）：分到的請求數與 guard 記下的用量。
        CheckConstraint(
            "(requests_allotted IS NULL OR requests_allotted >= 0) "
            "AND (requests_sent IS NULL OR requests_sent >= 0) "
            "AND (requests_denied IS NULL OR requests_denied >= 0) "
            "AND (traffic_seconds IS NULL OR traffic_seconds >= 0)",
            name="usage_not_negative",
        ),
        CheckConstraint(
            "requests_sent IS NULL OR (requests_allotted IS NOT NULL "
            "AND requests_sent <= requests_allotted)",
            name="sent_within_allotment",
        ),
        # preflight 的結果（docs/DECISIONS.md §16.5）：只有 preflight 的 run 有值。
        CheckConstraint(
            f"preflight_result IS NULL OR (engine = '{Engine.PREFLIGHT.value}' "
            f"AND preflight_result IN ({_PREFLIGHT_RESULTS}))",
            name="preflight_result_valid",
        ),
        # 解析的結果（docs/DECISIONS.md §19.6）：寫入時一起有值；版本與退出碼可能是未知的。
        CheckConstraint(
            "results_recorded = (parser_version IS NOT NULL) "
            "AND results_recorded = (observation_count IS NOT NULL) "
            "AND results_recorded = (result_details IS NOT NULL) "
            "AND (results_recorded OR (engine_version IS NULL AND exit_code IS NULL))",
            name="results_consistent",
        ),
        CheckConstraint(
            "(observation_count IS NULL OR observation_count >= 0) "
            "AND (exit_code IS NULL OR exit_code BETWEEN 0 AND 255)",
            name="result_counts_valid",
        ),
        CheckConstraint(
            "result_details IS NULL OR (jsonb_typeof(result_details) = 'object' "
            f"AND octet_length(result_details::text) <= {MAX_DETAILS_BYTES})",
            name="result_details_valid",
        ),
        # 實際執行的內容（docs/DECISIONS.md §20.2）：runner 在建立容器之前寫入一次。
        CheckConstraint(
            f"plan_hash IS NULL OR (plan_hash ~ '{_SHA256_HEX}' AND container_name IS NOT NULL)",
            name="plan_hash_valid",
        ),
        CheckConstraint(
            "profile_definition_sha256 IS NULL "
            f"OR (profile_definition_sha256 ~ '{_SHA256_HEX}' AND engine = '{Engine.ZAP.value}' "
            "AND plan_hash IS NOT NULL)",
            name="profile_definition_valid",
        ),
        CheckConstraint(
            "guard_policy_version IS NULL OR (guard_policy_version IN "
            "('strict-1', 'encoded-params-1') AND plan_hash IS NOT NULL)",
            name="guard_policy_version_valid",
        ),
    )

    scan_id: Mapped[UUID] = mapped_column(ForeignKey("scans.id", ondelete="RESTRICT"))
    engine: Mapped[str] = mapped_column(String(ENGINE_MAX_LENGTH))
    sequence: Mapped[int]
    status: Mapped[str] = mapped_column(String(LABEL_MAX_LENGTH))
    lease_owner: Mapped[str | None] = mapped_column(String(LEASE_OWNER_MAX_LENGTH))
    lease_expires_at: Mapped[datetime | None]
    heartbeat_at: Mapped[datetime | None]
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    error_code: Mapped[str | None] = mapped_column(String(ERROR_CODE_MAX_LENGTH))
    container_name: Mapped[str | None] = mapped_column(String(CONTAINER_NAME_MAX_LENGTH))
    image_ref: Mapped[str | None] = mapped_column(String(IMAGE_REF_MAX_LENGTH))
    container_removed_at: Mapped[datetime | None]
    requests_allotted: Mapped[int | None]
    requests_sent: Mapped[int | None]
    requests_denied: Mapped[int | None]
    traffic_seconds: Mapped[int | None]
    preflight_result: Mapped[str | None] = mapped_column(String(PREFLIGHT_RESULT_MAX_LENGTH))
    coverage_recorded: Mapped[bool] = mapped_column(server_default=text("false"))
    results_recorded: Mapped[bool] = mapped_column(server_default=text("false"))
    parser_version: Mapped[str | None] = mapped_column(String(VERSION_MAX_LENGTH))
    engine_version: Mapped[str | None] = mapped_column(String(VERSION_MAX_LENGTH))
    exit_code: Mapped[int | None]
    observation_count: Mapped[int | None]
    result_details: Mapped[JsonObject | None] = mapped_column(JSONB)
    plan_hash: Mapped[str | None] = mapped_column(String(SHA256_BYTES * 2))
    profile_definition_sha256: Mapped[str | None] = mapped_column(String(SHA256_BYTES * 2))
    guard_policy_version: Mapped[str | None] = mapped_column(String(32))


class ScanEventModel(Base):
    __tablename__ = "scan_events"
    __table_args__ = (
        PrimaryKeyConstraint("scan_id", "sequence"),
        ForeignKeyConstraint(
            ["scanner_run_id", "scan_id"],
            ["scanner_runs.id", "scanner_runs.scan_id"],
            name="fk_scan_events_run_scan",
            ondelete="RESTRICT",
        ),
        CheckConstraint("sequence > 0", name="sequence_positive"),
        CheckConstraint(f"event_type IN ({_EVENT_TYPES})", name="event_type_valid"),
        CheckConstraint(
            f"(event_type = '{EventType.RUN_STATUS.value}') = (scanner_run_id IS NOT NULL)",
            name="run_matches_type",
        ),
        CheckConstraint(
            "jsonb_typeof(payload) = 'object' "
            f"AND octet_length(payload::text) <= {MAX_EVENT_PAYLOAD_BYTES}",
            name="payload_valid",
        ),
    )

    scan_id: Mapped[UUID] = mapped_column(ForeignKey("scans.id", ondelete="RESTRICT"))
    # 每個 scan 各自的流水號，在持有 scan 的鎖時取 max + 1（依 commit 的順序、沒有間隔）。
    sequence: Mapped[int] = mapped_column(autoincrement=False)
    event_type: Mapped[str] = mapped_column(String(EVENT_TYPE_MAX_LENGTH))
    scanner_run_id: Mapped[UUID | None]
    payload: Mapped[JsonObject] = mapped_column(JSONB)
    # 實際寫入的時間：同一個 transaction 中的事件也有先後。
    created_at: Mapped[datetime] = mapped_column(server_default=func.clock_timestamp())


class ScanOperationModel(Base):
    __tablename__ = "scan_operations"
    __table_args__ = (
        PrimaryKeyConstraint("scan_id", "ordinal"),
        UniqueConstraint("scan_id", "method", "path"),
        CheckConstraint(f"method IN ({_METHODS})", name="method_valid"),
        CheckConstraint("left(path, 1) = '/'", name="path_valid"),
        CheckConstraint(f"ordinal >= 0 AND ordinal < {MAX_OPERATIONS}", name="ordinal_valid"),
        CheckConstraint(
            "operation_id IS NULL OR char_length(btrim(operation_id)) > 0",
            name="operation_id_not_blank",
        ),
        CheckConstraint(
            f"ineligible_reason IS NULL OR ineligible_reason IN ({_REASONS})",
            name="reason_valid",
        ),
    )

    scan_id: Mapped[UUID] = mapped_column(ForeignKey("scans.id", ondelete="RESTRICT"))
    ordinal: Mapped[int] = mapped_column(autoincrement=False)
    method: Mapped[str] = mapped_column(String(METHOD_MAX_LENGTH))
    path: Mapped[str] = mapped_column(String(PATH_MAX_LENGTH))
    operation_id: Mapped[str | None] = mapped_column(String(OPERATION_ID_MAX_LENGTH))
    # NULL 代表在 grant 的範圍內（coverage 的分母）。
    ineligible_reason: Mapped[str | None] = mapped_column(String(LABEL_MAX_LENGTH))


class RunCoverageModel(Base):
    """一個 run 轉送的請求涵蓋的 operation（docs/DECISIONS.md §16.6）；不可修改或刪除。"""

    __tablename__ = "run_coverage"
    __table_args__ = (
        PrimaryKeyConstraint("scanner_run_id", "ordinal"),
        ForeignKeyConstraint(
            ["scanner_run_id", "scan_id"],
            ["scanner_runs.id", "scanner_runs.scan_id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["scan_id", "ordinal"],
            ["scan_operations.scan_id", "scan_operations.ordinal"],
            ondelete="RESTRICT",
        ),
        Index("ix_run_coverage_scan_id", "scan_id"),
    )

    scanner_run_id: Mapped[UUID]
    scan_id: Mapped[UUID]
    ordinal: Mapped[int] = mapped_column(autoincrement=False)
    authenticated: Mapped[bool]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class ArtifactModel(UuidPrimaryKeyMixin, CreatedAtMixin, Base):
    """一個 run 的輸入與輸出檔（manifest 的內容）；不可修改或刪除。內容在 runs volume。"""

    __tablename__ = "artifacts"
    __table_args__ = (
        ForeignKeyConstraint(
            ["scanner_run_id", "scan_id"],
            ["scanner_runs.id", "scanner_runs.scan_id"],
            ondelete="RESTRICT",
        ),
        UniqueConstraint("scanner_run_id", "kind", "path"),
        # observations 以 (report_artifact_id, scanner_run_id) 引用：報告一定屬於同一個 run。
        UniqueConstraint("id", "scanner_run_id"),
        Index("ix_artifacts_scan_id", "scan_id"),
        CheckConstraint(
            f"(kind = '{ArtifactKind.OUTPUT.value}' "
            f"AND classification = '{ArtifactClassification.MASKED.value}') "
            f"OR (kind = '{ArtifactKind.INPUT.value}' "
            f"AND classification = '{ArtifactClassification.INPUT.value}')",
            name="classification_matches_kind",
        ),
        CheckConstraint(f"sha256 ~ '{_SHA256_HEX}'", name="sha256_valid"),
        CheckConstraint("size >= 0 AND redactions >= 0", name="counts_not_negative"),
        CheckConstraint("char_length(btrim(path)) > 0", name="path_not_blank"),
        CheckConstraint("char_length(btrim(storage_key)) > 0", name="storage_key_not_blank"),
    )

    scanner_run_id: Mapped[UUID]
    scan_id: Mapped[UUID]
    kind: Mapped[str] = mapped_column(String(LABEL_MAX_LENGTH))
    path: Mapped[str] = mapped_column(String(ARTIFACT_PATH_MAX_LENGTH))
    sha256: Mapped[str] = mapped_column(String(SHA256_BYTES * 2))
    size: Mapped[int] = mapped_column(BigInteger)
    redactions: Mapped[int]
    classification: Mapped[str] = mapped_column(String(LABEL_MAX_LENGTH))
    encrypted: Mapped[bool] = mapped_column(server_default=text("false"))
    storage_key: Mapped[str] = mapped_column(String(ARTIFACT_STORAGE_KEY_MAX_LENGTH))


class ObservationModel(UuidPrimaryKeyMixin, CreatedAtMixin, Base):
    """工具的一個單次觀察（CLAUDE.md §10；docs/DECISIONS.md §19.6）；不可修改或刪除。

    文字都已遮罩、截斷。等級與信心是工具的原始值，正規化在 T19。
    """

    __tablename__ = "observations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["scanner_run_id", "scan_id"],
            ["scanner_runs.id", "scanner_runs.scan_id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["report_artifact_id", "scanner_run_id"],
            ["artifacts.id", "artifacts.scanner_run_id"],
            ondelete="RESTRICT",
        ),
        UniqueConstraint("scanner_run_id", "source_event_id"),
        UniqueConstraint("scanner_run_id", "ordinal"),
        # 查詢：依 scan、引擎的順序與入庫的順序列出。
        Index(
            "ix_observations_scan_id_scanner_run_id_ordinal", "scan_id", "scanner_run_id", "ordinal"
        ),
        CheckConstraint("ordinal >= 1", name="ordinal_valid"),
        CheckConstraint("source_index >= 0", name="source_index_valid"),
        CheckConstraint(f"source_event_id ~ '{_SHA256_HEX}'", name="source_event_id_valid"),
        CheckConstraint("char_length(btrim(source_rule)) > 0", name="source_rule_not_blank"),
        CheckConstraint("char_length(btrim(title)) > 0", name="title_not_blank"),
        CheckConstraint("char_length(btrim(raw_severity)) > 0", name="raw_severity_not_blank"),
        CheckConstraint("char_length(btrim(raw_confidence)) > 0", name="raw_confidence_not_blank"),
        CheckConstraint("cwe_id IS NULL OR cwe_id > 0", name="cwe_positive"),
        CheckConstraint("wasc_id IS NULL OR wasc_id > 0", name="wasc_positive"),
        CheckConstraint(f"method IN ({_OBSERVATION_METHODS})", name="method_valid"),
        CheckConstraint("left(path, 1) = '/'", name="path_valid"),
        CheckConstraint(
            f"parameter_location IN ({_PARAMETER_LOCATIONS})", name="parameter_location_valid"
        ),
        CheckConstraint(
            rf"auth_role ~ '^[a-z][a-z0-9_]{{0,{ROLE_LABEL_MAX_LENGTH - 1}}}$'",
            name="auth_role_valid",
        ),
        CheckConstraint("char_length(btrim(parser_version)) > 0", name="parser_version_not_blank"),
    )

    scanner_run_id: Mapped[UUID]
    scan_id: Mapped[UUID]
    ordinal: Mapped[int] = mapped_column(autoincrement=False)
    source_event_id: Mapped[str] = mapped_column(String(SHA256_BYTES * 2))
    source_index: Mapped[int]
    source_rule: Mapped[str] = mapped_column(String(RULE_MAX_LENGTH))
    rule_variant: Mapped[str | None] = mapped_column(String(RULE_MAX_LENGTH))
    title: Mapped[str] = mapped_column(String(TITLE_MAX_LENGTH))
    raw_severity: Mapped[str] = mapped_column(String(RAW_LEVEL_MAX_LENGTH))
    severity_label: Mapped[str] = mapped_column(String(RAW_LEVEL_MAX_LENGTH))
    raw_confidence: Mapped[str] = mapped_column(String(RAW_LEVEL_MAX_LENGTH))
    confidence_label: Mapped[str] = mapped_column(String(RAW_LEVEL_MAX_LENGTH))
    cwe_id: Mapped[int | None]
    wasc_id: Mapped[int | None]
    method: Mapped[str] = mapped_column(String(METHOD_MAX_LENGTH))
    path: Mapped[str] = mapped_column(String(POSITION_MAX_LENGTH))
    query: Mapped[str | None] = mapped_column(String(POSITION_MAX_LENGTH))
    parameter: Mapped[str | None] = mapped_column(String(PARAMETER_MAX_LENGTH))
    parameter_location: Mapped[str] = mapped_column(String(LABEL_MAX_LENGTH))
    attack: Mapped[str | None] = mapped_column(String(TEXT_MAX_LENGTH))
    evidence: Mapped[str | None] = mapped_column(String(TEXT_MAX_LENGTH))
    other_info: Mapped[str | None] = mapped_column(String(TEXT_MAX_LENGTH))
    auth_role: Mapped[str] = mapped_column(String(ROLE_LABEL_MAX_LENGTH))
    report_artifact_id: Mapped[UUID | None]
    parser_version: Mapped[str] = mapped_column(String(VERSION_MAX_LENGTH))
