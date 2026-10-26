"""scans、scanner_runs、scan_events、scan_operations 資料表（docs/DECISIONS.md §13）。

- scans：快照以複合 FK 引用 target（含 project）、grant、規格與 auth profile 的版本，DB 保證它們
  屬於同一個 target；建立後只有狀態、取消與結束的時間可以改，終止之後完全不可變
  （migration 的 trigger）。
- scanner_runs：佇列的單位；lease 的欄位只在持有 lease 的狀態有值。
- scan_events、scan_operations：append-only。
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
from secscan.scans.domain.model import ANONYMOUS_ROLE, MAX_EVENT_PAYLOAD_BYTES, EventType
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
_METHODS = _in_list(method.upper() for method in OPERATION_METHODS)


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
