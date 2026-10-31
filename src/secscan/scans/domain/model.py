"""scan 的 domain model 與事件的 payload（docs/DECISIONS.md §13.1、§13.5）。

repository 回傳這裡的 frozen model；從 DB 讀回的資料也經過 __post_init__ 的檢查（fail closed）。
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from secscan.core.json_types import JsonObject
from secscan.grants.domain.matching import IneligibleReason
from secscan.grants.domain.scope import Budget
from secscan.scans.domain.catalog import Engine, PlannedRun, ScanProfile
from secscan.scans.domain.lifecycle import (
    ERROR_REQUIRED_RUN_STATUSES,
    TERMINAL_SCAN_STATUSES,
    RunErrorCode,
    RunStatus,
    ScanStatus,
)
from secscan.scans.domain.observation import RunResult
from secscan.scans.domain.preflight import PreflightResult
from secscan.targets.domain import Origin

# 未認證的 scan 的 auth role（contract §7）；auth profile 不能使用這個 role_label
# （auth_profiles 的 RESERVED_ROLE_LABELS）。
ANONYMOUS_ROLE = "anonymous"
# 事件的 payload 只由 enum 與 id 組成，DB 的 CHECK 是 1 KiB。
MAX_EVENT_PAYLOAD_BYTES = 1_024
# 容器版 runner 的容器名稱（docs/DECISIONS.md §14.2）：一個 run 只可能有一個容器。
CONTAINER_NAME_PREFIX = "secscan-run-"


@dataclass(frozen=True, slots=True)
class VersionRef:
    """快照引用的不可變資料（grant、規格）：id 與它的版本。"""

    id: UUID
    version: int

    def __post_init__(self) -> None:
        if self.version < 1:
            raise ValueError("version 必須是正整數")


@dataclass(frozen=True, slots=True)
class AuthBinding:
    """綁定的 auth profile 版本（快照不含 secret，docs/DECISIONS.md §12.3）。"""

    profile_id: UUID
    version: int
    role_label: str

    def __post_init__(self) -> None:
        if self.version < 1:
            raise ValueError("auth profile 的 version 必須是正整數")
        if self.role_label == ANONYMOUS_ROLE:
            raise ValueError("anonymous 保留給未認證的 scan")


@dataclass(frozen=True, slots=True)
class ScannerRun:
    id: UUID
    scan_id: UUID
    engine: Engine
    sequence: int
    status: RunStatus
    error_code: RunErrorCode | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime
    # 共享預算與 telemetry（docs/DECISIONS.md §16.4 至 §16.6）：容器版的 run 才可能送出流量；
    # 用量是 guard 記下的數字（None 是不明）；coverage_recorded 是 telemetry 已對應到 operation。
    container: bool = False
    requests_sent: int | None = None
    requests_denied: int | None = None
    traffic_seconds: int | None = None
    preflight_result: PreflightResult | None = None
    coverage_recorded: bool = False
    # 解析的結果（docs/DECISIONS.md §19.6）；沒有解析過是 None。
    result: RunResult | None = None

    def __post_init__(self) -> None:
        if (self.status in ERROR_REQUIRED_RUN_STATUSES) != (self.error_code is not None):
            raise ValueError(f"run 的狀態 {self.status.value} 與錯誤碼不一致")
        if self.preflight_result is not None and self.engine is not Engine.PREFLIGHT:
            raise ValueError("只有 preflight 的 run 有 preflight 的結果")


@dataclass(frozen=True, slots=True)
class Coverage:
    """建立時凍結的 operation 數（coverage 的分母），以及轉送的請求涵蓋的 operation 數
    （observed；其中帶著認證 header 的是 authenticated，docs/DECISIONS.md §16.6）。
    """

    eligible_operations: int
    ineligible_operations: int
    observed_operations: int = 0
    authenticated_operations: int = 0

    def __post_init__(self) -> None:
        counts = (
            self.eligible_operations,
            self.ineligible_operations,
            self.observed_operations,
            self.authenticated_operations,
        )
        if any(count < 0 for count in counts):
            raise ValueError("coverage 的數量不可為負數")
        if (
            not self.authenticated_operations
            <= self.observed_operations
            <= (self.eligible_operations)
        ):
            raise ValueError("authenticated ≤ observed ≤ eligible")


@dataclass(frozen=True, slots=True)
class Scan:
    id: UUID
    project_id: UUID
    target_id: UUID
    target_origin: Origin
    status: ScanStatus
    profile: ScanProfile
    scope_grant: VersionRef
    api_spec: VersionRef | None
    auth: AuthBinding | None
    budget: Budget
    runs: tuple[ScannerRun, ...]
    coverage: Coverage | None
    cancel_requested_at: datetime | None
    created_by_key_id: UUID
    created_at: datetime
    finished_at: datetime | None

    def __post_init__(self) -> None:
        if not self.runs:
            raise ValueError("scan 至少要有一個 run")
        sequences = [run.sequence for run in self.runs]
        if sequences != list(range(1, len(self.runs) + 1)):
            raise ValueError("run 必須依 sequence 排列（從 1 開始連號）")

    @property
    def auth_role(self) -> str:
        return self.auth.role_label if self.auth is not None else ANONYMOUS_ROLE

    @property
    def fixture(self) -> bool:
        """有 fake 引擎：結果不是真的掃描（報告與實驗依此排除，docs/DECISIONS.md §13.7）。"""
        return any(run.engine is Engine.FAKE for run in self.runs)

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_SCAN_STATUSES

    @property
    def results_complete(self) -> bool:
        return self.status is ScanStatus.COMPLETED


@dataclass(frozen=True, slots=True)
class FrozenOperation:
    """建立 scan 時的 inventory 一列與它在 grant 下的判斷。

    ineligible_reason 是 None 代表在範圍內。
    """

    ordinal: int
    method: str
    path: str
    operation_id: str | None
    ineligible_reason: IneligibleReason | None


@dataclass(frozen=True, slots=True)
class NewScan:
    """要寫入的 scan、它的 run 與凍結的 operation（同一個 transaction）。"""

    project_id: UUID
    target_id: UUID
    target_origin: Origin
    scope_grant_id: UUID
    api_spec_id: UUID | None
    auth: AuthBinding | None
    profile: ScanProfile
    budget: Budget
    runs: tuple[PlannedRun, ...]
    operations: tuple[FrozenOperation, ...]
    idempotency_key: str = field(repr=False)
    request_sha256: bytes
    created_by_key_id: UUID


@dataclass(frozen=True, slots=True)
class Lease:
    """認領到的 run：之後每個轉換都要帶著它（owner 相同、而且還沒過期才算數）。"""

    run_id: UUID
    scan_id: UUID
    engine: Engine
    owner: str


class EventType(StrEnum):
    SCAN_CREATED = "scan.created"
    SCAN_STATUS = "scan.status"
    SCAN_CANCEL_REQUESTED = "scan.cancel_requested"
    RUN_STATUS = "run.status"


@dataclass(frozen=True, slots=True)
class ScanEvent:
    scan_id: UUID
    sequence: int
    type: EventType
    scanner_run_id: UUID | None
    payload: JsonObject
    created_at: datetime


def created_payload(*, profile: ScanProfile, engines: tuple[Engine, ...]) -> JsonObject:
    return {
        "status": ScanStatus.QUEUED.value,
        "profile": profile.value,
        "engines": [engine.value for engine in engines],
    }


def scan_status_payload(*, status: ScanStatus, previous: ScanStatus) -> JsonObject:
    return {"status": status.value, "previous_status": previous.value}


def cancel_requested_payload(*, previous: ScanStatus) -> JsonObject:
    return {"previous_status": previous.value}


def run_status_payload(
    *,
    engine: Engine,
    status: RunStatus,
    previous: RunStatus,
    error_code: RunErrorCode | None,
) -> JsonObject:
    return {
        "engine": engine.value,
        "status": status.value,
        "previous_status": previous.value,
        "error_code": error_code.value if error_code is not None else None,
    }
