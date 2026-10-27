"""scan 的請求與回應 schema（docs/API_CONTRACT.md §7、§8、§17）。

- 請求只限制型別與長度；引擎、profile 與預算的規則由 domain 在權限檢查之後判斷。
- 回應是完整的 scan：快照引用的版本、每個引擎的 run、凍結的 operation 數（coverage 的分母）。
  fixture 表示結果不是真的掃描（有 fake 引擎）；results_complete 只有 completed 才是 true。
"""

from datetime import datetime
from typing import Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from secscan.core.json_types import JsonObject
from secscan.grants.schemas import BudgetIn, BudgetOut
from secscan.scans.domain.catalog import Engine, ScanProfile
from secscan.scans.domain.lifecycle import RunStatus, ScanStatus
from secscan.scans.domain.model import Scan, ScanEvent, ScannerRun
from secscan.scans.domain.request import BudgetRequest, ScanRequest

# 還沒有量測實際流量（T12）：coverage_measured 一律 false，並說明原因（contract §8）。
TELEMETRY_UNAVAILABLE = "TRAFFIC_TELEMETRY_UNAVAILABLE"
NO_API_SPEC = "NO_API_SPEC"


class ScanCreate(BaseModel):
    """建立 scan；budget 省略的項目使用 grant 的值。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_id: UUID
    scope_grant_id: UUID
    api_spec_id: UUID | None = None
    auth_profile_id: UUID | None = None
    profile: ScanProfile
    engines: list[Engine] = Field(min_length=1, max_length=len(Engine))
    budget: BudgetIn = Field(default_factory=BudgetIn)

    def to_request(self) -> ScanRequest:
        return ScanRequest(
            target_id=self.target_id,
            scope_grant_id=self.scope_grant_id,
            api_spec_id=self.api_spec_id,
            auth_profile_id=self.auth_profile_id,
            profile=self.profile,
            engines=tuple(self.engines),
            budget=BudgetRequest(
                requests_per_second=self.budget.requests_per_second,
                max_requests=self.budget.max_requests,
                max_duration_seconds=self.budget.max_duration_seconds,
            ),
        )


class VersionRefOut(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: UUID
    version: int


class AuthBindingOut(BaseModel):
    """綁定的 auth profile 版本（不含 secret）。"""

    model_config = ConfigDict(frozen=True)

    profile_id: UUID
    version: int
    role_label: str


class EngineRunOut(BaseModel):
    model_config = ConfigDict(frozen=True)

    engine: Engine
    sequence: int
    status: RunStatus
    error_code: str | None
    started_at: datetime | None
    finished_at: datetime | None

    @classmethod
    def of(cls, run: ScannerRun) -> Self:
        return cls(
            engine=run.engine,
            sequence=run.sequence,
            status=run.status,
            error_code=run.error_code.value if run.error_code is not None else None,
            started_at=run.started_at,
            finished_at=run.finished_at,
        )


class CoverageOut(BaseModel):
    """建立時凍結的 operation 數；沒有規格時是 null。不代表實際測到了這些 operation。"""

    model_config = ConfigDict(frozen=True)

    eligible_operations: int | None
    ineligible_operations: int | None
    coverage_measured: bool
    limitations: list[str]


class ScanOut(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: UUID
    project_id: UUID
    target_id: UUID
    target_origin: str
    status: ScanStatus
    profile: ScanProfile
    scope_grant: VersionRefOut
    api_spec: VersionRefOut | None
    auth: AuthBindingOut | None
    auth_role: str
    budget: BudgetOut
    engines: list[EngineRunOut]
    coverage: CoverageOut
    fixture: bool
    results_complete: bool
    cancel_requested_at: datetime | None
    created_by_key_id: UUID
    created_at: datetime
    finished_at: datetime | None

    @classmethod
    def of(cls, scan: Scan) -> Self:
        spec, auth, budget = scan.api_spec, scan.auth, scan.budget
        return cls(
            id=scan.id,
            project_id=scan.project_id,
            target_id=scan.target_id,
            target_origin=str(scan.target_origin),
            status=scan.status,
            profile=scan.profile,
            scope_grant=VersionRefOut(id=scan.scope_grant.id, version=scan.scope_grant.version),
            api_spec=VersionRefOut(id=spec.id, version=spec.version) if spec is not None else None,
            auth=(
                AuthBindingOut(
                    profile_id=auth.profile_id, version=auth.version, role_label=auth.role_label
                )
                if auth is not None
                else None
            ),
            auth_role=scan.auth_role,
            budget=BudgetOut(
                requests_per_second=budget.requests_per_second,
                max_requests=budget.max_requests,
                max_duration_seconds=budget.max_duration_seconds,
            ),
            engines=[EngineRunOut.of(run) for run in scan.runs],
            coverage=_coverage(scan),
            fixture=scan.fixture,
            results_complete=scan.results_complete,
            cancel_requested_at=scan.cancel_requested_at,
            created_by_key_id=scan.created_by_key_id,
            created_at=scan.created_at,
            finished_at=scan.finished_at,
        )


class ScanEventOut(BaseModel):
    """一個狀態轉換；payload 只由 enum 與 id 組成。"""

    model_config = ConfigDict(frozen=True)

    sequence: int
    type: str
    scanner_run_id: UUID | None
    payload: JsonObject
    created_at: datetime

    @classmethod
    def of(cls, event: ScanEvent) -> Self:
        return cls(
            sequence=event.sequence,
            type=event.type.value,
            scanner_run_id=event.scanner_run_id,
            payload=event.payload,
            created_at=event.created_at,
        )


def _coverage(scan: Scan) -> CoverageOut:
    if scan.coverage is None:
        return CoverageOut(
            eligible_operations=None,
            ineligible_operations=None,
            coverage_measured=False,
            limitations=[NO_API_SPEC, TELEMETRY_UNAVAILABLE],
        )
    return CoverageOut(
        eligible_operations=scan.coverage.eligible_operations,
        ineligible_operations=scan.coverage.ineligible_operations,
        coverage_measured=False,
        limitations=[TELEMETRY_UNAVAILABLE],
    )
