"""scan 的請求與回應 schema（docs/API_CONTRACT.md §7、§8、§17）。

- 請求只限制型別與長度；引擎、profile 與預算的規則由 domain 在權限檢查之後判斷。
- 回應是完整的 scan：快照引用的版本、每個引擎的 run、凍結的 operation 數（coverage 的分母）。
  fixture 表示結果不是真的掃描（有 fake 引擎）；results_complete 只有 completed 才是 true。
- budget_usage、auth.preflight 與 coverage 的量測都來自 guard 的計數與 worker 的判斷
  （docs/DECISIONS.md §16.4 至 §16.6），不採用工具自報的數字。
"""

from datetime import datetime
from typing import Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from secscan.core.json_types import JsonObject
from secscan.grants.schemas import BudgetIn, BudgetOut
from secscan.guard.domain.policy import GuardPolicyVersion
from secscan.scans.domain.catalog import Engine, ScanProfile
from secscan.scans.domain.lifecycle import RunStatus, ScanStatus
from secscan.scans.domain.model import Scan, ScanEvent, ScannerRun
from secscan.scans.domain.observation import Observation, ParameterLocation, RunResult
from secscan.scans.domain.preflight import PreflightResult
from secscan.scans.domain.request import BudgetRequest, ScanRequest
from secscan.scans.domain.usage import (
    authentication_health_unknown,
    authentication_lost,
    budget_usage,
    coverage_measured,
    preflight_status,
)

# coverage 沒有量測依據、或認證沒有被證明有效時的原因（contract §8）。
TELEMETRY_UNAVAILABLE = "TRAFFIC_TELEMETRY_UNAVAILABLE"
NO_API_SPEC = "NO_API_SPEC"
AUTHENTICATION_NOT_VERIFIED = "AUTHENTICATION_NOT_VERIFIED"
# 憑證在掃描中途失效（docs/DECISIONS.md §20.4）：之後的結果不是以這個身分取得的。
AUTHENTICATION_LOST = "AUTHENTICATION_LOST"
# guard 的紀錄看不出憑證是否整段有效（沒有紀錄、telemetry 不完整、T16 之前的結果）。
AUTHENTICATION_HEALTH_UNKNOWN = "AUTHENTICATION_HEALTH_UNKNOWN"


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
    # preflight 的結果（passed、failed、inconclusive、blocked、not_executed）；還沒結束是 null。
    preflight: PreflightResult | None


class AuthHealthOut(BaseModel):
    """帶認證 header 的請求：被接受與被拒絕（401、403）的數量；regressed 是接受過、最後被拒絕的
    operation 數；probe_rejected 是 preflight 的端點被拒絕的次數；lost 是判定憑證失效
    （docs/DECISIONS.md §20.4）。
    """

    model_config = ConfigDict(frozen=True)

    accepted: int
    rejected: int
    regressed: int
    probe_rejected: int
    lost: bool


class GuardTrafficOut(BaseModel):
    """guard 記下的流量明細（§20.3）：telemetry 不能核對時 answered 與 auth 是 null。"""

    model_config = ConfigDict(frozen=True)

    forwarded: int
    policy_version: GuardPolicyVersion | None = None
    forwarded_encoded: int | None = None
    denied: dict[str, int]
    exhausted: bool
    first_at: datetime | None
    last_at: datetime | None
    answered: int | None
    auth: AuthHealthOut | None


class RunResultOut(BaseModel):
    """解析的結果：工具的版本與退出碼、入庫與排除的數量（docs/DECISIONS.md §19.6）。

    excluded 是工具回報、但不是目標的回應或不在範圍內的告警；traffic_verified 是 false 時，沒有
    guard 的 telemetry 可以核對。problem 是輸出不能用的原因（穩定的代碼）。guard_traffic 是 guard
    的流量明細（T16 之前的結果，或 guard 沒有這個 run 的紀錄時是 null）。
    """

    model_config = ConfigDict(frozen=True)

    parser_version: str
    engine_version: str | None
    exit_code: int | None
    observation_count: int
    excluded: dict[str, int]
    duplicates: int
    truncated_fields: int
    engine_errors: int
    engine_warnings: int
    time_limit_reached: bool
    traffic_verified: bool
    problem: str | None
    components: dict[str, str]
    guard_traffic: GuardTrafficOut | None = None

    @classmethod
    def of(cls, result: RunResult) -> Self:
        return cls.model_validate(
            {
                **result.details,
                "parser_version": result.parser_version,
                "engine_version": result.engine_version,
                "exit_code": result.exit_code,
                "observation_count": result.observation_count,
            }
        )


class EngineRunOut(BaseModel):
    model_config = ConfigDict(frozen=True)

    engine: Engine
    sequence: int
    status: RunStatus
    error_code: str | None
    started_at: datetime | None
    finished_at: datetime | None
    # 實際執行的 ExecutionPlan（映像、參數、輸入檔、上限）與 zap 的 profile 定義的 sha256
    # （§20.2）；沒有建立容器的 run 是 null。
    plan_hash: str | None
    profile_definition_sha256: str | None
    guard_policy_version: GuardPolicyVersion | None
    # 解析過才有值（fake、preflight 與還沒解析的 run 是 null）。
    result: RunResultOut | None

    @classmethod
    def of(cls, run: ScannerRun) -> Self:
        return cls(
            engine=run.engine,
            sequence=run.sequence,
            status=run.status,
            error_code=run.error_code.value if run.error_code is not None else None,
            started_at=run.started_at,
            finished_at=run.finished_at,
            plan_hash=run.plan_hash,
            profile_definition_sha256=run.profile_definition_sha256,
            guard_policy_version=run.guard_policy_version,
            result=RunResultOut.of(run.result) if run.result is not None else None,
        )


class ObservationOut(BaseModel):
    """工具的單次觀察（遮罩、截斷之後）：不是 finding，等級與信心是工具的原始值。

    attack、evidence、other_info 是目標回應的不可信內容，顯示時要編碼。
    """

    model_config = ConfigDict(frozen=True)

    id: UUID
    scan_id: UUID
    scanner_run_id: UUID
    engine: Engine
    ordinal: int
    source_rule: str
    rule_variant: str | None
    title: str
    raw_severity: str
    severity_label: str
    raw_confidence: str
    confidence_label: str
    cwe_id: int | None
    wasc_id: int | None
    method: str
    path: str
    query: str | None
    parameter: str | None
    parameter_location: ParameterLocation
    attack: str | None
    evidence: str | None
    other_info: str | None
    auth_role: str
    parser_version: str
    created_at: datetime

    @classmethod
    def of(cls, observation: Observation) -> Self:
        return cls(
            **{name: getattr(observation, name) for name in cls.model_fields},
        )


class CoverageOut(BaseModel):
    """建立時凍結的 operation 數（沒有規格時是 null），以及實際轉送的請求涵蓋的數量。

    observed 與 authenticated 只在有量測依據時給值；authenticated 要 preflight 通過（否則是 0），
    匿名的 scan 是 null。observed 不代表所有漏洞種類都測過了。
    """

    model_config = ConfigDict(frozen=True)

    eligible_operations: int | None
    ineligible_operations: int | None
    observed_operations: int | None
    authenticated_operations: int | None
    coverage_measured: bool
    limitations: list[str]


class BudgetUsageOut(BaseModel):
    """guard 實際轉送與拒絕的請求數與流量的秒數，跨 run 加總（不明是 null）。"""

    model_config = ConfigDict(frozen=True)

    requests_sent: int | None
    requests_denied: int | None
    traffic_duration_seconds: int | None


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
    budget_usage: BudgetUsageOut
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
                    profile_id=auth.profile_id,
                    version=auth.version,
                    role_label=auth.role_label,
                    preflight=preflight_status(scan.runs),
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
            budget_usage=_budget_usage(scan),
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
    coverage = scan.coverage
    measured = coverage is not None and coverage_measured(scan.runs, has_spec=True)
    limitations = [] if coverage is not None else [NO_API_SPEC]
    if not measured:
        limitations.append(TELEMETRY_UNAVAILABLE)
    verified = preflight_status(scan.runs) is PreflightResult.PASSED
    if scan.auth is not None and not verified:
        limitations.append(AUTHENTICATION_NOT_VERIFIED)
    lost = scan.auth is not None and authentication_lost(scan.runs)
    if lost:
        limitations.append(AUTHENTICATION_LOST)
    elif scan.auth is not None and authentication_health_unknown(scan.runs):
        limitations.append(AUTHENTICATION_HEALTH_UNKNOWN)
    observed = authenticated = None
    if coverage is not None and measured:
        observed = coverage.observed_operations
        # 失效之後的 token 打到公開端點仍是 200，會被算成已認證：不給這個數字（§20.4）。
        if scan.auth is not None and not lost:
            authenticated = coverage.authenticated_operations if verified else 0
    return CoverageOut(
        eligible_operations=coverage.eligible_operations if coverage is not None else None,
        ineligible_operations=coverage.ineligible_operations if coverage is not None else None,
        observed_operations=observed,
        authenticated_operations=authenticated,
        coverage_measured=measured,
        limitations=limitations,
    )


def _budget_usage(scan: Scan) -> BudgetUsageOut:
    usage = budget_usage(scan.runs)
    return BudgetUsageOut(
        requests_sent=usage.requests_sent,
        requests_denied=usage.requests_denied,
        traffic_duration_seconds=usage.traffic_seconds,
    )
