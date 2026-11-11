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

from pydantic import BaseModel, ConfigDict, Field, StrictInt

from secscan.core.json_types import JsonObject
from secscan.grants.schemas import BudgetIn, BudgetOut
from secscan.scans.domain.allocation import EngineBudget, EngineBudgetRequest
from secscan.scans.domain.catalog import Engine, ScanProfile
from secscan.scans.domain.evidence import (
    EvidenceHold,
    EvidenceHoldCode,
    EvidenceState,
    EvidenceStatus,
    HoldStage,
)
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


class EngineBudgetIn(BaseModel):
    """一個引擎的份額（T31；docs/DECISIONS.md §29）：建立時凍結，之後不能修改。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    engine: Engine
    max_requests: StrictInt
    max_duration_seconds: StrictInt


class ScanCreate(BaseModel):
    """建立 scan；budget 省略的項目使用 grant 的值。

    engine_budgets 是選填的引擎子預算：只用於兩個以上掃描引擎的 scan，每個引擎各列一次；省略時
    每個 run 分到剩下的全部預算（規則由 domain 判斷）。
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_id: UUID
    scope_grant_id: UUID
    api_spec_id: UUID | None = None
    auth_profile_id: UUID | None = None
    profile: ScanProfile
    engines: list[Engine] = Field(min_length=1, max_length=len(Engine))
    budget: BudgetIn = Field(default_factory=BudgetIn)
    engine_budgets: list[EngineBudgetIn] | None = Field(
        default=None, min_length=1, max_length=len(Engine)
    )

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
            engine_budgets=(
                tuple(
                    EngineBudgetRequest(
                        engine=item.engine,
                        max_requests=item.max_requests,
                        max_duration_seconds=item.max_duration_seconds,
                    )
                    for item in self.engine_budgets
                )
                if self.engine_budgets is not None
                else None
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


class EngineBudgetOut(BaseModel):
    """建立 scan 時凍結的這個引擎的上限（T31）。"""

    model_config = ConfigDict(frozen=True)

    max_requests: int
    max_duration_seconds: int

    @classmethod
    def of(cls, budget: EngineBudget) -> Self:
        return cls(
            max_requests=budget.max_requests, max_duration_seconds=budget.max_duration_seconds
        )


class RunUsageOut(BaseModel):
    """這個 run 分到的配額與 guard 的計數（T31；docs/DECISIONS.md §29）。

    沒有容器（in-process 的 fake、還沒開始、開始之前就結束）或不明時是 null；
    duration_allotted_seconds 在 T31 之前的 run 沒有記下。traffic_duration_seconds 是容器啟動到
    清理完成的秒數，可能略多於分到的秒數（被 runner 停止時的清理時間），會從之後的 run 扣除。
    """

    model_config = ConfigDict(frozen=True)

    requests_allotted: int | None
    duration_allotted_seconds: int | None
    requests_sent: int | None
    requests_denied: int | None
    traffic_duration_seconds: int | None

    @classmethod
    def of(cls, run: ScannerRun) -> Self:
        return cls(
            requests_allotted=run.requests_allotted,
            duration_allotted_seconds=run.seconds_allotted,
            requests_sent=run.requests_sent,
            requests_denied=run.requests_denied,
            traffic_duration_seconds=run.traffic_seconds,
        )


class RunEvidenceHoldOut(BaseModel):
    """keeper 的隔離紀錄（docs/DECISIONS.md §30.12）：目錄連續超過資源上限而加密失敗。

    error_code：深度（EVIDENCE_TREE_TOO_DEEP）、條目數（EVIDENCE_TREE_TOO_MANY_ENTRIES）或路徑
    總長度（EVIDENCE_TREE_PATHS_TOO_LONG）。

    stage（§30.13）：isolating（隔離未完成：目錄還在 active/，worker 可能讀得到）、isolated（已搬到
    held/，worker 讀不到）、releasing（已在 held/ 加密並驗證，正在搬回）、resolved（已解除）。

    isolated_at：搬到 held/ 的時間；releasing_at：開始解除的時間。這個版本之前就解除的紀錄兩者都是
    null。resolved_at：人工以 `secscan-admin retry-evidence` 加密成功的時間；還沒解除是 null。
    搬移失敗的細節只在 retention-status。
    """

    model_config = ConfigDict(frozen=True)

    error_code: EvidenceHoldCode
    attempts: int
    stage: HoldStage
    held_at: datetime
    isolated_at: datetime | None
    releasing_at: datetime | None
    resolved_at: datetime | None

    @classmethod
    def of(cls, hold: EvidenceHold) -> Self:
        return cls(
            error_code=hold.code,
            attempts=hold.attempts,
            stage=hold.stage,
            held_at=hold.held_at,
            isolated_at=hold.isolated_at,
            releasing_at=hold.releasing_at,
            resolved_at=hold.resolved_at,
        )


class RunEvidenceOut(BaseModel):
    """runs volume 中原始證據的狀態（docs/DECISIONS.md §30.3、§30.12）。

    none：從來沒有目錄；pending：還沒加密（執行中、等待解析，或加密失敗後等待重試）；
    sealed：只剩加密檔（run 結束之後才加密，不是全程靜態加密）；purged：保留期限到了已刪除；
    manual_intervention_required：目錄超過上限、連續加密失敗而被隔離，明文保留、等待人工處理
    （不是加密成功）。hold：隔離紀錄，從來沒有隔離是 null，解除之後仍保留。
    """

    model_config = ConfigDict(frozen=True)

    status: EvidenceStatus
    sealed_at: datetime | None
    purged_at: datetime | None
    hold: RunEvidenceHoldOut | None

    @classmethod
    def of(cls, state: EvidenceState) -> Self:
        return cls(
            status=state.status,
            sealed_at=state.sealed_at,
            purged_at=state.purged_at,
            hold=RunEvidenceHoldOut.of(state.hold) if state.hold is not None else None,
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
    # 解析過才有值（fake、preflight 與還沒解析的 run 是 null）。
    result: RunResultOut | None
    # 引擎子預算（T31）：建立時凍結的上限；沒有指定是 null（分到剩下的全部）。
    budget: EngineBudgetOut | None
    usage: RunUsageOut
    evidence: RunEvidenceOut

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
            result=RunResultOut.of(run.result) if run.result is not None else None,
            budget=EngineBudgetOut.of(run.budget) if run.budget is not None else None,
            usage=RunUsageOut.of(run),
            evidence=RunEvidenceOut.of(run.evidence),
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
