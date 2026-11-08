"""harness 共用的不可變紀錄：由平台 API 的 JSON 正規化而來（benchmarks.collect）。

只保留評估與 manifest 需要的欄位；不保存觀察的 evidence（目標回應的內容）。
"""

from dataclasses import dataclass

# scan 的終止狀態（docs/API_CONTRACT.md §17.2）。
TERMINAL_SCAN_STATUSES = frozenset(
    {"completed", "partially_completed", "failed", "timed_out", "cancelled", "interrupted"}
)


@dataclass(frozen=True, slots=True)
class EngineCap:
    """建立 scan 時凍結的引擎上限（engines[].budget）。"""

    max_requests: int
    max_duration_seconds: int


@dataclass(frozen=True, slots=True)
class RunRecord:
    """一個引擎的 run：狀態、上限、分到的配額與 guard 的計數（不明是 None）。"""

    engine: str
    sequence: int
    status: str
    error_code: str | None
    plan_hash: str | None
    cap: EngineCap | None
    requests_allotted: int | None
    seconds_allotted: int | None
    requests_sent: int | None
    requests_denied: int | None
    traffic_seconds: int | None
    # 解析過的 run 才有（沒有收集的 run 是 None）。
    observation_count: int | None
    time_limit_reached: bool | None
    guard_exhausted: bool | None


@dataclass(frozen=True, slots=True)
class Signature:
    """對照 ground truth 與人工標記用的 finding 位置（同一個匿名 scan 內唯一）。"""

    rule_group: str
    method: str
    route: str
    parameter_location: str | None
    parameter_name: str | None


@dataclass(frozen=True, slots=True)
class FindingRecord:
    """GET /scans/{id}/findings 的一項：engines 與 observations 只看這個 scan。"""

    id: str
    kind: str
    signature: Signature
    engines: tuple[str, ...]
    observations: int


@dataclass(frozen=True, slots=True)
class ScanRecord:
    id: str
    status: str
    fixture: bool
    profile: str
    auth_role: str
    requests_per_second: int
    max_requests: int
    max_duration_seconds: int
    runs: tuple[RunRecord, ...]
    findings: tuple[FindingRecord, ...]
    observation_count: int
    coverage_measured: bool
    eligible_operations: int | None
    observed_operations: int | None
    created_at: str
    finished_at: str | None


@dataclass(frozen=True, slots=True)
class ComparisonItem:
    finding_id: str
    classification: str
    manual_review_required: bool


@dataclass(frozen=True, slots=True)
class ComparisonRecord:
    id: str
    baseline_scan_id: str
    current_scan_id: str
    comparability: str
    manual_review_required: bool
    items: tuple[ComparisonItem, ...]


@dataclass(frozen=True, slots=True)
class LabeledScan:
    """排程中的一次 scan 與它的結果（組別、靶場、版本來自規格）。"""

    position: int
    group: str
    target: str
    target_kind: str
    variant: str
    repetition: int | None
    comparison: str | None
    role: str | None
    scan: ScanRecord
