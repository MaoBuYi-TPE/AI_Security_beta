"""觀察的輸入契約（docs/DECISIONS.md §19.3）：parser 的輸出，與引擎無關；worker 以它寫入 DB。

observation 是不可變的單次觀察：只有工具回報的原始值（等級、信心）、遮罩之後的位置與文字。正規化的
severity、rule group 與 fingerprint 在 T19（CLAUDE.md §10）。M4 的 Nuclei parser 輸出同一個契約。
RunOutcome 是輸出的判定（§19.2）：解析不丟例外，資料的問題都走判定。
"""

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from uuid import UUID

from secscan.core.json_types import JsonObject, JsonValue
from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.lifecycle import ERROR_REQUIRED_RUN_STATUSES, RunErrorCode, RunStatus
from secscan.scans.domain.traffic import GuardTraffic

MAX_DETAILS_BYTES = 4096
TITLE_MAX_LENGTH = 512
PARAMETER_MAX_LENGTH = 512
POSITION_MAX_LENGTH = 2048
TEXT_MAX_LENGTH = 4096
RULE_MAX_LENGTH = 64
RAW_LEVEL_MAX_LENGTH = 32
VERSION_MAX_LENGTH = 64
# runner 收集的上限：深度 8 加上檔名本身，每層 255 個字元。
ARTIFACT_PATH_MAX_LENGTH = 2400
# 工具回報的請求可能是 grant 以外的 method：比 OpenAPI 的清單多 CONNECT。
OBSERVATION_METHODS = frozenset(
    {"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE", "CONNECT"}
)
_OUTCOME_STATUSES = frozenset({RunStatus.SUCCEEDED, RunStatus.FAILED, RunStatus.TIMED_OUT})


class ParameterLocation(StrEnum):
    QUERY = "query"
    UNKNOWN = "unknown"


class ArtifactKind(StrEnum):
    INPUT = "input"
    OUTPUT = "output"


class ArtifactClassification(StrEnum):
    """INPUT：runner 產生的輸入。MASKED：工具的輸出，已遮罩、仍是目標的不可信內容（§19.6）。"""

    INPUT = "input"
    MASKED = "masked"


class Exclusion(StrEnum):
    """工具回報、但不是目標的回應或不在範圍內的告警（§19.4）；只計數，不入庫。"""

    OUT_OF_SCOPE = "out_of_scope"
    GUARD_DENIED = "guard_denied"
    NOT_ANSWERED = "not_answered"
    GUARD_RESPONSE = "guard_response"


@dataclass(frozen=True, slots=True)
class RunOutcome:
    status: RunStatus
    error_code: RunErrorCode | None = None

    def __post_init__(self) -> None:
        if self.status not in _OUTCOME_STATUSES:
            raise ValueError(f"{self.status.value} 不是解析的判定")
        if (self.status in ERROR_REQUIRED_RUN_STATUSES) != (self.error_code is not None):
            raise ValueError(f"{self.status.value} 的錯誤碼不符合規則")


@dataclass(frozen=True, slots=True)
class ArtifactRecord:
    """manifest 的一個檔案（hash 是遮罩之後的內容）。path 是 in/ 或 out/ 底下的相對路徑。"""

    kind: ArtifactKind
    path: str
    sha256: str
    size: int
    redactions: int = 0

    @property
    def classification(self) -> ArtifactClassification:
        if self.kind is ArtifactKind.INPUT:
            return ArtifactClassification.INPUT
        return ArtifactClassification.MASKED

    def storage_key(self, run_id: UUID) -> str:
        """runs volume 中的相對路徑。"""
        directory = "in" if self.kind is ArtifactKind.INPUT else "out"
        return f"{run_id}/{directory}/{self.path}"


@dataclass(frozen=True, slots=True)
class ObservationInput:
    """一個觀察。文字都已遮罩、截斷，可以直接保存（不含 NUL、孤立的 surrogate）。"""

    source_event_id: str
    source_index: int
    source_rule: str
    rule_variant: str | None
    title: str
    # 工具自己的值與名稱（例如 ZAP 的 "2"、"Medium"）；正規化在 T19。
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


@dataclass(frozen=True, slots=True)
class Observation:
    """已入庫的觀察（GET /scans/{id}/observations）。engine 來自 run。"""

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


@dataclass(frozen=True, slots=True)
class RunResult:
    """已入庫的解析結果（GET /scans/{id} 的 engines[].result）。details 是 result_details。"""

    parser_version: str
    engine_version: str | None
    exit_code: int | None
    observation_count: int
    details: Mapping[str, JsonValue]


@dataclass(frozen=True, slots=True)
class ParsedRun:
    """一個 run 的輸出解析的結果。engine_version 是 None：輸出不能用，版本未知。"""

    parser_version: str
    outcome: RunOutcome
    engine_version: str | None = None
    observations: tuple[ObservationInput, ...] = ()
    excluded: Mapping[Exclusion, int] = field(default_factory=lambda: MappingProxyType({}))
    duplicates: int = 0
    truncated_fields: int = 0
    engine_errors: int = 0
    engine_warnings: int = 0
    # 引擎在自己的時間上限停止。
    time_limit_reached: bool = False
    # 有 guard 的 telemetry 可以核對（§19.4）；沒有時少一層排除。
    traffic_verified: bool = False
    # 輸出不能用的原因（穩定的代碼，不含輸出的內容）。
    problem: str | None = None
    components: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    # guard 記下的流量明細（§20.3）：worker 讀 guard 的 summary 與 telemetry 後加上。
    traffic: GuardTraffic | None = None


def event_id(*fields: str) -> str:
    """同一個 run 中判斷重複的識別：欄位以 JSON 陣列分隔，不會互相滲透。"""
    encoded = json.dumps(list(fields), ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("ascii")).hexdigest()


def result_details(parsed: ParsedRun) -> JsonObject:
    """scanner_runs.result_details：計數、判定與元件的版本（§19.6），不含輸出的內容。"""
    outcome = parsed.outcome
    excluded: JsonObject = {
        reason.value: parsed.excluded.get(reason, 0) for reason in sorted(Exclusion)
    }
    components: dict[str, JsonValue] = dict(parsed.components)
    return {
        "status": outcome.status.value,
        "error_code": outcome.error_code.value if outcome.error_code is not None else None,
        "excluded": excluded,
        "duplicates": parsed.duplicates,
        "truncated_fields": parsed.truncated_fields,
        "engine_errors": parsed.engine_errors,
        "engine_warnings": parsed.engine_warnings,
        "time_limit_reached": parsed.time_limit_reached,
        "traffic_verified": parsed.traffic_verified,
        "problem": parsed.problem,
        "components": components,
        "guard_traffic": _traffic_details(parsed.traffic),
    }


def _traffic_details(traffic: GuardTraffic | None) -> JsonValue:
    if traffic is None:
        return None
    health = traffic.auth
    auth: JsonValue = None
    if health is not None:
        auth = {
            "accepted": health.accepted,
            "rejected": health.rejected,
            "regressed": health.regressed,
            "probe_rejected": health.probe_rejected,
            "lost": health.lost,
        }
    denied: JsonObject = dict(traffic.denied)
    return {
        "forwarded": traffic.forwarded,
        "denied": denied,
        "exhausted": traffic.exhausted,
        "first_at": _utc(traffic.first_at),
        "last_at": _utc(traffic.last_at),
        "answered": traffic.answered,
        "auth": auth,
    }


def _utc(epoch: float | None) -> str | None:
    return None if epoch is None else datetime.fromtimestamp(epoch, UTC).isoformat()


def outcome_from_details(details: Mapping[str, JsonValue]) -> RunOutcome:
    """存下的判定（重試時不再解析）。內容是自己寫入的：格式不符是 DB 被改動，讓它拋出。"""
    error_code = details["error_code"]
    return RunOutcome(
        RunStatus(str(details["status"])),
        RunErrorCode(str(error_code)) if error_code is not None else None,
    )
