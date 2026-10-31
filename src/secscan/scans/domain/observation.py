"""觀察的輸入契約（docs/DECISIONS.md §19.3）：parser 的輸出，與引擎無關；worker 以它寫入 DB。

observation 是不可變的單次觀察：只有工具回報的原始值（等級、信心）、遮罩之後的位置與文字。正規化的
severity、rule group 與 fingerprint 在 T19（CLAUDE.md §10）。M4 的 Nuclei parser 輸出同一個契約。
RunOutcome 是輸出的判定（§19.2）：解析不丟例外，資料的問題都走判定。
"""

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType

from secscan.core.json_types import JsonObject, JsonValue
from secscan.scans.domain.lifecycle import ERROR_REQUIRED_RUN_STATUSES, RunErrorCode, RunStatus

MAX_DETAILS_BYTES = 4096
_OUTCOME_STATUSES = frozenset({RunStatus.SUCCEEDED, RunStatus.FAILED, RunStatus.TIMED_OUT})


class ParameterLocation(StrEnum):
    QUERY = "query"
    UNKNOWN = "unknown"


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
class ObservationInput:
    """一個觀察。文字都已遮罩、截斷，可以直接保存（不含 NUL、孤立的 surrogate）。"""

    source_event_id: str
    source_index: int
    source_rule: str
    rule_variant: str | None
    title: str
    raw_severity: str
    raw_confidence: str
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
    }


def outcome_from_details(details: Mapping[str, JsonValue]) -> RunOutcome:
    """存下的判定（重試時不再解析）。內容是自己寫入的：格式不符是 DB 被改動，讓它拋出。"""
    error_code = details["error_code"]
    return RunOutcome(
        RunStatus(str(details["status"])),
        RunErrorCode(str(error_code)) if error_code is not None else None,
    )
