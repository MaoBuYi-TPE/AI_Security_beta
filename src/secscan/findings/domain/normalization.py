"""工具原始等級與信心的正規化（docs/DECISIONS.md §25.4；CLAUDE.md §10）。

observation 保留工具的原值；這裡的對照表有版本（NORMALIZATION_VERSION），改表就要升版。
- severity：ZAP 的 riskcode 0 到 3 → info/low/medium/high；Nuclei 的 info.severity 一對一
  （不分大小寫）。其他值（含 Nuclei 的 unknown）→ info，並標 needs_review（不猜等級）。
- confidence：ZAP 的 0 到 4 依 ZAP 自己的標籤（是工具的自評，不是人工 triage）；Nuclei 不回報
  → unknown。
  finding 不聚合 confidence：多個來源不提高信心，只在各來源保留。
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from secscan.core.json_types import JsonObject, JsonValue
from secscan.scans.domain.catalog import Engine

NORMALIZATION_VERSION = "1"


class Severity(StrEnum):
    """由低到高宣告（highest 依宣告的順序比較）。"""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    FALSE_POSITIVE = "false_positive"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"
    UNKNOWN = "unknown"


_RANK = MappingProxyType({severity: rank for rank, severity in enumerate(Severity)})
_SEVERITIES: Mapping[Engine, Mapping[str, Severity]] = MappingProxyType(
    {
        Engine.ZAP: MappingProxyType(
            {"0": Severity.INFO, "1": Severity.LOW, "2": Severity.MEDIUM, "3": Severity.HIGH}
        ),
        Engine.NUCLEI: MappingProxyType({severity.value: severity for severity in Severity}),
    }
)
_CONFIDENCES: Mapping[Engine, Mapping[str, Confidence]] = MappingProxyType(
    {
        Engine.ZAP: MappingProxyType(
            {
                "0": Confidence.FALSE_POSITIVE,
                "1": Confidence.LOW,
                "2": Confidence.MEDIUM,
                "3": Confidence.HIGH,
                "4": Confidence.CONFIRMED,
            }
        ),
    }
)
# Nuclei 的值是模板作者寫的文字：比較前去掉空白、轉小寫。ZAP 的是數字代碼，原樣比對。
_CASE_INSENSITIVE = frozenset({Engine.NUCLEI})


@dataclass(frozen=True, slots=True)
class Normalized:
    severity: Severity
    confidence: Confidence
    # 等級無法對應（不是表中的值）：要人工確認，不代表弱點的嚴重程度。
    needs_review: bool


def normalize(engine: Engine, raw_severity: str, raw_confidence: str) -> Normalized:
    severity = _SEVERITIES.get(engine, {}).get(_key(engine, raw_severity))
    confidence = _CONFIDENCES.get(engine, {}).get(_key(engine, raw_confidence), Confidence.UNKNOWN)
    if severity is None:
        return Normalized(Severity.INFO, confidence, needs_review=True)
    return Normalized(severity, confidence, needs_review=False)


def highest(severities: Iterable[Severity]) -> Severity:
    """最高的等級（來源數不加分；空的輸入是呼叫端的錯誤）。"""
    return max(severities, key=_RANK.__getitem__)


def normalization_document() -> JsonObject:
    """對照表的內容（taxonomy 的 sha256 包含它：改表就會改變版本的雜湊）。"""
    case_insensitive: list[JsonValue] = [engine.value for engine in sorted(_CASE_INSENSITIVE)]
    return {
        "version": NORMALIZATION_VERSION,
        "severity": {
            engine.value: {raw: value.value for raw, value in sorted(table.items())}
            for engine, table in sorted(_SEVERITIES.items())
        },
        "confidence": {
            engine.value: {raw: value.value for raw, value in sorted(table.items())}
            for engine, table in sorted(_CONFIDENCES.items())
        },
        "case_insensitive": case_insensitive,
    }


def _key(engine: Engine, raw: str) -> str:
    return raw.strip().lower() if engine in _CASE_INSENSITIVE else raw
