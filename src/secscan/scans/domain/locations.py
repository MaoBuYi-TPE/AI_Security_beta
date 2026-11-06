"""記憶體中的逐位置摘要；不含參數名稱／值，寫入 DB 前將字面 path 轉為 SHA-256。"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Location:
    method: str
    path: str
    answered: bool
    discovery_answered: bool
    authenticated: bool
    unanswered: bool


@dataclass(frozen=True, slots=True)
class RuleLocation:
    method: str
    path: str
    rule: str
    answered: bool
    parameters_unknown: bool
    parameters_truncated: bool


@dataclass(frozen=True, slots=True)
class LocationSummary:
    locations: tuple[Location, ...]
    rules: tuple[RuleLocation, ...]
    has_unusable_paths: bool
