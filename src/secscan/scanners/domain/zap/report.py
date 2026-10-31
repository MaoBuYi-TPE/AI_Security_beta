"""traditional-json 報告的嚴格解析（docs/DECISIONS.md §19.3）；純函式，不丟例外。

報告是 ZAP 寫出的不可信資料（內容來自目標）：
- 上限先於解析；JSON 拒絕重複的 key、NaN、Infinity 與浮點數（這個範本沒有數字），接住超長的整數
  與過深的巢狀。
- 欄位的型別與格式都要正確；缺少必要的 key 整份不用。未知的 key 忽略（範本更新多出的欄位）。
- 只接受鎖定的版本：parser 的語意是對這個版本量測的。
這裡只取出結構，遮罩、截斷與排除在 results.py。desc、solution、reference 是規則固定的說明，不取。
"""

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn

from secscan.scanners.domain.zap.policy import ZAP_VERSION
from secscan.scans.domain.observation import OBSERVATION_METHODS

MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_SITES = 16
MAX_ALERTS = 1024
MAX_INSTANCES = 20_000
_PROGRAM = "ZAP"
_RISK_CODES = frozenset("0123")
_CONFIDENCES = frozenset("01234")
_ID = re.compile(r"-?[0-9]{1,9}")
_ALERT_REF = re.compile(r"-?[0-9]{1,9}(?:-[0-9]{1,9})?")


class ReportProblem(StrEnum):
    TOO_LARGE = "report_too_large"
    NOT_JSON = "report_not_json"
    SHAPE = "report_shape"
    PROGRAM = "report_program"
    VERSION = "report_version"
    LIMITS = "report_limits"


@dataclass(frozen=True, slots=True)
class Instance:
    uri: str
    method: str
    param: str
    attack: str
    evidence: str
    other_info: str


@dataclass(frozen=True, slots=True)
class Alert:
    plugin_id: str
    alert_ref: str
    name: str
    risk: str
    confidence: str
    cwe_id: int | None
    wasc_id: int | None
    instances: tuple[Instance, ...]


@dataclass(frozen=True, slots=True)
class ZapReport:
    version: str
    alerts: tuple[Alert, ...]


class _RejectedError(Exception):
    def __init__(self, problem: ReportProblem) -> None:
        self.problem = problem


def parse_report(raw: bytes) -> ZapReport | ReportProblem:
    if len(raw) > MAX_REPORT_BYTES:
        return ReportProblem.TOO_LARGE
    try:
        return _report(_strict_json(raw))
    except _RejectedError as rejected:
        return rejected.problem


def _strict_json(raw: bytes) -> object:
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_keys,
            parse_constant=_reject_number,
            parse_float=_reject_number,
        )
    except (ValueError, RecursionError):  # JSONDecodeError、UnicodeDecodeError 是 ValueError
        raise _RejectedError(ReportProblem.NOT_JSON) from None


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document = dict(pairs)
    if len(document) != len(pairs):
        raise ValueError("重複的 key")
    return document


def _reject_number(_: str) -> NoReturn:
    raise ValueError("這個範本沒有浮點數")


def _report(document: object) -> ZapReport:
    top = _object(document)
    if _text(top, "@programName") != _PROGRAM:
        raise _RejectedError(ReportProblem.PROGRAM)
    version = _text(top, "@version")
    if version != ZAP_VERSION:
        raise _RejectedError(ReportProblem.VERSION)
    sites = _list(top, "site")
    if len(sites) > MAX_SITES:
        raise _RejectedError(ReportProblem.LIMITS)
    raw_alerts = [alert for site in sites for alert in _list(_object(site), "alerts")]
    if len(raw_alerts) > MAX_ALERTS:
        raise _RejectedError(ReportProblem.LIMITS)
    alerts = tuple(_alert(_object(alert)) for alert in raw_alerts)
    if sum(len(alert.instances) for alert in alerts) > MAX_INSTANCES:
        raise _RejectedError(ReportProblem.LIMITS)
    return ZapReport(version=version, alerts=alerts)


def _alert(alert: dict[str, object]) -> Alert:
    instances = _list(alert, "instances")
    if len(instances) > MAX_INSTANCES:
        raise _RejectedError(ReportProblem.LIMITS)
    name = _text(alert, "name")
    risk = _text(alert, "riskcode")
    confidence = _text(alert, "confidence")
    if not name or risk not in _RISK_CODES or confidence not in _CONFIDENCES:
        raise _RejectedError(ReportProblem.SHAPE)
    return Alert(
        plugin_id=_matching(alert, "pluginid", _ID),
        alert_ref=_matching(alert, "alertRef", _ALERT_REF),
        name=name,
        risk=risk,
        confidence=confidence,
        cwe_id=_positive(_matching(alert, "cweid", _ID)),
        wasc_id=_positive(_matching(alert, "wascid", _ID)),
        instances=tuple(_instance(_object(instance)) for instance in instances),
    )


def _instance(instance: dict[str, object]) -> Instance:
    uri = _text(instance, "uri")
    method = _text(instance, "method")
    if not uri or method not in OBSERVATION_METHODS:
        raise _RejectedError(ReportProblem.SHAPE)
    return Instance(
        uri=uri,
        method=method,
        param=_text(instance, "param"),
        attack=_text(instance, "attack"),
        evidence=_text(instance, "evidence"),
        other_info=_text(instance, "otherinfo"),
    )


def _positive(text: str) -> int | None:
    value = int(text)
    return value if value > 0 else None


def _object(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise _RejectedError(ReportProblem.SHAPE)
    return value


def _list(container: dict[str, object], key: str) -> Sequence[object]:
    value = container.get(key)
    if not isinstance(value, list):
        raise _RejectedError(ReportProblem.SHAPE)
    return value


def _text(container: dict[str, object], key: str) -> str:
    value = container.get(key)
    if not isinstance(value, str):
        raise _RejectedError(ReportProblem.SHAPE)
    return value


def _matching(container: dict[str, object], key: str, pattern: re.Pattern[str]) -> str:
    value = _text(container, key)
    if pattern.fullmatch(value) is None:
        raise _RejectedError(ReportProblem.SHAPE)
    return value
