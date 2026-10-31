"""ZAP 輸出的判定與觀察（docs/DECISIONS.md §19.2、§19.3、§19.4）；純函式，不丟例外。

輸出（報告、log、guard 的 telemetry）都是不可信的資料：資料的問題一律走判定（RunOutcome）。依序：
1. 退出碼 1、沒有報告 → failed（ENGINE_FAILED）：ZAP 沒有跑到 plan。
2. 報告或 log 不能用、摘要和退出碼矛盾 → failed（OUTPUT_INVALID）。
3. 退出碼 1、報告有效 → failed（ENGINE_REPORTED_ERRORS），部分結果入庫。
4. guard 沒有轉送任何請求，或沒有任何請求得到上游的回應 → failed（NO_TARGET_TRAFFIC）。
5. 退出碼 2、摘要有 plan 的 maxDuration → timed_out（ENGINE_TIMEOUT），觀察入庫。
6. 其他 → succeeded；沒有觀察就是乾淨的結果。

ZAP 的報告沒有 response 的 header 與 status（允許的範本只有這一個），分層排除不是目標的回應：
不在 origin 上 → guard 一定會拒絕（和 guard 同一套規則）→ telemetry 中沒有上游回應。telemetry 不能用
時少了第三層，改以內容是否為 guard 的拒絕訊息判斷，結果標 traffic_verified=False。

文字先遮罩、後截斷；識別（source_event_id）在遮罩之後計算，不含 ZAP 每次都不同的 instance id。
"""

from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import unquote_plus

from secscan.core.text import display_text
from secscan.grants.domain.matching import ScopeRules
from secscan.guard.domain.requests import DENY_MESSAGE, scope_reason, split_target
from secscan.scanners.domain.zap.log import PlanSummary, parse_summary
from secscan.scanners.domain.zap.policy import REQUIRED_ADDONS
from secscan.scanners.domain.zap.report import (
    Alert,
    Instance,
    ReportProblem,
    ZapReport,
    parse_report,
)
from secscan.scans.domain.coverage import Exchange, telemetry_complete
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.domain.observation import (
    PARAMETER_MAX_LENGTH,
    POSITION_MAX_LENGTH,
    TEXT_MAX_LENGTH,
    TITLE_MAX_LENGTH,
    Exclusion,
    ObservationInput,
    ParameterLocation,
    ParsedRun,
    RunOutcome,
    event_id,
)
from secscan.security.redaction import redact_text, redact_url, sensitive_query_values
from secscan.targets.domain import DEFAULT_HTTP_PORT, Origin

PARSER_VERSION = "zap-traditional-json/1"
_NO_ERRORS = 0
_ENGINE_ERRORS = 1
_ENGINE_WARNINGS = 2
# ZAP 自己的等級名稱（riskcode、confidence；org.parosproxy.paros.core.scanner.Alert）。
_RISK_LABELS = ("Informational", "Low", "Medium", "High")
_CONFIDENCE_LABELS = ("False Positive", "Low", "Medium", "High", "User Confirmed")
_REPORT_UNREADABLE = "report_unreadable"
_LOG_UNREADABLE = "log_unreadable"
_SUMMARY_MISSING = "summary_missing"
_SUMMARY_MISMATCH = "summary_mismatch"
_OUTPUT_INVALID = RunOutcome(RunStatus.FAILED, RunErrorCode.OUTPUT_INVALID)

_Answers = frozenset[tuple[str, str]]


@dataclass(frozen=True, slots=True)
class ZapOutput:
    """一個 run 的輸出與判斷需要的範圍。

    exit_code 是 None：manifest 讀不到。report_listed：manifest 有列出報告（report 是 None 而這裡
    是 True：讀不到或超過上限）。forwarded 是 guard 記下的轉送數（None 是不明）；exchanges 是
    telemetry（None 是讀不到）。
    """

    exit_code: int | None
    report: bytes | None = field(repr=False)
    report_listed: bool
    log: bytes | None = field(repr=False)
    origin: Origin
    rules: ScopeRules
    forwarded: int | None
    exchanges: tuple[Exchange, ...] | None = field(repr=False)


@dataclass(frozen=True, slots=True)
class _Collected:
    observations: tuple[ObservationInput, ...]
    excluded: Counter[Exclusion]
    duplicates: int
    truncated_fields: int


def interpret(output: ZapOutput) -> ParsedRun:
    if output.exit_code == _ENGINE_ERRORS and not output.report_listed:
        return ParsedRun(PARSER_VERSION, RunOutcome(RunStatus.FAILED, RunErrorCode.ENGINE_FAILED))
    if output.report is None:
        return _invalid(_REPORT_UNREADABLE)
    report = parse_report(output.report)
    if isinstance(report, ReportProblem):
        return _invalid(report.value)
    if output.log is None:
        return _invalid(_LOG_UNREADABLE)
    summary = parse_summary(output.log)
    if summary is None:
        return _invalid(_SUMMARY_MISSING)
    if not _consistent(output.exit_code, summary):
        return _invalid(_SUMMARY_MISMATCH)
    return _parsed(output, report, summary)


def _invalid(problem: str) -> ParsedRun:
    return ParsedRun(PARSER_VERSION, _OUTPUT_INVALID, problem=problem)


def _consistent(exit_code: int | None, summary: PlanSummary) -> bool:
    if exit_code == _NO_ERRORS:
        return summary.succeeded
    if exit_code == _ENGINE_ERRORS:
        return summary.errors > 0
    return exit_code == _ENGINE_WARNINGS and summary.warnings > 0 and summary.errors == 0


def _parsed(output: ZapOutput, report: ZapReport, summary: PlanSummary) -> ParsedRun:
    answers = _answers(output.forwarded, output.exchanges)
    collected = _collect(report, output.origin, output.rules, answers)
    outcome = _outcome(summary, answers)
    return ParsedRun(
        parser_version=PARSER_VERSION,
        outcome=outcome,
        engine_version=report.version,
        observations=collected.observations,
        excluded=dict(collected.excluded),
        duplicates=collected.duplicates,
        truncated_fields=collected.truncated_fields,
        engine_errors=summary.errors,
        engine_warnings=summary.warnings,
        time_limit_reached=summary.max_duration,
        traffic_verified=answers is not None,
        components=REQUIRED_ADDONS,
    )


def _outcome(summary: PlanSummary, answers: _Answers | None) -> RunOutcome:
    if summary.errors:
        return RunOutcome(RunStatus.FAILED, RunErrorCode.ENGINE_REPORTED_ERRORS)
    if answers is not None and not answers:
        return RunOutcome(RunStatus.FAILED, RunErrorCode.NO_TARGET_TRAFFIC)
    if summary.max_duration:
        return RunOutcome(RunStatus.TIMED_OUT, RunErrorCode.ENGINE_TIMEOUT)
    return RunOutcome(RunStatus.SUCCEEDED)


def _answers(forwarded: int | None, exchanges: tuple[Exchange, ...] | None) -> _Answers | None:
    """得到上游回應的 (method, path)；None 是沒有依據。

    guard 記下轉送 0 個：沒有 telemetry 的檔案也算有依據。轉送數不明或 telemetry 不完整就無法判斷
    （和 coverage 相同的條件）：殘缺的檔案不等於沒有流量。
    """
    if forwarded == 0:
        return frozenset()
    if forwarded is None or exchanges is None:
        return None
    if not telemetry_complete(exchanges, forwarded=forwarded):
        return None
    return frozenset(
        (exchange.method, exchange.path) for exchange in exchanges if exchange.status is not None
    )


def _collect(
    report: ZapReport, origin: Origin, rules: ScopeRules, answers: _Answers | None
) -> _Collected:
    observations: list[ObservationInput] = []
    excluded: Counter[Exclusion] = Counter()
    seen: set[str] = set()
    duplicates = truncated = 0
    index = -1
    for alert in report.alerts:
        for instance in alert.instances:
            index += 1
            target = _request_target(instance.uri, origin)
            if target is None:
                excluded[Exclusion.OUT_OF_SCOPE] += 1
                continue
            exclusion = _exclusion(instance, target, rules, answers)
            if exclusion is not None:
                excluded[exclusion] += 1
                continue
            observation, cut = _observation(alert, instance, target, index)
            if observation.source_event_id in seen:
                duplicates += 1
                continue
            seen.add(observation.source_event_id)
            observations.append(observation)
            truncated += cut
    return _Collected(tuple(observations), excluded, duplicates, truncated)


def _request_target(uri: str, origin: Origin) -> str | None:
    """URI 在 target 的 origin 上時，回傳送出的 target（path 加 query；fragment 不會送出）。

    以 canonical origin 的文字比對：帳密、其他 port 與相似的 host 都不符合。
    """
    prefixes = [str(origin)]
    if origin.port == DEFAULT_HTTP_PORT:
        prefixes.append(f"{origin}:{DEFAULT_HTTP_PORT}")
    for prefix in prefixes:
        if uri == prefix or uri.startswith((f"{prefix}/", f"{prefix}?", f"{prefix}#")):
            rest = uri[len(prefix) :].partition("#")[0]
            return rest if rest.startswith("/") else f"/{rest}"
    return None


def _exclusion(
    instance: Instance, target: str, rules: ScopeRules, answers: _Answers | None
) -> Exclusion | None:
    if scope_reason(instance.method, target, rules) is not None:
        return Exclusion.GUARD_DENIED
    path, _ = split_target(target)
    if answers is not None and (instance.method, path) not in answers:
        return Exclusion.NOT_ANSWERED
    # 內容是目標控制的：只在沒有 telemetry 可以核對時才看（目標不能藉此隱藏自己的告警）。
    if answers is None and (
        DENY_MESSAGE in instance.evidence or DENY_MESSAGE in instance.other_info
    ):
        return Exclusion.GUARD_RESPONSE
    return None


def _observation(
    alert: Alert, instance: Instance, target: str, index: int
) -> tuple[ObservationInput, int]:
    values = sensitive_query_values(target)
    attack = redact_text(instance.attack, values=values)
    evidence = redact_text(instance.evidence, values=values)
    other_info = redact_text(instance.other_info, values=values)
    parameter = redact_text(instance.param)
    position = redact_url(target)
    path, _, query = position.partition("?")
    source_event_id = event_id(
        alert.alert_ref, instance.method, position, parameter, attack, evidence, other_info
    )
    fields = (
        display_text(redact_text(alert.name), max_length=TITLE_MAX_LENGTH),
        display_text(path, max_length=POSITION_MAX_LENGTH),
        display_text(query, max_length=POSITION_MAX_LENGTH),
        display_text(parameter, max_length=PARAMETER_MAX_LENGTH),
        display_text(attack, max_length=TEXT_MAX_LENGTH),
        display_text(evidence, max_length=TEXT_MAX_LENGTH),
        display_text(other_info, max_length=TEXT_MAX_LENGTH),
    )
    title, shown_path, shown_query, shown_parameter, shown_attack, shown_evidence, shown_other = (
        text for text, _ in fields
    )
    return (
        ObservationInput(
            source_event_id=source_event_id,
            source_index=index,
            source_rule=alert.plugin_id,
            rule_variant=alert.alert_ref,
            title=title,
            raw_severity=alert.risk,
            severity_label=_RISK_LABELS[int(alert.risk)],
            raw_confidence=alert.confidence,
            confidence_label=_CONFIDENCE_LABELS[int(alert.confidence)],
            cwe_id=alert.cwe_id,
            wasc_id=alert.wasc_id,
            method=instance.method,
            path=shown_path,
            query=shown_query or None,
            parameter=shown_parameter or None,
            parameter_location=_location(instance.param, query),
            attack=shown_attack or None,
            evidence=shown_evidence or None,
            other_info=shown_other or None,
        ),
        sum(cut for _, cut in fields),
    )


def _location(parameter: str, query: str) -> ParameterLocation:
    names = {unquote_plus(pair.partition("=")[0]) for pair in query.split("&") if pair}
    return ParameterLocation.QUERY if parameter in names else ParameterLocation.UNKNOWN
