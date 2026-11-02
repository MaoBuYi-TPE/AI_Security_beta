"""Nuclei JSONL 輸出的嚴格解析與判定（T18；DECISIONS §19.2 至 §19.5、§23）；純函式，不丟例外。

輸出（JSONL、guard 的 telemetry）是不可信的資料：資料的問題一律走判定（RunOutcome）。依序：
1. 退出碼非 0、沒有列出報告 → failed（ENGINE_FAILED）：nuclei 沒有正常結束（exit code 只收集 0）。
2. 報告讀不到、過大、或任一行不是合法的 JSONL 記錄 → failed（OUTPUT_INVALID）。
3. guard 沒有轉送任何請求 → failed（NO_TARGET_TRAFFIC）。
4. 達共享預算/時間上限（guard summary）→ timed_out（ENGINE_TIMEOUT），已解析的觀察仍入庫。
5. 其他 → succeeded；沒有觀察就是乾淨的結果（零告警，和失敗明確可分）。

guard 的合成 403（negative-matcher 模板會誤報成目標缺陷）以回應的 X-Secscan-Guard header 權威排除：
guard 會剝除上游偽造的同名 header，所以這個 header 出現就代表是 guard 合成的回應。沒有 telemetry 時
退到 body 的拒絕訊息（目標可控，只在這種情況看）。文字先遮罩、後截斷；識別在遮罩之後計算。
"""

import json
import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import NoReturn

from secscan.core.text import display_text
from secscan.grants.domain.matching import ScopeRules
from secscan.guard.domain.requests import (
    DENY_MESSAGE,
    GUARD_HEADER,
    Reason,
    scope_reason,
    split_target,
)
from secscan.scanners.domain.nuclei.policy import NUCLEI_VERSION
from secscan.scans.domain.coverage import Exchange, telemetry_complete
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.domain.observation import (
    OBSERVATION_METHODS,
    POSITION_MAX_LENGTH,
    RAW_LEVEL_MAX_LENGTH,
    RULE_MAX_LENGTH,
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

PARSER_VERSION = "nuclei-jsonl/1"
_SUCCESS = 0
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_RESULTS = 20_000
# nuclei 的 info.severity（org/pdcp）；未知的值保留原文、標成 Unknown。
_SEVERITY_LABELS = {
    "info": "Informational",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
    "unknown": "Unknown",
}
# nuclei 不回報 confidence：以固定佔位（DB 要求 raw_confidence 非空），正規化在 T19。
_RAW_CONFIDENCE = "unknown"
_CONFIDENCE_LABEL = "Unknown"
_CWE = re.compile(r"CWE-([0-9]{1,7})", re.IGNORECASE)
_REPORT_UNREADABLE = "report_unreadable"
# template-id 要存進 source_rule（VARCHAR 64、non-blank）：首字英數，其餘英數與 . _ -。
_TEMPLATE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
# guard 合成回應的標記：名稱精確比對、值為 Reason（guard 只剝除精確名稱）。
_GUARD_HEADER_LOWER = GUARD_HEADER.lower()
_GUARD_REASONS = frozenset(reason.value for reason in Reason)

_Answers = frozenset[tuple[str, str]]


class JsonlProblem(StrEnum):
    TOO_LARGE = "report_too_large"
    NOT_JSONL = "report_not_jsonl"
    LIMITS = "report_limits"


@dataclass(frozen=True, slots=True)
class NucleiFinding:
    """JSONL 的一行（嚴格解析後的結構）。response 保留原文供 guard 標記判斷，遮罩在 results。"""

    template_id: str
    name: str
    severity: str
    matched_at: str
    method: str
    extracted: tuple[str, ...]
    variant: str | None  # extractor-name 或 matcher-name：同一模板多個比對時的區分
    cwe_id: int | None
    response: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class NucleiOutput:
    """一個 run 的輸出與判斷需要的範圍。

    exit_code 是 None：manifest 讀不到。report 是 None 而 report_listed 是 True：讀不到或超過上限。
    forwarded 是 guard 記下的轉送數（None 是不明）；exchanges 是 telemetry（None 是讀不到）。
    time_limit_reached：guard 的 summary 顯示共享預算/時間用完（worker 代入）。
    """

    exit_code: int | None
    report: bytes | None = field(repr=False)
    report_listed: bool
    origin: Origin
    rules: ScopeRules
    forwarded: int | None
    exchanges: tuple[Exchange, ...] | None = field(repr=False)
    time_limit_reached: bool = False


@dataclass(frozen=True, slots=True)
class _Collected:
    observations: tuple[ObservationInput, ...]
    excluded: Counter[Exclusion]
    duplicates: int
    truncated_fields: int


def interpret(output: NucleiOutput) -> ParsedRun:
    # 非零退出（collect_exit_codes={0}）且沒有列出報告 → 引擎失敗；exit_code 讀不到（manifest 壞）
    # 不算失敗，往下走成 OUTPUT_INVALID（report_unreadable），和 worker/nuclei.py 的文件一致。
    if output.exit_code is not None and output.exit_code != _SUCCESS and not output.report_listed:
        return ParsedRun(PARSER_VERSION, RunOutcome(RunStatus.FAILED, RunErrorCode.ENGINE_FAILED))
    if output.report is None:
        return _invalid(_REPORT_UNREADABLE)
    findings = parse_report(output.report)
    if isinstance(findings, JsonlProblem):
        return _invalid(findings.value)
    return _parsed(output, findings)


def _invalid(problem: str) -> ParsedRun:
    return ParsedRun(
        PARSER_VERSION, RunOutcome(RunStatus.FAILED, RunErrorCode.OUTPUT_INVALID), problem=problem
    )


def parse_report(raw: bytes) -> tuple[NucleiFinding, ...] | JsonlProblem:
    """嚴格解析 JSONL：每行是合法 JSON 的 http 記錄，否則整份不用（corrupted 不做部分解析）。"""
    if len(raw) > MAX_REPORT_BYTES:
        return JsonlProblem.TOO_LARGE
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return JsonlProblem.NOT_JSONL
    findings: list[NucleiFinding] = []
    try:
        # 只以 \n 切行（JSONL 的分隔）：不可用 splitlines()，否則目標回應裡的 U+0085／U+2028／
        # U+2029 會把一行切成兩段、讓整份報告變成不合法（來自目標的位元組，不做 Unicode 斷行）。
        for line in text.split("\n"):
            if line.strip():
                findings.append(_finding(_strict_json(line)))
    except _RejectedError:
        return JsonlProblem.NOT_JSONL
    if len(findings) > MAX_RESULTS:
        return JsonlProblem.LIMITS
    return tuple(findings)


class _RejectedError(Exception):
    pass


def _strict_json(line: str) -> object:
    # nuclei 的 JSONL 合法地帶浮點數（例如 cvss-score），所以允許 float；只拒 NaN/Infinity。
    try:
        return json.loads(line, object_pairs_hook=_unique_keys, parse_constant=_reject_number)
    except (ValueError, RecursionError):
        raise _RejectedError from None


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document = dict(pairs)
    if len(document) != len(pairs):
        raise ValueError("重複的 key")
    return document


def _reject_number(_: str) -> NoReturn:
    raise ValueError("JSONL 不接受 NaN/Infinity")


def _finding(document: object) -> NucleiFinding:
    top = _object(document)
    if _text(top, "type") != "http":
        raise _RejectedError  # 凍結清單只收 http；其他型別不應出現
    template_id = _text(top, "template-id")
    if _TEMPLATE_ID.fullmatch(template_id) is None:
        raise _RejectedError  # 不合格的識別碼存不進 source_rule（整份判 OUTPUT_INVALID）
    info = _object(top.get("info"))
    name = _text(info, "name")
    severity = _text(info, "severity")  # 缺 key 由 _text 拒絕；長度在 _observation 截斷
    if not name.strip():
        raise _RejectedError
    return NucleiFinding(
        template_id=template_id,
        name=name,
        severity=severity,
        matched_at=_matched_at(top),
        method=_method(top.get("request")),
        extracted=_extracted(top.get("extracted-results")),
        variant=_variant(top),
        cwe_id=_cwe(info.get("classification")),
        response=_optional_text(top.get("response")) or "",
    )


def _parsed(output: NucleiOutput, findings: Sequence[NucleiFinding]) -> ParsedRun:
    answers = _answers(output.forwarded, output.exchanges)
    collected = _collect(findings, output.origin, output.rules, answers)
    return ParsedRun(
        parser_version=PARSER_VERSION,
        outcome=_outcome(answers, time_limit=output.time_limit_reached),
        engine_version=NUCLEI_VERSION,
        observations=collected.observations,
        excluded=dict(collected.excluded),
        duplicates=collected.duplicates,
        truncated_fields=collected.truncated_fields,
        time_limit_reached=output.time_limit_reached,
        traffic_verified=answers is not None,
    )


def _outcome(answers: _Answers | None, *, time_limit: bool) -> RunOutcome:
    if answers is not None and not answers:
        return RunOutcome(RunStatus.FAILED, RunErrorCode.NO_TARGET_TRAFFIC)
    if time_limit:
        return RunOutcome(RunStatus.TIMED_OUT, RunErrorCode.ENGINE_TIMEOUT)
    return RunOutcome(RunStatus.SUCCEEDED)


def _answers(forwarded: int | None, exchanges: tuple[Exchange, ...] | None) -> _Answers | None:
    """得到上游回應的 (method, path)；None 是沒有依據（和 ZAP、coverage 同一套條件）。"""
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
    findings: Sequence[NucleiFinding], origin: Origin, rules: ScopeRules, answers: _Answers | None
) -> _Collected:
    observations: list[ObservationInput] = []
    excluded: Counter[Exclusion] = Counter()
    seen: set[str] = set()
    duplicates = truncated = 0
    for index, finding in enumerate(findings):
        target = _request_target(finding.matched_at, origin)
        if target is None:
            excluded[Exclusion.OUT_OF_SCOPE] += 1
            continue
        exclusion = _exclusion(finding, target, rules, answers)
        if exclusion is not None:
            excluded[exclusion] += 1
            continue
        observation, cut = _observation(finding, target, index)
        if observation.source_event_id in seen:
            duplicates += 1
            continue
        seen.add(observation.source_event_id)
        observations.append(observation)
        truncated += cut
    return _Collected(tuple(observations), excluded, duplicates, truncated)


def _request_target(matched_at: str, origin: Origin) -> str | None:
    """matched-at 在 target 的 origin 上時回傳送出的 target（path 加 query；fragment 不送出）。

    以 canonical origin 的文字比對（比照 zap/results.py 的 _request_target）：帳密、其他 port 與
    相似的 host 都不符合。
    """
    prefixes = [str(origin)]
    if origin.port == DEFAULT_HTTP_PORT:
        prefixes.append(f"{origin}:{DEFAULT_HTTP_PORT}")
    for prefix in prefixes:
        boundaries = (f"{prefix}/", f"{prefix}?", f"{prefix}#")
        if matched_at == prefix or matched_at.startswith(boundaries):
            rest = matched_at[len(prefix) :].partition("#")[0]
            return rest if rest.startswith("/") else f"/{rest}"
    return None


def _exclusion(
    finding: NucleiFinding, target: str, rules: ScopeRules, answers: _Answers | None
) -> Exclusion | None:
    # guard 的合成 403：header 是權威的（guard 會剝除上游偽造的同名 header），一律排除。
    if _guard_marked(finding.response):
        return Exclusion.GUARD_RESPONSE
    if scope_reason(finding.method, target, rules) is not None:
        return Exclusion.GUARD_DENIED
    path, _ = split_target(target)
    if answers is not None and (finding.method, path) not in answers:
        return Exclusion.NOT_ANSWERED
    # body 是目標控制的：只在沒有 telemetry 可以核對時才看（目標不能藉此隱藏自己的告警）。
    if answers is None and DENY_MESSAGE in finding.response:
        return Exclusion.GUARD_RESPONSE
    return None


def _guard_marked(response: str) -> bool:
    """回應的 header 區塊有沒有 X-Secscan-Guard（guard 合成回應的權威標記）。

    只以 \\r?\\n 切 header（不用 splitlines，否則目標在 header 值裡放 U+2028／U+0085 可偽造一行）；
    名稱精確比對、不折疊 `_`（guard 只剝除名稱精確為 X-Secscan-Guard 的 header，X_Secscan_Guard
    不會被剝除、也不該被當成標記）；值必須是 Reason（縱深防禦）。
    """
    head = re.split(r"\r\n\r\n|\n\n", response, maxsplit=1)[0]
    for line in re.split(r"\r?\n", head)[1:]:  # 跳過狀態列
        name, separator, value = line.partition(":")
        if separator and name.strip().lower() == _GUARD_HEADER_LOWER:
            return value.strip() in _GUARD_REASONS
    return False


def _observation(finding: NucleiFinding, target: str, index: int) -> tuple[ObservationInput, int]:
    values = sensitive_query_values(target)
    evidence = redact_text(" ".join(finding.extracted), values=values)
    position = redact_url(target)
    path, _, query = position.partition("?")
    # 去重鍵含 variant（matcher/extractor 名稱）：同模板不同 matcher 是不同發現，不可當重複丟掉。
    source_event_id = event_id(
        finding.template_id, finding.variant or "", finding.method, position, evidence
    )
    fields = (
        display_text(redact_text(finding.name), max_length=TITLE_MAX_LENGTH),
        display_text(path, max_length=POSITION_MAX_LENGTH),
        display_text(query, max_length=POSITION_MAX_LENGTH),
        display_text(evidence, max_length=TEXT_MAX_LENGTH),
        display_text(redact_text(finding.matched_at, values=values), max_length=TEXT_MAX_LENGTH),
        # 識別欄位也有長度上限（簽章模板有 76 字元的 matcher 名）：一併截斷。
        display_text(finding.variant or "", max_length=RULE_MAX_LENGTH),
        display_text(finding.severity, max_length=RAW_LEVEL_MAX_LENGTH),
    )
    title, shown_path, shown_query, shown_evidence, shown_other, shown_variant, shown_severity = (
        text for text, _ in fields
    )
    return (
        ObservationInput(
            source_event_id=source_event_id,
            source_index=index,
            source_rule=finding.template_id,
            rule_variant=shown_variant or None,
            title=title,
            raw_severity=shown_severity or "unknown",
            severity_label=_SEVERITY_LABELS.get(finding.severity.strip().lower(), "Unknown"),
            raw_confidence=_RAW_CONFIDENCE,
            confidence_label=_CONFIDENCE_LABEL,
            cwe_id=finding.cwe_id,
            wasc_id=None,
            method=finding.method,
            path=shown_path,
            query=shown_query or None,
            parameter=None,
            parameter_location=ParameterLocation.UNKNOWN,
            attack=None,
            evidence=shown_evidence or None,
            other_info=shown_other or None,
        ),
        sum(cut for _, cut in fields),
    )


# --- JSONL 欄位的嚴格取值 -------------------------------------------------------------------


def _matched_at(top: dict[str, object]) -> str:
    value = top.get("matched-at")
    if isinstance(value, str) and value:
        return value
    return _text(top, "url")  # 退回模板的 base url


def _method(request: object) -> str:
    if not isinstance(request, str):
        return "GET"
    verb = request.partition(" ")[0].strip().upper()
    return verb if verb in OBSERVATION_METHODS else "GET"


def _extracted(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _variant(top: dict[str, object]) -> str | None:
    """同一模板多個比對時的區分：優先 extractor-name，否則 matcher-name。"""
    return _optional_text(top.get("extractor-name")) or _optional_text(top.get("matcher-name"))


def _cwe(classification: object) -> int | None:
    if not isinstance(classification, dict):
        return None
    raw = classification.get("cwe-id")
    candidates = raw if isinstance(raw, list) else [raw]
    for candidate in candidates:
        if isinstance(candidate, str):
            match = _CWE.search(candidate)
            if match is not None:
                return int(match.group(1))
    return None


def _object(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise _RejectedError
    return value


def _text(container: dict[str, object], key: str) -> str:
    value = container.get(key)
    if not isinstance(value, str):
        raise _RejectedError
    return value


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise _RejectedError
    return value
