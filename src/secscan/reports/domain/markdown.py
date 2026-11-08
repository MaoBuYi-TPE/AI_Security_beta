"""Markdown 報告（SEC-17；docs/DECISIONS.md §28.5）。純函式。

平台文字在 code 以外；不可信的值一律經 code_span（單行）或最上層的 code_block（多行）。輸入是
document.py 投影出的白名單文件，不直接讀快照。
"""

from datetime import datetime

from secscan.core.json_types import JsonObject, JsonValue
from secscan.reports.domain import wording
from secscan.reports.domain.document import document
from secscan.reports.domain.encoding import code_block, code_span
from secscan.reports.domain.model import ReportSnapshot


def markdown(snapshot: ReportSnapshot, generated_at: datetime, count: int) -> str:
    """Markdown：平台文字在 code 以外，不可信的值一律經 code_span／code_block。"""
    data = document(snapshot, generated_at, count)
    lines: list[str] = [f"# {wording.SECTION_TITLES['report']}", ""]
    truncation = data["truncation"]
    truncation = _obj(truncation)
    if truncation["notice"]:
        lines += [f"> {truncation['notice']}", ""]
    lines += [f"## {wording.SECTION_TITLES['notices']}", ""]
    lines += [f"- {notice}" for notice in _strings(data["notices"])]
    lines += ["", *_markdown_scan(data), *_markdown_summary(data)]
    lines += [f"## {wording.SECTION_TITLES['findings']}", ""]
    findings = data["findings"]
    findings = _list(findings)
    for index, finding in enumerate(findings, start=1):
        finding = _obj(finding)
        lines += _markdown_finding(index, finding)
    lines += _markdown_comparisons(data)
    if truncation["notice"]:
        lines += [f"## {wording.SECTION_TITLES['truncation']}", "", f"> {truncation['notice']}", ""]
    return "\n".join(lines) + "\n"


def _obj(value: JsonValue) -> JsonObject:
    if not isinstance(value, dict):
        raise TypeError("報告文件的結構不符")
    return value


def _list(value: JsonValue) -> list[JsonValue]:
    if not isinstance(value, list):
        raise TypeError("報告文件的結構不符")
    return value


def _strings(value: JsonValue) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _field(label: str, value: JsonValue, *, untrusted: bool = False) -> str:
    if value is None:
        return f"- {label}：（無）"
    if untrusted:
        return f"- {label}：{code_span(str(value))}"
    return f"- {label}：{value}"


def _markdown_scan(data: JsonObject) -> list[str]:
    scan, grant, auth = data["scan"], data["authorization"], data["authentication"]
    scan = _obj(scan)
    grant = _obj(grant)
    auth = _obj(auth)
    usage = scan["budget_usage"]
    usage = _obj(usage)
    lines = [f"## {wording.SECTION_TITLES['scan']}", ""]
    lines += [
        _field("report_id", data["report_id"]),
        _field(wording.FIELD_LABELS["generated_at"], data["generated_at"]),
        _field(wording.FIELD_LABELS["data_as_of"], data["data_as_of"]),
        _field("scan_id", scan["id"]),
        _field("status", scan["status"]),
        _field("results_complete", scan["results_complete"]),
        _field("fixture", scan["fixture"]),
        _field("profile", scan["profile"]),
        _field("target", scan["target_name"], untrusted=True),
        _field("origin", scan["target_origin"], untrusted=True),
        _field("auth_role", auth["role"], untrusted=True),
        _field("preflight", auth["preflight"]),
        _field("requests_sent", usage["requests_sent"]),
        _field("requests_denied", usage["requests_denied"]),
        _field("traffic_duration_seconds", usage["traffic_duration_seconds"]),
        "",
        f"## {wording.SECTION_TITLES['authorization']}",
        "",
        _field("grant_id", grant["grant_id"]),
        _field("grant_version", grant["grant_version"]),
        _field(wording.FIELD_LABELS["approved_at"], grant["approved_at"]),
        _field("valid_from", grant["valid_from"]),
        _field("valid_until", grant["valid_until"]),
        _field("authorization_reference", grant["authorization_reference"], untrusted=True),
        "",
        f"## {wording.SECTION_TITLES['engines']}",
        "",
        "| engine | status | error_code |",
        "|---|---|---|",
    ]
    engines = data["engines"]
    engines = _list(engines)
    for run in engines:
        run = _obj(run)
        lines.append(f"| {run['engine']} | {run['status']} | {run['error_code'] or '-'} |")
    coverage = data["coverage"]
    coverage = _obj(coverage)
    lines += ["", f"## {wording.SECTION_TITLES['coverage']}", ""]
    lines += [_field(key, coverage[key]) for key in coverage if key != "limitations"]
    lines += [f"- limitation：{item}" for item in _strings(coverage["limitations"])]
    return [*lines, ""]


def _markdown_summary(data: JsonObject) -> list[str]:
    summary_data = data["summary"]
    summary_data = _obj(summary_data)
    lines = [f"## {wording.SECTION_TITLES['summary']}", "", "| 項目 | 數量 |", "|---|---|"]
    for key, value in summary_data.items():
        if isinstance(value, dict):
            lines += [f"| {key}.{name} | {count} |" for name, count in value.items()]
        else:
            lines.append(f"| {key} | {value} |")
    return [*lines, ""]


def _markdown_finding(index: int, finding: JsonObject) -> list[str]:
    location = finding["location"]
    location = _obj(location)
    lines = [
        f"### {index}. {finding['severity']} / {finding['kind']} / {finding['category']}",
        "",
        _field("finding_id", finding["id"]),
        _field("title", finding["title"], untrusted=True),
        _field("rule_group", finding["rule_group"], untrusted=True),
        _field("method", location["method"]),
        _field("route", location["route"], untrusted=True),
        _field("parameter_location", location["parameter_location"]),
        _field("parameter", location["parameter_name"], untrusted=True),
        _field("auth_role", finding["auth_role"], untrusted=True),
        _field("auth_verified", finding["auth_verified"]),
        _field("triage", f"{finding['triage_state']}（{finding['triage_label']}）"),
        _field("lifecycle", f"{finding['lifecycle_state']}（{finding['lifecycle_label']}）"),
        _field("triage_version", finding["triage_version"]),
        _field("distinct_paths", finding["distinct_paths"]),
    ]
    if finding["review_label"]:
        lines.append(f"- 需要人工確認：{finding['review_label']}")
    resolution = finding["resolution"]
    if isinstance(resolution, dict):
        lines += _markdown_resolution(resolution)
    if finding["multiple_sources_note"]:
        lines.append(f"- {finding['multiple_sources_note']}")
    sources = finding["sources"]
    sources = _list(sources)
    for source in sources:
        source = _obj(source)
        lines.append(
            f"- source：{source['engine']} / {source['normalized_severity']} / "
            f"{source['observations']} / {code_span(str(source['rule']))}"
        )
    lines.append("")
    samples = finding["samples"]
    samples = _list(samples)
    for number, sample in enumerate(samples, start=1):
        sample = _obj(sample)
        lines += [
            f"樣本 {number}：path {code_span(str(sample['path']))}",
            "",
        ]
        if sample["evidence"]:
            lines += [code_block(str(sample["evidence"])), ""]
    return lines


def _markdown_resolution(resolution: JsonObject) -> list[str]:
    lines = [
        f"- resolution：{resolution['basis']}（{resolution['basis_label']}）",
        _field("evidence_provenance", resolution["evidence_provenance"]),
        _field("decided_at", resolution["decided_at"]),
        _field("decided_by_role", resolution["decided_by_role"]),
        _field("comparison_id", resolution["comparison_id"]),
    ]
    attestation = resolution["attestation"]
    if isinstance(attestation, dict):
        lines += [
            _field("performed_at", attestation["performed_at"]),
            _field("performed_by", attestation["performed_by"], untrusted=True),
            _field("procedure", attestation["procedure"], untrusted=True),
            _field("request_excerpt_sha256", attestation["request_excerpt_sha256"]),
            _field("response_excerpt_sha256", attestation["response_excerpt_sha256"]),
            _field("checks_version", attestation["checks_version"]),
        ]
    return lines


def _markdown_comparisons(data: JsonObject) -> list[str]:
    comparisons = data["comparisons"]
    comparisons = _list(comparisons)
    if not comparisons:
        return []
    lines = [f"## {wording.SECTION_TITLES['comparisons']}", "", f"- {wording.COMPARISON_NOTICE}"]
    for item in comparisons:
        item = _obj(item)
        counts = item["counts"]
        counts = _obj(counts)
        described = "、".join(f"{key} {value}" for key, value in counts.items())
        lines.append(
            f"- {item['id']}：{item['role']}，對照 {item['other_scan_id']}，"
            f"{item['comparability']}；{described}"
        )
    return [*lines, ""]
