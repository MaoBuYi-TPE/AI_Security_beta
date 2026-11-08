"""Markdown 報告（SEC-17；docs/DECISIONS.md §28.5）。純函式。

平台文字在 code 以外；不可信的值一律經 code_span（單行）或最上層的 code_block（多行）。輸入是
document.py 投影出的白名單文件，不直接讀快照。
"""

from collections.abc import Sequence
from datetime import datetime

from secscan.core.json_types import JsonObject, JsonValue
from secscan.reports.domain import wording
from secscan.reports.domain.document import document
from secscan.reports.domain.encoding import code_block, code_span
from secscan.reports.domain.model import ReportSnapshot


def markdown(snapshot: ReportSnapshot, generated_at: datetime, count: int) -> str:
    """Markdown：平台文字在 code 以外，不可信的值一律經 code_span／code_block。"""
    data = document(snapshot, generated_at, count)
    return assemble(data, finding_fragments(_list(data["findings"])))


def finding_fragments(findings: Sequence[JsonValue]) -> tuple[str, ...]:
    """每個 finding 的 Markdown 片段（以換行結尾）；第 i 個的編號是 i + 1，不隨截斷改變。"""
    return tuple(
        "\n".join(_markdown_finding(index, _obj(finding))) + "\n"
        for index, finding in enumerate(findings, start=1)
    )


def assemble(data: JsonObject, fragments: Sequence[str]) -> str:
    """固定部分加上前 len(fragments) 個 finding 的片段（和逐行 join 的結果完全相同）。"""
    truncation = _obj(data["truncation"])
    head: list[str] = [f"# {wording.SECTION_TITLES['report']}", ""]
    if truncation["notice"]:
        head += [f"> {truncation['notice']}", ""]
    head += [f"## {wording.SECTION_TITLES['notices']}", ""]
    head += [f"- {notice}" for notice in _strings(data["notices"])]
    head += ["", *_markdown_scan(data), *_markdown_summary(data)]
    head += [f"## {wording.SECTION_TITLES['findings']}", ""]
    tail = _markdown_comparisons(data)
    if truncation["notice"]:
        tail += [f"## {wording.SECTION_TITLES['truncation']}", "", f"> {truncation['notice']}", ""]
    text = "\n".join(head) + "\n" + "".join(fragments)
    return text + "\n".join(tail) + "\n" if tail else text


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


def _inline(value: JsonValue) -> str:
    """句中的不可信值（工具的規則、原始等級與信心）：一律 code span；沒有值時是平台的標記。"""
    return "（無）" if value is None or value == "" else code_span(str(value))


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
        *_markdown_spec(data["spec"]),
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


def _markdown_spec(spec: JsonValue) -> list[str]:
    """API 規格（沒有規格的 scan 不列這一節）；openapi_version 來自上傳的文件，放在 code 中。"""
    if spec is None:
        return []
    spec = _obj(spec)
    return [
        f"## {wording.SECTION_TITLES['spec']}",
        "",
        _field("spec_id", spec["id"]),
        _field("spec_version", spec["version"]),
        _field("openapi_version", spec["openapi_version"], untrusted=True),
        _field("operation_count", spec["operation_count"]),
        "",
    ]


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
        f"### {index}. {finding['severity']}（正規化）/ {finding['kind']} / {finding['category']}",
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
            f"- source：{source['engine']}；規則 {_inline(source['rule'])}；"
            f"工具的原始嚴重度 {_inline(source['severity_label'])}；"
            f"平台正規化 {source['normalized_severity']}；"
            f"工具的信心 {_inline(source['confidence_label'])}；"
            f"觀察 {source['observations']} 次"
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
    truncation = _obj(data["truncation"])
    if truncation["comparisons_omitted"]:
        lines.append(
            wording.COMPARISONS_OMITTED_NOTICE.format(omitted=truncation["comparisons_omitted"])
        )
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
