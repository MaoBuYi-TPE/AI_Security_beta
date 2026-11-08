"""報告的投影與渲染：標示、遮罩（canary）、摘要、確定性、用語檢查與 8 MiB 截斷。"""

import json
from dataclasses import replace
from typing import Any
from uuid import UUID

import pytest
from markdown_it import MarkdownIt

from secscan.reports.domain import wording
from secscan.reports.domain.document import clean, summary
from secscan.reports.domain.model import (
    MAX_REPORT_BYTES,
    ReportFormat,
    ReportSnapshot,
    SourceRow,
    SpecSection,
)
from secscan.reports.domain.render import render
from tests.unit.reports.factory import FINDING, MANUAL, NOW, SCAN, finding, snapshot
from tests.unit.reports.test_encoding import MALICIOUS, assert_safe, flatten

PLATFORM_KEY = "secscan_0123456789abcdef_" + "a" * 64
CANARIES = (
    "Bearer canary-bearer-token",
    PLATFORM_KEY,
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5hcnkifQ.c2lnbmF0dXJl",
    "Authorization: Basic Y2FuYXJ5OnBhc3N3b3Jk",
)
_FORBIDDEN_FIELDS = (
    "storage_key",
    "key_hash",
    "idempotency_key",
    "request_sha256",
    "lease_owner",
    "actor_key_id",
    "created_by_key_id",
    "ciphertext",
    'request_excerpt"',
)


def render_both(item: ReportSnapshot) -> tuple[str, dict[str, Any]]:
    markdown = render(item, generated_at=NOW).content.decode()
    as_json = render(replace(item, format=ReportFormat.JSON), generated_at=NOW).content.decode()
    document: dict[str, Any] = json.loads(as_json)
    return markdown, document


def non_code_text(markdown: str) -> str:
    tokens = flatten(MarkdownIt("commonmark").enable("table").parse(markdown))
    return "\n".join(token.content for token in tokens if token.type == "text")


def test_labels_and_fixed_notices_are_explicit() -> None:
    resolved = finding(
        triage_state="confirmed", lifecycle_state="resolved", triage_version=2, resolution=MANUAL
    )
    review = finding(
        triage_state="confirmed",
        lifecycle_state="resolved",
        resolution=MANUAL,
        review_reasons=("mapping_changed_since_resolution",),
    )
    markdown, document = render_both(snapshot((finding(), resolved, review)))
    for notice in wording.NOTICES:
        assert notice in markdown
    assert wording.FIXTURE_NOTICE in markdown
    assert "partially_completed" in wording.INCOMPLETE_NOTICE.format(status=SCAN.status)
    assert wording.INCOMPLETE_NOTICE.format(status=SCAN.status) in markdown
    assert wording.TRIAGE_LABELS["unreviewed"] in markdown
    assert wording.BASIS_LABELS["manual_retest"] in markdown
    assert wording.REVIEW_LABEL in markdown
    findings = document["findings"]
    assert isinstance(findings, list)
    assert findings[1]["resolution"]["evidence_provenance"] == "operator_supplied"
    assert findings[1]["resolution"]["attestation"]["request_excerpt_sha256"] == "a" * 64
    assert document["summary"]["resolved_operator_supplied"] == 1
    assert document["summary"]["resolved_review_required"] == 1
    assert document["authorization"]["approved_at"] == NOW.isoformat()
    assert wording.FIELD_LABELS["approved_at"] in markdown
    assert document["scan"]["results_complete"] is False


def test_platform_text_makes_no_unverified_claims() -> None:
    for text in wording.all_platform_text():
        assert wording.claims_violations(text) == [], text
    assert wording.claims_violations("這個問題已修補") == ["已修補"]
    assert wording.claims_violations("the issue is fixed") == ["fixed"]
    assert wording.claims_violations("not_observed 不等於已修補") == []
    # 不可信的資料（finding 標題）帶誇大字詞也只在 code 中，不算平台的敘述。
    markdown, _ = render_both(snapshot((finding(title="Fixed and verified secure"),)))
    assert wording.claims_violations(non_code_text(markdown)) == []


@pytest.mark.parametrize("value", MALICIOUS)
def test_untrusted_values_are_encoded_in_every_field(value: str) -> None:
    hostile = finding(
        title=value,
        rule_group=value,
        route="/" + value,
        parameter_name=value,
        auth_role=value,
        samples=(replace(finding().samples[0], path="/" + value, evidence=value),),
    )
    item = snapshot(
        (hostile,),
        scan=replace(SCAN, target_name=value, target_origin=value),
        authorization=replace(snapshot().authorization, authorization_reference=value),
    )
    markdown, document = render_both(item)
    assert_safe(markdown)
    assert document["findings"]


def test_canary_secrets_never_reach_either_format() -> None:
    evidence = " ".join(CANARIES)
    item = snapshot(
        (
            finding(
                title=f"title {CANARIES[0]}",
                samples=(replace(finding().samples[0], evidence=evidence),),
                resolution=replace(MANUAL, performed_by=CANARIES[1], procedure=CANARIES[3]),
                lifecycle_state="resolved",
                triage_state="confirmed",
            ),
        ),
        authorization=replace(snapshot().authorization, authorization_reference=CANARIES[2]),
        scan=replace(SCAN, target_name=CANARIES[1]),
    )
    markdown, document = render_both(item)
    serialized = json.dumps(document, ensure_ascii=False)
    for canary in CANARIES:
        for part in (canary, canary.split(" ")[-1]):
            assert part not in markdown
            assert part not in serialized
    for field in _FORBIDDEN_FIELDS:
        assert field not in serialized


def test_rendering_is_deterministic_and_fields_are_whitelisted() -> None:
    item = snapshot((finding(), finding()))
    first, second = render(item, generated_at=NOW), render(item, generated_at=NOW)
    assert first == second
    _, document = render_both(item)
    assert list(document) == [
        "schema_version",
        "report_id",
        "format",
        "generated_at",
        "data_as_of",
        "notices",
        "scan",
        "authorization",
        "spec",
        "authentication",
        "engines",
        "coverage",
        "summary",
        "findings",
        "comparisons",
        "truncation",
    ]


def test_truncation_keeps_whole_findings_and_true_totals() -> None:
    items = tuple(finding(title=f"finding {index}") for index in range(40))
    full = render(snapshot(items), generated_at=NOW)
    limit = len(full.content) // 2
    for report_format in ReportFormat:
        cut = render(snapshot(items, report_format), generated_at=NOW, max_bytes=limit)
        assert cut.truncated
        assert 0 < cut.omitted_findings < 40
        assert len(cut.content) <= limit
        text = cut.content.decode()
        notice = wording.TRUNCATED_NOTICE.format(omitted=cut.omitted_findings)
        if report_format is ReportFormat.MARKDOWN:
            assert text.count(notice) >= 2
        else:
            document = json.loads(text)
            assert document["summary"]["findings_total"] == 40
            assert document["truncation"]["omitted_findings"] == cut.omitted_findings
            assert len(document["findings"]) == 40 - cut.omitted_findings
            assert notice in document["notices"]


def test_a_real_eight_mebibyte_limit_with_multibyte_text() -> None:
    evidence = "多位元組🙂" * 300
    items = tuple(
        finding(samples=tuple(replace(finding().samples[0], evidence=evidence) for _ in range(3)))
        for _ in range(1500)
    )
    for report_format in ReportFormat:
        rendered = render(snapshot(items, report_format), generated_at=NOW)
        assert len(rendered.content) <= MAX_REPORT_BYTES
        assert rendered.truncated
        rendered.content.decode("utf-8")


def test_summary_counts_every_finding_and_review_is_not_resolved() -> None:
    counted = summary(
        (
            finding(severity="high"),
            finding(severity="low", triage_state="false_positive"),
            finding(
                lifecycle_state="resolved",
                triage_state="confirmed",
                resolution=replace(MANUAL, provenance="platform_comparison"),
            ),
        )
    )
    assert counted["findings_total"] == 3
    assert counted["by_severity"] == {
        "critical": 0,
        "high": 3 - 1,
        "medium": 0,
        "low": 1,
        "info": 0,
    }
    assert counted["resolved_platform_comparison"] == 1
    assert counted["resolved_operator_supplied"] == 0


def test_lifecycle_counts_keep_review_required_out_of_resolved() -> None:
    resolved = finding(lifecycle_state="resolved", triage_state="confirmed", resolution=MANUAL)
    counted: dict[str, Any] = summary(
        (
            finding(),
            finding(lifecycle_state="reopened", triage_state="confirmed"),
            resolved,
            replace(
                resolved, id=finding().id, review_reasons=("mapping_changed_since_resolution",)
            ),
        )
    )
    assert counted["by_lifecycle"] == {
        "open": 1,
        "resolved": 1,
        "reopened": 1,
        "resolved_review_required": 1,
    }
    assert sum(counted["by_lifecycle"].values()) == counted["findings_total"]
    assert counted["resolved_review_required"] == 1
    # 需要人工確認的也不算進依證據性質的計數：兩個計數加起來就是 resolved 那一桶。
    assert counted["resolved_operator_supplied"] == 1
    assert (
        counted["resolved_operator_supplied"] + counted["resolved_platform_comparison"]
        == counted["by_lifecycle"]["resolved"]
    )


def test_omitted_comparisons_are_disclosed_in_both_formats() -> None:
    markdown, document = render_both(snapshot(comparisons_omitted=4))
    assert document["truncation"]["comparisons_omitted"] == 4
    assert wording.COMPARISONS_OMITTED_NOTICE.format(omitted=4) in markdown
    plain_markdown, plain = render_both(snapshot())
    assert plain["truncation"]["comparisons_omitted"] == 0
    assert "份較舊的未列出" not in plain_markdown


def test_secrets_are_masked_before_the_value_is_shortened() -> None:
    """先截斷會切開最後一個 JWT，半截不再符合遮罩的樣式；遮罩之後才截斷就不會（安全審查 L7）。"""
    jwt = CANARIES[2]
    # 最後一個 JWT 從第 3970 個字元開始：舊作法在 4000 處切開，只剩 header 與半個 payload。
    start = 3970
    repeats = start // (len(jwt) + 1)
    filler = start - repeats * (len(jwt) + 1)
    value = (jwt + " ") * repeats + "x" * (filler - 1) + " " + jwt
    assert value.rindex(jwt) == start
    cleaned = clean(value)
    assert cleaned is not None
    assert "eyJ" not in cleaned


def test_a_spec_section_appears_in_both_formats() -> None:
    spec = SpecSection(UUID(int=9), 3, "3.1.0\n# 標題注入", 12)
    markdown, document = render_both(snapshot(spec=spec))
    assert document["spec"] == {
        "id": str(UUID(int=9)),
        "version": 3,
        "openapi_version": "3.1.0\n# 標題注入",
        "operation_count": 12,
    }
    assert f"## {wording.SECTION_TITLES['spec']}" in markdown
    assert "- operation_count：12" in markdown
    assert_safe(markdown)
    assert "\n# 標題注入" not in markdown
    plain, _ = render_both(snapshot())
    assert wording.SECTION_TITLES["spec"] not in plain


def test_a_rescan_resolution_has_no_attestation_and_multiple_sources_are_noted() -> None:
    rescan = replace(
        MANUAL,
        basis="rescan_not_observed",
        provenance="platform_comparison",
        performed_at=None,
        performed_by=None,
        procedure=None,
        request_excerpt_sha256=None,
        request_excerpt_bytes=None,
        response_excerpt_sha256=None,
        response_excerpt_bytes=None,
        checks_version=None,
        platform_checks=(),
    )
    sources = (*FINDING.sources, SourceRow("nuclei", "cors", "info", "info", "", 1))
    item = finding(
        lifecycle_state="resolved", triage_state="confirmed", resolution=rescan, sources=sources
    )
    markdown, document = render_both(snapshot((item,)))
    [projected] = document["findings"]
    assert projected["resolution"]["attestation"] is None
    assert projected["resolution"]["evidence_provenance"] == "platform_comparison"
    assert projected["multiple_sources_note"]
    assert "performed_at" not in markdown
    assert projected["multiple_sources_note"] in markdown
