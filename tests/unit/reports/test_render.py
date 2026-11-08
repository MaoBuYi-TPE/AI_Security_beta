"""截斷的成本與大小分布無關（安全審查 M1；docs/DECISIONS.md §28.14）。

- 每個 finding 只投影一次、Markdown 片段只渲染一次，不因大小分布偏斜而重複渲染整份報告。
- 截斷點和逐一嘗試的結果相同（放得下的最大數量）。
- 估計失準時以實際大小二分搜尋，絕不送出超過上限的內容。
"""

from dataclasses import replace
from typing import Any

import pytest

from secscan.reports.domain import document as document_module
from secscan.reports.domain import markdown as markdown_module
from secscan.reports.domain import render as render_module
from secscan.reports.domain.document import document
from secscan.reports.domain.encoding import to_json
from secscan.reports.domain.markdown import markdown
from secscan.reports.domain.model import FindingSection, ReportFormat, ReportSnapshot
from secscan.reports.domain.render import ReportTooLargeError, render
from tests.unit.reports.factory import NOW, finding, snapshot


def skewed() -> tuple[FindingSection, ...]:
    """前面少數幾個很大（長 evidence、滿是 backtick 的 path），後面大量很小。"""
    base = finding()
    big_sample = replace(base.samples[0], path="/" + "`" * 900, evidence="證據`" * 240)
    big = tuple(
        finding(severity="high", title="大" * 900, samples=(big_sample,) * 3) for _ in range(6)
    )
    small = tuple(finding(severity="info", title=f"s{index}", samples=()) for index in range(60))
    return big + small


def brute_force(item: ReportSnapshot, max_bytes: int) -> int:
    """逐一嘗試：放得下的最大 finding 數量。"""
    for count in range(len(item.findings), -1, -1):
        if item.format is ReportFormat.JSON:
            content = to_json(document(item, NOW, count))
        else:
            content = markdown(item, NOW, count)
        if len(content.encode("utf-8")) <= max_bytes:
            return count
    raise AssertionError("連固定部分都放不下")


@pytest.mark.parametrize("report_format", list(ReportFormat))
def test_skewed_sizes_cut_at_the_brute_force_count(report_format: ReportFormat) -> None:
    item = snapshot(skewed(), report_format)
    full = len(render(item, generated_at=NOW).content)
    for ratio in (0.3, 0.55, 0.8, 0.97):
        limit = int(full * ratio)
        cut = render(item, generated_at=NOW, max_bytes=limit)
        assert len(cut.content) <= limit
        assert len(item.findings) - cut.omitted_findings == brute_force(item, limit)


@pytest.mark.parametrize("report_format", list(ReportFormat))
def test_each_finding_is_projected_and_rendered_once(
    report_format: ReportFormat, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = {"project": 0, "fragment": 0}
    project, fragment = document_module._finding, markdown_module._markdown_finding

    def counted_project(item: FindingSection) -> Any:
        calls["project"] += 1
        return project(item)

    def counted_fragment(index: int, value: Any) -> Any:
        calls["fragment"] += 1
        return fragment(index, value)

    monkeypatch.setattr(document_module, "_finding", counted_project)
    monkeypatch.setattr(markdown_module, "_markdown_finding", counted_fragment)
    item = snapshot(skewed(), report_format)
    full = len(render(item, generated_at=NOW).content)
    calls.update(project=0, fragment=0)

    cut = render(item, generated_at=NOW, max_bytes=full // 3)

    assert cut.truncated
    assert calls["project"] == len(item.findings)
    expected = len(item.findings) if report_format is ReportFormat.MARKDOWN else 0
    assert calls["fragment"] == expected


@pytest.mark.parametrize("report_format", list(ReportFormat))
def test_untruncated_output_is_the_plain_rendering(report_format: ReportFormat) -> None:
    item = snapshot(skewed(), report_format)
    count = len(item.findings)
    expected = (
        to_json(document(item, NOW, count))
        if report_format is ReportFormat.JSON
        else markdown(item, NOW, count)
    )
    assert render(item, generated_at=NOW).content == expected.encode("utf-8")


def test_an_underestimate_falls_back_to_searching_actual_sizes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 每個 finding 實際增加 50 bytes，估計卻只有 10：估計會選太多，必須以實際大小找回 4 個。
    layout = render_module._Layout(lambda count: b"x" * (100 + 50 * count), (10,) * 20)
    monkeypatch.setattr(render_module, "_layout", lambda *_: layout)
    item = snapshot(tuple(finding() for _ in range(20)))

    cut = render(item, generated_at=NOW, max_bytes=320)

    assert (cut.truncated, cut.omitted_findings, len(cut.content)) == (True, 16, 300)


def test_a_fixed_part_over_the_limit_is_an_error() -> None:
    with pytest.raises(ReportTooLargeError):
        render(snapshot(skewed()), generated_at=NOW, max_bytes=100)


def test_one_more_finding_is_added_when_the_estimate_leaves_room(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 估計（每個 60）比實際（每個 50）大：估計選 3 個，實際還放得下第 4 個。
    layout = render_module._Layout(lambda count: b"x" * (100 + 50 * count), (60,) * 6)
    monkeypatch.setattr(render_module, "_layout", lambda *_: layout)
    cut = render(snapshot(tuple(finding() for _ in range(6))), generated_at=NOW, max_bytes=320)
    assert (cut.omitted_findings, len(cut.content)) == (2, 300)


def test_all_but_the_last_finding_fit(monkeypatch: pytest.MonkeyPatch) -> None:
    layout = render_module._Layout(lambda count: b"x" * (100 + 50 * count), (50,) * 4)
    monkeypatch.setattr(render_module, "_layout", lambda *_: layout)
    cut = render(snapshot(tuple(finding() for _ in range(4))), generated_at=NOW, max_bytes=290)
    assert (cut.truncated, cut.omitted_findings, len(cut.content)) == (True, 1, 250)


def test_malformed_documents_are_rejected_by_the_markdown_renderer() -> None:
    with pytest.raises(TypeError):
        markdown_module.assemble({"truncation": []}, ())
    with pytest.raises(TypeError):
        markdown_module.finding_fragments(["not an object"])
    with pytest.raises(TypeError):
        markdown_module._list({"not": "a list"})
