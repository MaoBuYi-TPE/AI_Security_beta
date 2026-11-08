"""報告的渲染與大小上限（docs/DECISIONS.md §28.5）。純函式。

依優先順序（快照中的順序）以整個 finding 為單位加入，超過上限就省略之後的 finding，兩種格式的開頭
與結尾都有截斷說明；最後再確認實際的位元組數。
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from secscan.reports.domain.document import document
from secscan.reports.domain.encoding import to_json
from secscan.reports.domain.markdown import markdown
from secscan.reports.domain.model import MAX_REPORT_BYTES, ReportFormat, ReportSnapshot


@dataclass(frozen=True, slots=True)
class Rendered:
    content: bytes
    truncated: bool
    omitted_findings: int


class ReportTooLargeError(ValueError):
    """連一個 finding 都放不下時，固定部分本身就超過上限（不應發生）。"""


def render(
    snapshot: ReportSnapshot, *, generated_at: datetime, max_bytes: int = MAX_REPORT_BYTES
) -> Rendered:
    renderer = _json if snapshot.format is ReportFormat.JSON else markdown
    findings = snapshot.findings
    count = len(findings)
    while count >= 0:
        content = renderer(snapshot, generated_at, count).encode("utf-8")
        if len(content) <= max_bytes:
            return Rendered(content, count < len(findings), len(findings) - count)
        count = _shrink(renderer, snapshot, generated_at, count, max_bytes, len(content))
    raise ReportTooLargeError("報告的固定部分超過大小上限")


def _shrink(
    renderer: Callable[[ReportSnapshot, datetime, int], str],
    snapshot: ReportSnapshot,
    generated_at: datetime,
    count: int,
    max_bytes: int,
    size: int,
) -> int:
    """依平均每個 finding 的大小估計還要省略多少個；至少少一個，保證結束。"""
    if count == 0:
        return -1
    fixed = len(renderer(snapshot, generated_at, 0).encode("utf-8"))
    average = max(1, (size - fixed) // count)
    excess = size - max_bytes
    return max(0, min(count - 1, count - (excess // average) - 1))


def _json(snapshot: ReportSnapshot, generated_at: datetime, count: int) -> str:
    return to_json(document(snapshot, generated_at, count))
