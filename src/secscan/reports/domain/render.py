"""報告的渲染與大小上限（docs/DECISIONS.md §28.5、§28.14）。純函式。

依優先順序（快照中的順序）以整個 finding 為單位加入，超過上限就省略之後的 finding，兩種格式的開頭
與結尾都有截斷說明；最後一定以實際的位元組數確認。

成本與 finding 的大小分布無關（安全審查 M1）：每個 finding 只投影（遮罩、清理）一次，Markdown 的
片段也只渲染一次；以每個 finding 的位元組數做前綴和，一次算出截斷點。固定部分以「省略全部」時的
大小估計（截斷說明的位數最多），所以估計只會偏大：選出的數量一定放得下，最多再試多放一個（固定
部分的差距只有幾十個位元組，小於任何一個 finding）。
"""

from bisect import bisect_right
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from itertools import accumulate

from secscan.core.json_types import JsonObject
from secscan.reports.domain.document import document, project_findings
from secscan.reports.domain.encoding import to_json
from secscan.reports.domain.markdown import assemble, finding_fragments
from secscan.reports.domain.model import MAX_REPORT_BYTES, ReportFormat, ReportSnapshot


@dataclass(frozen=True, slots=True)
class Rendered:
    content: bytes
    truncated: bool
    omitted_findings: int


class ReportTooLargeError(ValueError):
    """連一個 finding 都放不下時，固定部分本身就超過上限（不應發生）。"""


@dataclass(frozen=True, slots=True)
class _Layout:
    """compose(k)：前 k 個 finding 的完整內容；costs[i]：第 i 個 finding 最多增加的位元組數。"""

    compose: Callable[[int], bytes]
    costs: tuple[int, ...]


def render(
    snapshot: ReportSnapshot, *, generated_at: datetime, max_bytes: int = MAX_REPORT_BYTES
) -> Rendered:
    projected = project_findings(snapshot)
    layout = _layout(snapshot, generated_at, projected)
    total = len(projected)
    content = layout.compose(total)
    if len(content) <= max_bytes:
        return Rendered(content, truncated=False, omitted_findings=0)
    fixed = len(layout.compose(0))
    if fixed > max_bytes:
        raise ReportTooLargeError("報告的固定部分超過大小上限")
    prefix = (0, *accumulate(layout.costs))
    count = min(bisect_right(prefix, max_bytes - fixed) - 1, total - 1)
    content = layout.compose(count)
    # 估計只會偏大，超過不應發生；仍以實際大小二分搜尋，絕不送出超過上限的內容。
    if len(content) > max_bytes:
        count, content = _search(layout, count, max_bytes)
    elif count + 1 < total:
        larger = layout.compose(count + 1)
        if len(larger) <= max_bytes:
            count, content = count + 1, larger
    return Rendered(content, truncated=True, omitted_findings=total - count)


def _search(layout: _Layout, upper: int, max_bytes: int) -> tuple[int, bytes]:
    """在 [0, upper) 中找放得下的最大數量（最多 log2(upper) + 1 次組裝；0 一定放得下）。"""
    low, high = 0, upper
    while high - low > 1:
        middle = (low + high) // 2
        if len(layout.compose(middle)) <= max_bytes:
            low = middle
        else:
            high = middle
    return low, layout.compose(low)


def _layout(
    snapshot: ReportSnapshot, generated_at: datetime, projected: Sequence[JsonObject]
) -> _Layout:
    def data(count: int) -> JsonObject:
        return document(snapshot, generated_at, count, projected=projected)

    if snapshot.format is ReportFormat.JSON:
        # JSON 陣列中每個元素之後最多一個逗號。
        costs = tuple(len(to_json(item).encode("utf-8")) + 1 for item in projected)
        return _Layout(lambda count: to_json(data(count)).encode("utf-8"), costs)
    fragments = finding_fragments(projected)
    costs = tuple(len(fragment.encode("utf-8")) for fragment in fragments)
    return _Layout(lambda count: assemble(data(count), fragments[:count]).encode("utf-8"), costs)
