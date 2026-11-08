"""finding 與 ground truth、人工裁定的對應（純函式）。

一個 finding 同時對上兩個案例：ground truth 有歧義，停止評估（不猜它屬於哪一個）。
"""

from benchmarks.ground_truth import Adjudication, Adjudications, Case, GroundTruth
from benchmarks.models import Signature


class AmbiguousMatchError(ValueError):
    """一個 finding 對上多個案例；訊息列出案例的 id（ground truth 的內容，不是掃描輸出）。"""


def match_case(truth: GroundTruth, signature: Signature) -> Case | None:
    matched = [
        case for case in truth.cases if any(matcher.matches(signature) for matcher in case.matchers)
    ]
    if len(matched) > 1:
        ids = "、".join(case.id for case in matched)
        raise AmbiguousMatchError(f"一個 finding 同時對上多個案例（{ids}）：ground truth 有歧義")
    return matched[0] if matched else None


def adjudication_for(
    adjudications: Adjudications | None, *, target: str, variant: str, signature: Signature
) -> Adjudication | None:
    if adjudications is None:
        return None
    for item in adjudications.items:
        if (
            item.target.value == target
            and item.variant.value == variant
            and item.finding.signature() == signature
        ):
            return item
    return None
