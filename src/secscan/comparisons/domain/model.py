"""封存的比較結果；分類不改動 finding 的人工生命週期。"""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from secscan.comparisons.domain.comparability import Comparability

ALGORITHM_VERSION = 1
COMPARISON_NOTICE = "not_observed 不等於已修補；缺少覆蓋證據時不推論安全。"


@dataclass(frozen=True, slots=True)
class ComparisonCounts:
    new: int = 0
    persistent: int = 0
    not_observed: int = 0
    inconclusive: int = 0
    not_comparable: int = 0


@dataclass(frozen=True, slots=True)
class ComparisonSnapshot:
    id: UUID
    project_id: UUID
    target_id: UUID
    baseline_scan_id: UUID
    current_scan_id: UUID
    algorithm_version: int
    comparability: Comparability
    reasons: tuple[str, ...]
    manual_review_required: bool
    counts: ComparisonCounts
    created_at: datetime
