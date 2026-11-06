"""比較 API 只接受 scan ID，不接受自行宣稱的完成性、規則或分類。"""

from datetime import datetime
from typing import Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from secscan.comparisons.domain.classification import Classification, ComparisonFacts
from secscan.comparisons.domain.comparability import Comparability
from secscan.comparisons.domain.facts import FindingComparison
from secscan.comparisons.domain.model import COMPARISON_NOTICE, ComparisonCounts, ComparisonSnapshot


class ComparisonCreate(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    baseline_scan_id: UUID
    current_scan_id: UUID


class ComparisonOut(BaseModel):
    model_config = ConfigDict(frozen=True, from_attributes=True)

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
    notice: str = COMPARISON_NOTICE

    @classmethod
    def of(cls, snapshot: ComparisonSnapshot) -> Self:
        return cls.model_validate(snapshot)


class ComparisonFindingOut(BaseModel):
    model_config = ConfigDict(frozen=True, from_attributes=True)

    finding_id: UUID
    classification: Classification
    reasons: tuple[str, ...]
    manual_review_required: bool
    evidence: ComparisonFacts

    @classmethod
    def of(cls, finding: FindingComparison) -> Self:
        return cls.model_validate(finding)
