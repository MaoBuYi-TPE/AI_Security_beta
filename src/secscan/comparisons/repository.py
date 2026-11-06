"""比較快照的保存與查詢：呼叫端交易內建立、寫明細、封存，重複建立讀原快照。"""

import json
from collections.abc import Sequence
from uuid import UUID, uuid4

from pydantic import TypeAdapter
from sqlalchemy import func, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from secscan.comparisons.domain.classification import Classification, ComparisonFacts
from secscan.comparisons.domain.comparability import Comparability
from secscan.comparisons.domain.facts import Evaluation, FindingComparison, ScanEvidence
from secscan.comparisons.domain.model import ALGORITHM_VERSION, ComparisonCounts, ComparisonSnapshot
from secscan.comparisons.models import ScanComparisonFindingModel, ScanComparisonModel
from secscan.comparisons.observations import ComparisonInputLimitError
from secscan.core.json_types import JsonObject
from secscan.core.pagination import Page, PageRequest

_EVIDENCE = TypeAdapter(ComparisonFacts)
MAX_EVIDENCE_BYTES = 16_384
BATCH_SIZE = 250


class ComparisonRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, comparison_id: UUID) -> ComparisonSnapshot | None:
        row = self._session.scalar(
            select(ScanComparisonModel).where(
                ScanComparisonModel.id == comparison_id,
                ScanComparisonModel.sealed.is_(True),
            )
        )
        return self._snapshot(row) if row else None

    def for_pair(self, baseline: UUID, current: UUID) -> ComparisonSnapshot | None:
        row = self._session.scalar(
            select(ScanComparisonModel).where(
                ScanComparisonModel.baseline_scan_id == baseline,
                ScanComparisonModel.current_scan_id == current,
                ScanComparisonModel.algorithm_version == ALGORITHM_VERSION,
                ScanComparisonModel.sealed.is_(True),
            )
        )
        return self._snapshot(row) if row else None

    def save(
        self,
        baseline: ScanEvidence,
        current: ScanEvidence,
        evaluation: Evaluation,
    ) -> tuple[ComparisonSnapshot, bool]:
        comparison_id = self._session.scalar(
            pg_insert(ScanComparisonModel)
            .values(
                id=uuid4(),
                project_id=baseline.scan.project_id,
                target_id=baseline.scan.target_id,
                baseline_scan_id=baseline.scan.scan_id,
                current_scan_id=current.scan.scan_id,
                algorithm_version=ALGORITHM_VERSION,
                comparability=evaluation.scans.comparability.value,
                reasons=list(evaluation.scans.reasons),
                manual_review_required=(
                    evaluation.scans.manual_review_required
                    or any(item.manual_review_required for item in evaluation.findings)
                ),
            )
            .on_conflict_do_nothing(
                index_elements=[
                    "baseline_scan_id",
                    "current_scan_id",
                    "algorithm_version",
                ]
            )
            .returning(ScanComparisonModel.id)
        )
        if comparison_id is None:
            existing = self.for_pair(baseline.scan.scan_id, current.scan.scan_id)
            if existing is None:
                raise ValueError("衝突的比較快照不存在或未封存")
            return existing, False
        self._insert_findings(comparison_id, baseline.scan.target_id, evaluation.findings)
        self._session.execute(
            update(ScanComparisonModel)
            .where(
                ScanComparisonModel.id == comparison_id,
            )
            .values(sealed=True)
        )
        result = self.get(comparison_id)
        if result is None:
            raise ValueError("比較快照未完成封存")
        return result, True

    def findings(
        self,
        comparison_id: UUID,
        classification: Classification | None,
        page: PageRequest,
    ) -> Page[FindingComparison]:
        conditions = [ScanComparisonFindingModel.comparison_id == comparison_id]
        if classification is not None:
            conditions.append(ScanComparisonFindingModel.classification == classification.value)
        total = self._session.scalar(
            select(func.count()).select_from(ScanComparisonFindingModel).where(*conditions)
        )
        rows = self._session.scalars(
            select(ScanComparisonFindingModel)
            .where(*conditions)
            .order_by(ScanComparisonFindingModel.finding_id)
            .offset(page.offset)
            .limit(page.limit)
        )
        return Page(
            items=tuple(
                FindingComparison(
                    row.finding_id,
                    Classification(row.classification),
                    tuple(row.reasons),
                    row.manual_review_required,
                    _EVIDENCE.validate_python(row.evidence),
                )
                for row in rows
            ),
            total=total or 0,
            request=page,
        )

    def _insert_findings(
        self,
        comparison_id: UUID,
        target_id: UUID,
        findings: Sequence[FindingComparison],
    ) -> None:
        for offset in range(0, len(findings), BATCH_SIZE):
            self._session.execute(
                insert(ScanComparisonFindingModel),
                [
                    {
                        "comparison_id": comparison_id,
                        "target_id": target_id,
                        "finding_id": finding.finding_id,
                        "classification": finding.classification,
                        "reasons": list(finding.reasons),
                        "manual_review_required": finding.manual_review_required,
                        "evidence": _evidence(finding.evidence),
                    }
                    for finding in findings[offset : offset + BATCH_SIZE]
                ],
            )

    def _snapshot(self, row: ScanComparisonModel) -> ComparisonSnapshot:
        counts = dict(
            self._session.execute(
                select(
                    ScanComparisonFindingModel.classification,
                    func.count(),
                )
                .where(ScanComparisonFindingModel.comparison_id == row.id)
                .group_by(ScanComparisonFindingModel.classification)
            ).all()
        )
        return ComparisonSnapshot(
            id=row.id,
            project_id=row.project_id,
            target_id=row.target_id,
            baseline_scan_id=row.baseline_scan_id,
            current_scan_id=row.current_scan_id,
            algorithm_version=row.algorithm_version,
            comparability=Comparability(row.comparability),
            reasons=tuple(row.reasons),
            manual_review_required=row.manual_review_required,
            counts=ComparisonCounts(**counts),
            created_at=row.created_at,
        )


def _evidence(facts: ComparisonFacts) -> JsonObject:
    document = _EVIDENCE.dump_python(facts, mode="json")
    if not isinstance(document, dict):
        raise ValueError("比較證據必須是物件")
    if len(json.dumps(document, ensure_ascii=True).encode("ascii")) > MAX_EVIDENCE_BYTES:
        raise ComparisonInputLimitError("比較證據超過大小上限")
    return document
