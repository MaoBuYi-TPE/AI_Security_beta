"""比較先授權兩側 scan，再驗證先後與終止；建立結果不寫入 finding 生命週期。"""

from collections.abc import Mapping
from http import HTTPStatus
from uuid import UUID

from sqlalchemy.orm import Session

from secscan.api_keys.access import authorize
from secscan.api_keys.domain import Permission, Principal
from secscan.audit.service import AuditTrail
from secscan.comparisons.domain.classification import Classification
from secscan.comparisons.domain.comparability import (
    ComparisonError,
    ComparisonErrorCode,
    compare_scans,
)
from secscan.comparisons.domain.evaluation import evaluate
from secscan.comparisons.domain.facts import FindingComparison, ScanEvidence
from secscan.comparisons.domain.model import ComparisonSnapshot
from secscan.comparisons.domain.reidentification import relations
from secscan.comparisons.inputs import ComparisonInputs
from secscan.comparisons.observations import ComparisonInputLimitError
from secscan.comparisons.repository import ComparisonRepository
from secscan.core.errors import AppError, ErrorCode, not_found_error
from secscan.core.pagination import Page, PageRequest
from secscan.findings.domain.taxonomy import load_taxonomy, mapping_identity


class ComparisonService:
    def __init__(self, session: Session) -> None:
        self._inputs = ComparisonInputs(session)
        self._records = ComparisonRepository(session)
        self._audit = AuditTrail(session)

    def create(
        self,
        principal: Principal,
        baseline_id: UUID,
        current_id: UUID,
        *,
        request_id: str | None,
    ) -> tuple[ComparisonSnapshot, bool]:
        self._authorize_pair(principal, baseline_id, current_id)
        existing = self._records.for_pair(baseline_id, current_id)
        if existing is not None:
            return existing, False
        baseline, current = self._inputs.scan(baseline_id), self._inputs.scan(current_id)
        if baseline is None or current is None:
            raise not_found_error()
        try:
            # 先驗證 pair 再讀取大量 finding，未終止的 scan 不會產生快照。
            compare_scans(baseline.scan, current.scan)
            findings = self._inputs.findings(baseline_id, current_id)
            result = evaluate(baseline, current, findings, related=_relations(baseline, current))
            snapshot, created = self._records.save(baseline, current, result)
        except ComparisonError as exc:
            raise _invalid_pair(exc) from None
        except ComparisonInputLimitError:
            raise AppError(
                status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
                code=ErrorCode.QUOTA_EXCEEDED,
                message="比較資料超過處理上限；未建立部分快照。",
            ) from None
        if created:
            self._audit.record(
                action="scan_comparison.create",
                object_type="scan_comparison",
                object_id=snapshot.id,
                actor_key_id=principal.key_id,
                project_id=snapshot.project_id,
                request_id=request_id,
                changes={
                    "baseline_scan_id": str(baseline_id),
                    "current_scan_id": str(current_id),
                    "algorithm_version": snapshot.algorithm_version,
                },
            )
        return snapshot, created

    def get(self, principal: Principal, comparison_id: UUID) -> ComparisonSnapshot:
        result = self._records.get(comparison_id)
        if result is None:
            raise not_found_error()
        authorize(principal, Permission.PROJECT_READ, result.project_id)
        return result

    def findings(
        self,
        principal: Principal,
        comparison_id: UUID,
        classification: Classification | None,
        page: PageRequest,
    ) -> Page[FindingComparison]:
        self.get(principal, comparison_id)
        return self._records.findings(comparison_id, classification, page)

    def _authorize_pair(self, principal: Principal, baseline: UUID, current: UUID) -> None:
        projects = (self._inputs.project_id(baseline), self._inputs.project_id(current))
        for project in projects:
            if project is None:
                raise not_found_error()
            authorize(principal, Permission.PROJECT_READ, project)
        for project in projects:
            authorize(principal, Permission.PROJECT_WRITE, project)


def _invalid_pair(error: ComparisonError) -> AppError:
    if error.code is ComparisonErrorCode.NOT_TERMINAL:
        return AppError(
            status_code=HTTPStatus.CONFLICT,
            code=ErrorCode.SCAN_NOT_TERMINAL,
            message="兩次掃描都必須已結束，才能建立比較快照。",
        )
    if error.code is ComparisonErrorCode.TARGET_MISMATCH:
        return AppError(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            code=ErrorCode.TARGET_MISMATCH,
            message="只能比較相同專案及 target 的掃描。",
        )
    return AppError(
        status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
        code=ErrorCode.INVALID_REQUEST,
        message="baseline 必須是不同且較早建立的掃描。",
    )


def _relations(baseline: ScanEvidence, current: ScanEvidence) -> Mapping[str, frozenset[str]]:
    known = mapping_identity()
    if all(
        (item.scan.mapping_version, item.scan.taxonomy_sha256) == known
        for item in (baseline, current)
    ):
        return relations(load_taxonomy())
    # 沒有保存舊版分類表時，不拿目前的 related／佐證設定推論舊 scan 的重新識別。
    return {}
