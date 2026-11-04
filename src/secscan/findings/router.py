"""finding 的端點（docs/API_CONTRACT.md §17.9）。只做輸入驗證與呼叫 service。"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query

from secscan.api_keys.dependencies import CurrentPrincipal
from secscan.core.api import PageQuery, ok_page
from secscan.core.db import DbSession
from secscan.core.envelope import Envelope
from secscan.findings.domain.model import FindingFilters, TriageState
from secscan.findings.domain.normalization import Severity
from secscan.findings.domain.taxonomy import FindingCategory, FindingKind
from secscan.findings.schemas import FindingOut
from secscan.findings.service import FindingService
from secscan.scans.domain.catalog import Engine
from secscan.targets.dependencies import CurrentLab

router = APIRouter(tags=["findings"])


@router.get("/scans/{scan_id}/findings")
def list_scan_findings(
    scan_id: UUID,
    principal: CurrentPrincipal,
    session: DbSession,
    lab: CurrentLab,
    page: PageQuery,
    kind: Annotated[FindingKind | None, Query(description="只列這個 kind")] = None,
    severity: Annotated[
        Severity | None, Query(description="只列 finding 的正規化等級（所有掃描的最高值）是這個的")
    ] = None,
    engine: Annotated[
        Engine | None, Query(description="只列這個引擎在這個 scan 中有來源的 finding")
    ] = None,
    triage_state: Annotated[TriageState | None, Query(description="只列這個 triage 狀態")] = None,
    category: Annotated[
        FindingCategory | None,
        Query(description="只列這個分類（unclassified 是未審查的 fallback）"),
    ] = None,
    needs_review: Annotated[
        bool | None, Query(description="只列需要（或不需要）人工確認對應的 finding")
    ] = None,
) -> Envelope[list[FindingOut]]:
    """這個 scan 的觀察連結到的 finding（等級由高到低）；其他 project 的 scan 回 404。

    sources 只有這個 scan 中的來源。多個工具同時命中只代表有多個來源，不提高等級，也不是人工確認。
    """
    filters = FindingFilters(
        kind=kind,
        severity=severity,
        engine=engine,
        triage_state=triage_state,
        category=category,
        needs_review=needs_review,
    )
    findings = FindingService(session, lab=lab).for_scan(principal, scan_id, filters, page)
    return ok_page(findings, FindingOut.of)
