"""finding 的端點（docs/API_CONTRACT.md §17.9、§17.10）。只做輸入驗證與呼叫 service。"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query

from secscan.api_keys.dependencies import CurrentPrincipal
from secscan.core.api import PageQuery, ok_page, ok_snapshot_page
from secscan.core.db import DbSession
from secscan.core.envelope import Envelope, SnapshotEnvelope, ok
from secscan.findings.domain.model import FindingFilters, TriageState
from secscan.findings.domain.normalization import Severity
from secscan.findings.domain.taxonomy import FindingCategory, FindingKind
from secscan.findings.provenance_schemas import (
    FindingDetailOut,
    ScanAppearanceOut,
    TracedObservationOut,
)
from secscan.findings.schemas import FindingOut
from secscan.findings.service import FindingService
from secscan.scans.domain.catalog import Engine
from secscan.targets.dependencies import CurrentLab

router = APIRouter(tags=["findings"])

# 快照：finding 的連結數（bigint）。省略時是目前的連結數；翻頁時帶回第一頁的值。
AsOf = Annotated[
    int | None,
    Query(
        ge=1,
        le=2**63 - 1,
        description="快照（明細或第一頁回傳的 observations_as_of／meta.as_of）；省略時是目前的值",
    ),
]


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


@router.get("/findings/{finding_id}")
def get_finding(
    finding_id: UUID,
    principal: CurrentPrincipal,
    session: DbSession,
    lab: CurrentLab,
    as_of: AsOf = None,
) -> Envelope[FindingDetailOut]:
    """finding 的摘要：身分、對應、快照中的 scan 數與觀察數、各引擎的數量與近期 5 次 scan。

    完整的掃描歷史與觀察以 /scans、/observations 分頁（帶回 observations_as_of）。其他 project 的
    finding 與不存在的一樣 404。
    """
    detail = FindingService(session, lab=lab).detail(principal, finding_id, as_of)
    return ok(FindingDetailOut.of(detail))


@router.get("/findings/{finding_id}/scans")
def list_finding_scans(
    finding_id: UUID,
    principal: CurrentPrincipal,
    session: DbSession,
    lab: CurrentLab,
    page: PageQuery,
    as_of: AsOf = None,
) -> SnapshotEnvelope[list[ScanAppearanceOut]]:
    """快照中出現過這個 finding 的 scan，由舊到新；每個 scan 列出所有 run（含失敗、沒有觀察的）。"""
    scans, snapshot = FindingService(session, lab=lab).scans(principal, finding_id, page, as_of)
    return ok_snapshot_page(scans, ScanAppearanceOut.of, as_of=snapshot)


@router.get("/findings/{finding_id}/observations")
def list_finding_observations(
    finding_id: UUID,
    principal: CurrentPrincipal,
    session: DbSession,
    lab: CurrentLab,
    page: PageQuery,
    as_of: AsOf = None,
    scan_id: Annotated[UUID | None, Query(description="只列這個 scan 的觀察")] = None,
    engine: Annotated[Engine | None, Query(description="只列這個引擎的觀察")] = None,
) -> SnapshotEnvelope[list[TracedObservationOut]]:
    """連結到這個 finding 的觀察，依連結的序號排序：連結當時的值、遮罩後的觀察、報告 artifact 的
    metadata（不含 storage_key 與內容）與 run（映像、plan_hash、工具與 parser 的版本）。
    """
    traced, snapshot = FindingService(session, lab=lab).observations(
        principal, finding_id, page, as_of=as_of, scan_id=scan_id, engine=engine
    )
    return ok_snapshot_page(traced, TracedObservationOut.of, as_of=snapshot)
