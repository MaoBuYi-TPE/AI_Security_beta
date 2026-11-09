"""人工 triage 的端點（T21）。只做輸入驗證與呼叫 service；授權與規則在 service。"""

from uuid import UUID

from fastapi import APIRouter, Request, Response

from secscan.api_keys.dependencies import CurrentPrincipal
from secscan.core.api import PageQuery, ok_page
from secscan.core.db import DbSession
from secscan.core.envelope import Envelope, ok
from secscan.core.request_id import request_id_of
from secscan.findings.content_cipher import CurrentContentCipher, CurrentExcerptRetention
from secscan.findings.provenance_schemas import FindingDetailOut
from secscan.findings.service import FindingService
from secscan.targets.dependencies import CurrentLab
from secscan.triage.schemas import TriageChangeIn, TriageEventOut
from secscan.triage.service import TriageService

router = APIRouter(tags=["triage"])


@router.patch("/findings/{finding_id}/triage")
def change_triage(
    finding_id: UUID,
    body: TriageChangeIn,
    request: Request,
    principal: CurrentPrincipal,
    session: DbSession,
    lab: CurrentLab,
    cipher: CurrentContentCipher,
    retention: CurrentExcerptRetention,
) -> Envelope[FindingDetailOut]:
    """人工 triage：一次改一個欄位，必帶 expected_version 與 reason。

    resolved 一律是人工判定：basis 為 manual_retest 時附上人工複測聲明（平台只做一致性檢查）；
    rescan_not_observed 在比較演算法 v1 不會成立。比較快照不會被修改。
    """
    TriageService(session, cipher=cipher, excerpt_retention=retention).change(
        principal, finding_id, body.to_command(), request_id=request_id_of(request)
    )
    return ok(
        FindingDetailOut.of(FindingService(session, lab=lab).detail(principal, finding_id, None))
    )


@router.get("/findings/{finding_id}/triage-events")
def list_triage_events(
    finding_id: UUID,
    principal: CurrentPrincipal,
    session: DbSession,
    page: PageQuery,
    response: Response,
    cipher: CurrentContentCipher,
) -> Envelope[list[TriageEventOut]]:
    """不可修改的 triage 事件，依 sequence 由舊到新；摘錄內容只給 operator/admin（解密並核對）。"""
    events = TriageService(session, cipher=cipher).events(principal, finding_id, page)
    # 回應可能含人工複測的摘錄（只做樣式遮罩）：不得被 proxy 或 client 快取。
    response.headers["Cache-Control"] = "no-store"
    return ok_page(events, TriageEventOut.of)
