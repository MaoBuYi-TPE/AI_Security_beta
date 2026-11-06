"""複掃比較端點；授權與快照在 service 處理。"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query, Request, Response

from secscan.api_keys.dependencies import CurrentPrincipal
from secscan.comparisons.domain.classification import Classification
from secscan.comparisons.schemas import ComparisonCreate, ComparisonFindingOut, ComparisonOut
from secscan.comparisons.service import ComparisonService
from secscan.core.api import PageQuery, ok_page
from secscan.core.db import DbSession
from secscan.core.envelope import Envelope, ok
from secscan.core.request_id import request_id_of

router = APIRouter(prefix="/scan-comparisons", tags=["scan-comparisons"])


@router.post("", status_code=201, responses={200: {"model": Envelope[ComparisonOut]}})
def create_comparison(
    body: ComparisonCreate,
    request: Request,
    response: Response,
    principal: CurrentPrincipal,
    session: DbSession,
) -> Envelope[ComparisonOut]:
    snapshot, created = ComparisonService(session).create(
        principal,
        body.baseline_scan_id,
        body.current_scan_id,
        request_id=request_id_of(request),
    )
    response.status_code = 201 if created else 200
    return ok(ComparisonOut.of(snapshot))


@router.get("/{comparison_id}")
def get_comparison(
    comparison_id: UUID,
    principal: CurrentPrincipal,
    session: DbSession,
) -> Envelope[ComparisonOut]:
    return ok(ComparisonOut.of(ComparisonService(session).get(principal, comparison_id)))


@router.get("/{comparison_id}/findings")
def list_comparison_findings(
    comparison_id: UUID,
    principal: CurrentPrincipal,
    session: DbSession,
    page: PageQuery,
    classification: Annotated[Classification | None, Query()] = None,
) -> Envelope[list[ComparisonFindingOut]]:
    result = ComparisonService(session).findings(principal, comparison_id, classification, page)
    return ok_page(result, ComparisonFindingOut.of)
