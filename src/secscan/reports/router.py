"""報告的端點（T21）。只做輸入驗證與呼叫 service；下載的 header 在這裡固定。"""

from http import HTTPStatus
from uuid import UUID

from fastapi import APIRouter, Request, Response

from secscan.api_keys.dependencies import CurrentPrincipal
from secscan.core.api import PageQuery, ok_page
from secscan.core.db import DbSession
from secscan.core.envelope import Envelope, ok
from secscan.core.errors import AppError, ErrorCode
from secscan.core.request_id import request_id_of
from secscan.reports.domain.model import ReportFormat
from secscan.reports.schemas import ReportCreate, ReportOut
from secscan.reports.service import Report, ReportService
from secscan.scans.domain.request import InvalidIdempotencyKeyError, parse_idempotency_key
from secscan.targets.dependencies import CurrentLab

router = APIRouter(tags=["reports"])
IDEMPOTENCY_KEY_HEADER = "Idempotency-Key"
_MEDIA_TYPES = {
    ReportFormat.JSON: ("application/json", "json"),
    ReportFormat.MARKDOWN: ("text/markdown; charset=utf-8", "md"),
}
_KEY_PARAMETER = {
    "name": IDEMPOTENCY_KEY_HEADER,
    "in": "header",
    "required": True,
    "description": "client 產生的隨機 key（16 到 128 個英數字、- 或 _）；範圍是 project。",
    "schema": {"type": "string"},
}


@router.post(
    "/scans/{scan_id}/reports",
    status_code=HTTPStatus.ACCEPTED,
    openapi_extra={"parameters": [_KEY_PARAMETER]},
    responses={HTTPStatus.OK: {"model": Envelope[ReportOut], "description": "重送：報告已結束"}},
)
def create_report(
    scan_id: UUID,
    body: ReportCreate,
    request: Request,
    response: Response,
    principal: CurrentPrincipal,
    session: DbSession,
    lab: CurrentLab,
) -> Envelope[ReportOut]:
    """把報告排入佇列（scan 必須已終止）；worker 產生之後以 download 取得內容。"""
    report, _ = ReportService(session, lab=lab).create(
        principal,
        scan_id,
        body.format,
        idempotency_key=_idempotency_key(request),
        request_id=request_id_of(request),
    )
    response.status_code = HTTPStatus.OK if report.is_terminal else HTTPStatus.ACCEPTED
    return ok(ReportOut.of(report))


@router.get("/scans/{scan_id}/reports")
def list_scan_reports(
    scan_id: UUID, principal: CurrentPrincipal, session: DbSession, lab: CurrentLab, page: PageQuery
) -> Envelope[list[ReportOut]]:
    reports = ReportService(session, lab=lab).for_scan(principal, scan_id, page)
    return ok_page(reports, ReportOut.of)


@router.get("/reports/{report_id}")
def get_report(
    report_id: UUID, principal: CurrentPrincipal, session: DbSession, lab: CurrentLab
) -> Envelope[ReportOut]:
    return ok(ReportOut.of(ReportService(session, lab=lab).get(principal, report_id)))


@router.get(
    "/reports/{report_id}/download",
    response_class=Response,
    responses={HTTPStatus.OK: {"content": {"application/json": {}, "text/markdown": {}}}},
)
def download_report(
    report_id: UUID, principal: CurrentPrincipal, session: DbSession, lab: CurrentLab
) -> Response:
    """平台產生的報告內容（附件下載）；只能以 report id 下載，送出前核對 sha256。"""
    report, content = ReportService(session, lab=lab).download(principal, report_id)
    return Response(content=content, headers=download_headers(report))


def download_headers(report: Report) -> dict[str, str]:
    media_type, extension = _MEDIA_TYPES[report.format]
    filename = f"secscan-report-{report.scan_id.hex[:8]}-{report.id.hex[:8]}.{extension}"
    return {
        "Content-Type": media_type,
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; sandbox",
        "Cache-Control": "no-store",
    }


def _idempotency_key(request: Request) -> str:
    try:
        return parse_idempotency_key(request.headers.getlist(IDEMPOTENCY_KEY_HEADER))
    except InvalidIdempotencyKeyError as exc:
        raise AppError(
            status_code=HTTPStatus.BAD_REQUEST, code=ErrorCode.INVALID_REQUEST, message=f"{exc}。"
        ) from None
