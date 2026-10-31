"""scan 的端點（docs/API_CONTRACT.md §17）。只做輸入驗證與呼叫 service。

- 建立：202（新建立，或未終止的重送）；已終止的重送回 200。
- 取消：202（cancelling，等 runner 確認）；已終止回 200。
- Idempotency-Key 在 schema 驗證之後、權限檢查之前判斷（docs/DECISIONS.md §13.3）。
"""

from datetime import UTC, datetime
from http import HTTPStatus
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query, Request, Response

from secscan.api_keys.dependencies import CurrentPrincipal
from secscan.core.api import PageQuery, UtcDatetime, ok_page
from secscan.core.db import DbSession
from secscan.core.envelope import MAX_PAGE_LIMIT, Envelope, ok
from secscan.core.errors import AppError, ErrorCode
from secscan.core.request_id import request_id_of
from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.lifecycle import ScanStatus
from secscan.scans.domain.model import Scan
from secscan.scans.domain.request import (
    IDEMPOTENCY_KEY_MAX_LENGTH,
    IDEMPOTENCY_KEY_MIN_LENGTH,
    InvalidIdempotencyKeyError,
    parse_idempotency_key,
)
from secscan.scans.repository import ScanFilters
from secscan.scans.schemas import ObservationOut, ScanCreate, ScanEventOut, ScanOut
from secscan.scans.service import ScanService
from secscan.targets.dependencies import CurrentLab

router = APIRouter(tags=["scans"])

IDEMPOTENCY_KEY_HEADER = "Idempotency-Key"
# PostgreSQL integer 的上限：更大的 sequence 不存在，也不必送進 DB。
MAX_EVENT_SEQUENCE = 2_147_483_647
# header 由 route 自己讀（重複出現也要拒絕），這裡只為 API 文件宣告它是必填的 header。
_KEY_LENGTHS = f"{IDEMPOTENCY_KEY_MIN_LENGTH},{IDEMPOTENCY_KEY_MAX_LENGTH}"
_KEY_PARAMETER = {
    "name": IDEMPOTENCY_KEY_HEADER,
    "in": "header",
    "required": True,
    "description": (
        f"client 產生的隨機 key：{IDEMPOTENCY_KEY_MIN_LENGTH} 到 {IDEMPOTENCY_KEY_MAX_LENGTH} 個"
        "英數字、- 或 _（UUID 可用；可以加上雙引號）。同一個 key、同樣的內容回原本的 scan；"
        "內容不同回 409。範圍是 project，永久保存。"
    ),
    # 引號要成對，和伺服器的規則（parse_idempotency_key）一致。
    "schema": {
        "type": "string",
        "pattern": (
            '^(?:"[A-Za-z0-9_-]{' + _KEY_LENGTHS + '}"|[A-Za-z0-9_-]{' + _KEY_LENGTHS + "})$"
        ),
    },
}


def _now() -> datetime:
    return datetime.now(UTC)


@router.post(
    "/scans",
    status_code=HTTPStatus.ACCEPTED,
    openapi_extra={"parameters": [_KEY_PARAMETER]},
    responses={HTTPStatus.OK: {"model": Envelope[ScanOut], "description": "重送：scan 已終止"}},
)
def create_scan(
    body: ScanCreate,
    principal: CurrentPrincipal,
    session: DbSession,
    lab: CurrentLab,
    request: Request,
    response: Response,
) -> Envelope[ScanOut]:
    """建立 scan（operator、admin）：scan 與每個引擎的 run 在同一個 transaction 寫入（queued）。"""
    key = _idempotency_key(request)
    scan = ScanService(session, lab=lab).create(
        principal,
        body.to_request(),
        idempotency_key=key,
        clock=_now,
        request_id=request_id_of(request),
    )
    response.status_code = _status(scan)
    return ok(ScanOut.of(scan))


@router.get("/scans")
def list_scans(
    principal: CurrentPrincipal,
    session: DbSession,
    lab: CurrentLab,
    page: PageQuery,
    target_id: Annotated[UUID | None, Query(description="只列這個 target 的 scan")] = None,
    status: Annotated[ScanStatus | None, Query(description="只列這個狀態的 scan")] = None,
    created_after: Annotated[
        UtcDatetime | None, Query(description="建立時間不早於（含時區）")
    ] = None,
    created_before: Annotated[
        UtcDatetime | None, Query(description="建立時間早於（含時區）")
    ] = None,
) -> Envelope[list[ScanOut]]:
    """呼叫者看得到的 scan，新的在前。"""
    filters = ScanFilters(
        target_id=target_id,
        status=status,
        created_after=created_after,
        created_before=created_before,
    )
    scans = ScanService(session, lab=lab).list(principal, filters, page)
    return ok_page(scans, ScanOut.of)


@router.get("/scans/{scan_id}")
def get_scan(
    scan_id: UUID, principal: CurrentPrincipal, session: DbSession, lab: CurrentLab
) -> Envelope[ScanOut]:
    """其他 project 的 scan 與不存在的一樣回 404。"""
    return ok(ScanOut.of(ScanService(session, lab=lab).get(principal, scan_id)))


@router.get("/scans/{scan_id}/events")
def list_events(
    scan_id: UUID,
    principal: CurrentPrincipal,
    session: DbSession,
    lab: CurrentLab,
    after_sequence: Annotated[
        int, Query(ge=0, le=MAX_EVENT_SEQUENCE, description="只回傳 sequence 更大的事件")
    ] = 0,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_LIMIT, description="最多幾個")] = MAX_PAGE_LIMIT,
) -> Envelope[list[ScanEventOut]]:
    """狀態轉換的事件，依 sequence 遞增；以最後一個的 sequence 當作下一次的 after_sequence。"""
    events = ScanService(session, lab=lab).events(
        principal, scan_id, after_sequence=after_sequence, limit=limit
    )
    return ok([ScanEventOut.of(event) for event in events])


@router.get("/scans/{scan_id}/observations")
def list_observations(
    scan_id: UUID,
    principal: CurrentPrincipal,
    session: DbSession,
    lab: CurrentLab,
    page: PageQuery,
    engine: Annotated[Engine | None, Query(description="只列這個引擎的觀察")] = None,
) -> Envelope[list[ObservationOut]]:
    """工具的單次觀察（遮罩、截斷之後），依引擎的順序與入庫的順序。其他 project 的 scan 回 404。"""
    observations = ScanService(session, lab=lab).observations(
        principal, scan_id, engine=engine, page=page
    )
    return ok_page(observations, ObservationOut.of)


@router.post(
    "/scans/{scan_id}/cancel",
    status_code=HTTPStatus.ACCEPTED,
    responses={HTTPStatus.OK: {"model": Envelope[ScanOut], "description": "scan 已終止"}},
)
def cancel_scan(
    scan_id: UUID,
    principal: CurrentPrincipal,
    session: DbSession,
    lab: CurrentLab,
    request: Request,
    response: Response,
) -> Envelope[ScanOut]:
    """要求取消（operator、admin）；runner 確認停止之後才是 cancelled。"""
    scan = ScanService(session, lab=lab).cancel(
        principal, scan_id, request_id=request_id_of(request)
    )
    response.status_code = _status(scan)
    return ok(ScanOut.of(scan))


def _idempotency_key(request: Request) -> str:
    try:
        return parse_idempotency_key(request.headers.getlist(IDEMPOTENCY_KEY_HEADER))
    except InvalidIdempotencyKeyError as exc:
        raise AppError(
            status_code=HTTPStatus.BAD_REQUEST, code=ErrorCode.INVALID_REQUEST, message=f"{exc}。"
        ) from None


def _status(scan: Scan) -> int:
    return HTTPStatus.OK if scan.is_terminal else HTTPStatus.ACCEPTED
