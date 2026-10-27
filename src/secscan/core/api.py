"""/api/v1 業務路由共用的元件：版本前綴、分頁 query 與清單 envelope（CLAUDE.md §11）。"""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, Query
from pydantic import AfterValidator, AwareDatetime

from secscan.core.envelope import MAX_PAGE_LIMIT, Envelope, PageMeta
from secscan.core.pagination import DEFAULT_PAGE_LIMIT, MAX_PAGE, Page, PageRequest

API_V1_PREFIX = "/api/v1"


def page_request(
    page: Annotated[int, Query(ge=1, le=MAX_PAGE, description="第幾頁，從 1 起算")] = 1,
    limit: Annotated[
        int, Query(ge=1, le=MAX_PAGE_LIMIT, description="每頁筆數")
    ] = DEFAULT_PAGE_LIMIT,
) -> PageRequest:
    """清單的 page/limit query；超出範圍時回 422，不默默修正。"""
    return PageRequest(page=page, limit=limit)


PageQuery = Annotated[PageRequest, Depends(page_request)]


def _as_utc(value: datetime) -> datetime:
    """帶時區的時間換算成 UTC；換算之後超出 datetime 的範圍（例如 9999-12-31T23:00-05:00）時
    拋出 ValueError（422），不讓 DB 層的換算變成 500（安全審查發現）。"""
    try:
        return value.astimezone(UTC)
    except OverflowError:
        raise ValueError("換算成 UTC 之後超出可表示的時間範圍") from None


# query 中的時間：必須帶時區，在驗證時就換算成 UTC。
UtcDatetime = Annotated[AwareDatetime, AfterValidator(_as_utc)]


def ok_page[T, R](page: Page[T], convert: Callable[[T], R]) -> Envelope[list[R]]:
    """清單回應：data 是轉換後的項目，meta 帶 page、limit 與符合條件的總筆數。"""
    return Envelope(
        success=True,
        data=[convert(item) for item in page.items],
        meta=PageMeta(page=page.request.page, limit=page.request.limit, total=page.total),
    )
