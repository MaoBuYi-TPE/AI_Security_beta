"""/api/v1 業務路由共用的元件：版本前綴、分頁 query 與清單 envelope（CLAUDE.md §11）。"""

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, Query

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


def ok_page[T, R](page: Page[T], convert: Callable[[T], R]) -> Envelope[list[R]]:
    """清單回應：data 是轉換後的項目，meta 帶 page、limit 與符合條件的總筆數。"""
    return Envelope(
        success=True,
        data=[convert(item) for item in page.items],
        meta=PageMeta(page=page.request.page, limit=page.request.limit, total=page.total),
    )
