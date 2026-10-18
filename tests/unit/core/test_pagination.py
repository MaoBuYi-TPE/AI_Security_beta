import pytest

from secscan.core.envelope import MAX_PAGE_LIMIT
from secscan.core.pagination import DEFAULT_PAGE_LIMIT, MAX_PAGE, Page, PageRequest


def test_page_request_defaults_to_first_page() -> None:
    request = PageRequest()

    assert (request.page, request.limit, request.offset) == (1, DEFAULT_PAGE_LIMIT, 0)


@pytest.mark.parametrize(("page", "limit", "offset"), [(1, 10, 0), (2, 10, 10), (3, 25, 50)])
def test_offset_skips_previous_pages(page: int, limit: int, offset: int) -> None:
    assert PageRequest(page=page, limit=limit).offset == offset


@pytest.mark.parametrize(
    ("page", "limit"),
    # 頁碼也要有上限：offset 太大會讓 DB 的 bigint 溢位，或變成很慢的查詢。
    [(0, 10), (-1, 10), (MAX_PAGE + 1, 10), (10**17, 100), (1, 0), (1, MAX_PAGE_LIMIT + 1)],
)
def test_page_request_rejects_out_of_range_values(page: int, limit: int) -> None:
    with pytest.raises(ValueError, match=r"^(page|limit) "):
        PageRequest(page=page, limit=limit)


def test_page_request_accepts_max_page_and_limit() -> None:
    request = PageRequest(page=MAX_PAGE, limit=MAX_PAGE_LIMIT)

    assert (request.page, request.limit) == (MAX_PAGE, MAX_PAGE_LIMIT)


def test_page_keeps_items_total_and_request() -> None:
    request = PageRequest(page=2, limit=2)
    page = Page(items=("c", "d"), total=5, request=request)

    assert page.items == ("c", "d")
    assert page.total == 5
    assert page.request is request


def test_page_rejects_negative_total() -> None:
    with pytest.raises(ValueError, match="total"):
        Page(items=(), total=-1, request=PageRequest())
