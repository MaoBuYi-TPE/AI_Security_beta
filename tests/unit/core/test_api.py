"""/api/v1 共用的 API 元件：分頁 query 與清單 envelope（CLAUDE.md §11）。"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from secscan.core.api import API_V1_PREFIX, PageQuery, ok_page
from secscan.core.envelope import MAX_PAGE_LIMIT
from secscan.core.errors import register_error_handlers
from secscan.core.pagination import DEFAULT_PAGE_LIMIT, MAX_PAGE, Page, PageRequest


def _client() -> TestClient:
    app = FastAPI()
    register_error_handlers(app)

    @app.get("/items")
    def items(page: PageQuery) -> dict[str, int]:
        return {"page": page.page, "limit": page.limit}

    return TestClient(app)


def test_business_routes_are_versioned() -> None:
    assert API_V1_PREFIX == "/api/v1"


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({}, {"page": 1, "limit": DEFAULT_PAGE_LIMIT}),
        ({"page": MAX_PAGE, "limit": MAX_PAGE_LIMIT}, {"page": MAX_PAGE, "limit": MAX_PAGE_LIMIT}),
    ],
    ids=["defaults", "upper-bounds"],
)
def test_page_query_values(params: dict[str, int], expected: dict[str, int]) -> None:
    with _client() as client:
        response = client.get("/items", params=params)

    assert response.status_code == 200
    assert response.json() == expected


@pytest.mark.parametrize(
    ("params", "location"),
    [
        ({"page": 0}, "query.page"),
        ({"page": MAX_PAGE + 1}, "query.page"),
        ({"page": "two"}, "query.page"),
        ({"limit": 0}, "query.limit"),
        ({"limit": MAX_PAGE_LIMIT + 1}, "query.limit"),
    ],
)
def test_page_query_rejects_out_of_range_values(
    params: dict[str, int | str], location: str
) -> None:
    with _client() as client:
        response = client.get("/items", params=params)

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "INVALID_REQUEST"
    assert location in error["message"]


def test_ok_page_wraps_converted_items_with_meta() -> None:
    page = Page(items=(1, 2), total=7, request=PageRequest(page=2, limit=2))

    envelope = ok_page(page, str)

    assert envelope.model_dump() == {
        "success": True,
        "data": ["1", "2"],
        "error": None,
        "meta": {"page": 2, "limit": 2, "total": 7},
    }
