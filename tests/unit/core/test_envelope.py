import pytest
from pydantic import ValidationError

from secscan.core.envelope import MAX_PAGE_LIMIT, Envelope, ErrorDetail, PageMeta, ok

NOT_FOUND = ErrorDetail(code="RESOURCE_NOT_FOUND", message="找不到資源。", request_id="req-1")


def test_ok_wraps_data_in_success_envelope() -> None:
    envelope = ok({"status": "ok"})

    assert envelope.model_dump(mode="json") == {
        "success": True,
        "data": {"status": "ok"},
        "error": None,
        "meta": None,
    }


def test_failure_envelope_carries_code_message_and_request_id() -> None:
    envelope = Envelope[None](success=False, error=NOT_FOUND)

    assert envelope.model_dump(mode="json") == {
        "success": False,
        "data": None,
        "error": {
            "code": "RESOURCE_NOT_FOUND",
            "message": "找不到資源。",
            "request_id": "req-1",
        },
        "meta": None,
    }


def test_list_envelope_carries_page_meta() -> None:
    envelope = Envelope[list[int]](success=True, data=[1], meta=PageMeta(page=1, limit=25, total=1))

    assert envelope.model_dump(mode="json")["meta"] == {"page": 1, "limit": 25, "total": 1}


def test_success_envelope_rejects_error() -> None:
    with pytest.raises(ValidationError):
        Envelope[None](success=True, error=NOT_FOUND)


def test_failure_envelope_requires_error() -> None:
    with pytest.raises(ValidationError):
        Envelope[None](success=False)


def test_failure_envelope_rejects_data() -> None:
    with pytest.raises(ValidationError):
        Envelope[int](success=False, data=1, error=NOT_FOUND)


def test_failure_envelope_rejects_meta() -> None:
    with pytest.raises(ValidationError):
        Envelope[None](success=False, error=NOT_FOUND, meta=PageMeta(page=1, limit=25, total=0))


@pytest.mark.parametrize(
    ("page", "limit", "total"),
    [(0, 25, 0), (1, 0, 0), (1, MAX_PAGE_LIMIT + 1, 0), (1, 25, -1)],
)
def test_page_meta_rejects_out_of_range_values(page: int, limit: int, total: int) -> None:
    with pytest.raises(ValidationError):
        PageMeta(page=page, limit=limit, total=total)


def test_page_meta_accepts_max_limit() -> None:
    assert PageMeta(page=1, limit=MAX_PAGE_LIMIT, total=0).limit == MAX_PAGE_LIMIT


def test_envelope_is_immutable() -> None:
    envelope = ok(1)

    with pytest.raises(ValidationError):
        envelope.success = False  # type: ignore[misc]
