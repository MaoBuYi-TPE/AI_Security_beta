"""規格的 domain model：從 DB 讀回的資料也要經過檢查（fail closed）。"""

from dataclasses import replace
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from secscan.specs.domain.documents import SpecFormat
from secscan.specs.domain.model import ApiSpec
from secscan.targets.domain import parse_origin


def _spec(**overrides: object) -> ApiSpec:
    spec = ApiSpec(
        id=uuid4(),
        target_id=uuid4(),
        project_id=uuid4(),
        origin=parse_origin("http://juice-shop:3000"),
        version=1,
        source_format=SpecFormat.YAML,
        source_size=10,
        source_sha256=bytes(32),
        document_sha256=bytes(range(32)),
        openapi_version="3.0.3",
        base_path="/b2b/v2",
        operation_count=0,
        uploaded_by_key_id=uuid4(),
        created_at=datetime(2026, 10, 24, tzinfo=UTC),
    )
    return replace(spec, **overrides)  # type: ignore[arg-type]


def test_server_url_is_the_target_origin_plus_the_base_path() -> None:
    assert _spec().server_url == "http://juice-shop:3000/b2b/v2"
    assert _spec(base_path="").server_url == "http://juice-shop:3000"


@pytest.mark.parametrize(
    "overrides",
    [
        {"version": 0},
        {"operation_count": -1},
        {"source_size": 0},
        {"source_sha256": bytes(31)},
        {"document_sha256": bytes(33)},
    ],
)
def test_stored_values_are_checked(overrides: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="api spec"):
        _spec(**overrides)
