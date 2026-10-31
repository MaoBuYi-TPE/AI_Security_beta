"""轉送的請求涵蓋的 operation（docs/DECISIONS.md §16.6）。

- method 相同、path 符合 operation 的 route（佔位符對應一段）；同時符合多個時只算最具體的
  （佔位符最少，例如 /items/special 不算進 /items/{id}）。
- 只算有上游回應的請求（沒有回應不代表測到了）；authenticated 要帶認證 header 的請求取得
  401、403 以外的回應（審查發現：只看送出不看回應會高估）。
"""

import pytest

from secscan.grants.domain.request_paths import PathEncoding
from secscan.scans.domain.coverage import (
    Exchange,
    FrozenOperation,
    observed_operations,
    telemetry_complete,
)

OPERATIONS = (
    FrozenOperation(ordinal=0, method="GET", path="/items/{id}"),
    FrozenOperation(ordinal=1, method="GET", path="/items/special"),
    FrozenOperation(ordinal=2, method="POST", path="/items"),
    FrozenOperation(ordinal=3, method="GET", path="/users/{id}/orders/{order}"),
)


def _exchange(
    path: str, method: str = "GET", *, auth: bool = False, status: int | None = 200
) -> Exchange:
    return Exchange(method=method, path=path, authenticated=auth, status=status)


def test_requests_map_to_the_matching_operation() -> None:
    exchanges = [_exchange("/items/7"), _exchange("/items", "POST", auth=True)]

    assert observed_operations(OPERATIONS, exchanges, encoding=PathEncoding.REJECT) == {
        0: False,
        2: True,
    }


def test_the_most_specific_operation_wins() -> None:
    assert observed_operations(
        OPERATIONS, [_exchange("/items/special")], encoding=PathEncoding.REJECT
    ) == {1: False}


def test_one_authenticated_request_is_enough() -> None:
    exchanges = [_exchange("/items/1"), _exchange("/items/2", auth=True), _exchange("/items/3")]

    assert observed_operations(OPERATIONS, exchanges, encoding=PathEncoding.REJECT) == {0: True}


def test_other_methods_paths_and_shapes_do_not_count() -> None:
    exchanges = [
        _exchange("/items/7", "DELETE"),
        _exchange("/items"),  # GET /items 不在規格中
        _exchange("/items/7/extra"),
        _exchange("/items/7/"),  # 結尾的 / 不同
        _exchange("/users/1/orders"),
    ]

    assert observed_operations(OPERATIONS, exchanges, encoding=PathEncoding.REJECT) == {}


def test_nested_placeholders_match_one_segment_each() -> None:
    assert observed_operations(
        OPERATIONS, [_exchange("/users/1/orders/9")], encoding=PathEncoding.REJECT
    ) == {3: False}


def test_requests_without_a_response_are_not_coverage() -> None:
    assert (
        observed_operations(
            OPERATIONS,
            [_exchange("/items/7", auth=True, status=None)],
            encoding=PathEncoding.REJECT,
        )
        == {}
    )


def test_rejected_credentials_are_not_authenticated_coverage() -> None:
    exchanges = [
        _exchange("/items/1", auth=True, status=401),
        _exchange("/items/special", auth=True, status=403),
        _exchange("/users/1/orders/2", auth=True, status=500),
    ]

    assert observed_operations(OPERATIONS, exchanges, encoding=PathEncoding.REJECT) == {
        0: False,
        1: False,
        3: True,
    }


@pytest.mark.parametrize(
    ("lines", "forwarded", "complete"),
    [(3, 3, True), (2, 3, True), (1, 3, False), (0, 71, False), (4, 3, False), (0, 0, True)],
)
def test_telemetry_is_complete_within_one_line(lines: int, forwarded: int, complete: bool) -> None:
    """summary 先寫、行後寫（§16.3）：不會比轉送數多，中途失敗時最多少一行。"""
    assert telemetry_complete(range(lines), forwarded=forwarded) is complete


@pytest.mark.parametrize("path", ["/items/a%27", "/items/%7Busername%7D", "/items/a%3c"])
def test_encoded_parameter_data_covers_only_a_parameter_operation(path: str) -> None:
    assert observed_operations(
        OPERATIONS, [_exchange(path)], encoding=PathEncoding.ROUTE_PARAMETERS
    ) == {0: False}
    assert observed_operations(OPERATIONS, [_exchange(path)], encoding=PathEncoding.REJECT) == {}


@pytest.mark.parametrize("path", ["/items/%41", "/items/%252F", "/items/%2F", "/items/{id}"])
def test_ambiguous_paths_never_count_as_coverage(path: str) -> None:
    assert (
        observed_operations(OPERATIONS, [_exchange(path)], encoding=PathEncoding.ROUTE_PARAMETERS)
        == {}
    )
