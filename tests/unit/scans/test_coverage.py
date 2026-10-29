"""轉送的請求涵蓋的 operation（docs/DECISIONS.md §16.6）。

- method 相同、path 符合 operation 的 route（佔位符對應一段）；同時符合多個時只算最具體的
  （佔位符最少，例如 /items/special 不算進 /items/{id}）。
- 不在範圍內（ineligible）的 operation 不算；同一個 operation 只要有一個請求帶認證 header 就是
  authenticated。
"""

from secscan.guard.domain.telemetry import ForwardedRequest
from secscan.scans.domain.coverage import FrozenOperation, observed_operations

OPERATIONS = (
    FrozenOperation(ordinal=0, method="GET", path="/items/{id}"),
    FrozenOperation(ordinal=1, method="GET", path="/items/special"),
    FrozenOperation(ordinal=2, method="POST", path="/items"),
    FrozenOperation(ordinal=3, method="GET", path="/users/{id}/orders/{order}"),
)


def _request(path: str, method: str = "GET", *, auth: bool = False, sequence: int = 1) -> object:
    return ForwardedRequest(sequence=sequence, at=1.0, method=method, path=path, authenticated=auth)


def test_requests_map_to_the_matching_operation() -> None:
    requests = [_request("/items/7"), _request("/items", "POST", auth=True)]

    assert observed_operations(OPERATIONS, requests) == {0: False, 2: True}  # type: ignore[arg-type]


def test_the_most_specific_operation_wins() -> None:
    assert observed_operations(OPERATIONS, [_request("/items/special")]) == {1: False}  # type: ignore[list-item]


def test_one_authenticated_request_is_enough() -> None:
    requests = [_request("/items/1"), _request("/items/2", auth=True), _request("/items/3")]

    assert observed_operations(OPERATIONS, requests) == {0: True}  # type: ignore[arg-type]


def test_other_methods_paths_and_shapes_do_not_count() -> None:
    requests = [
        _request("/items/7", "DELETE"),
        _request("/items"),  # GET /items 不在規格中
        _request("/items/7/extra"),
        _request("/items/7/"),  # 結尾的 / 不同
        _request("/users/1/orders"),
    ]

    assert observed_operations(OPERATIONS, requests) == {}  # type: ignore[arg-type]


def test_nested_placeholders_match_one_segment_each() -> None:
    assert observed_operations(OPERATIONS, [_request("/users/1/orders/9")]) == {3: False}  # type: ignore[list-item]
