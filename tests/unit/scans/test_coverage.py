"""轉送的請求涵蓋的 operation（docs/DECISIONS.md §16.6）。

- method 相同、path 符合 operation 的 route（佔位符對應一段）；同時符合多個時只算最具體的
  （佔位符最少，例如 /items/special 不算進 /items/{id}）。
- 只算有上游回應的請求（沒有回應不代表測到了）；authenticated 要帶認證 header 的請求取得
  401、403 以外的回應（審查發現：只看送出不看回應會高估）。
"""

from secscan.scans.domain.coverage import Exchange, FrozenOperation, observed_operations

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

    assert observed_operations(OPERATIONS, exchanges) == {0: False, 2: True}


def test_the_most_specific_operation_wins() -> None:
    assert observed_operations(OPERATIONS, [_exchange("/items/special")]) == {1: False}


def test_one_authenticated_request_is_enough() -> None:
    exchanges = [_exchange("/items/1"), _exchange("/items/2", auth=True), _exchange("/items/3")]

    assert observed_operations(OPERATIONS, exchanges) == {0: True}


def test_other_methods_paths_and_shapes_do_not_count() -> None:
    exchanges = [
        _exchange("/items/7", "DELETE"),
        _exchange("/items"),  # GET /items 不在規格中
        _exchange("/items/7/extra"),
        _exchange("/items/7/"),  # 結尾的 / 不同
        _exchange("/users/1/orders"),
    ]

    assert observed_operations(OPERATIONS, exchanges) == {}


def test_nested_placeholders_match_one_segment_each() -> None:
    assert observed_operations(OPERATIONS, [_exchange("/users/1/orders/9")]) == {3: False}


def test_requests_without_a_response_are_not_coverage() -> None:
    assert observed_operations(OPERATIONS, [_exchange("/items/7", auth=True, status=None)]) == {}


def test_rejected_credentials_are_not_authenticated_coverage() -> None:
    exchanges = [
        _exchange("/items/1", auth=True, status=401),
        _exchange("/items/special", auth=True, status=403),
        _exchange("/users/1/orders/2", auth=True, status=500),
    ]

    assert observed_operations(OPERATIONS, exchanges) == {0: False, 1: False, 3: True}
