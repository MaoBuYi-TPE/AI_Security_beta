"""轉送的請求涵蓋的 operation（docs/DECISIONS.md §16.6）。

guard 記下的每個轉送的請求（method、不含 query 的 path、是否帶認證 header）對應到 scan 建立時
凍結、在範圍內的 operation：method 相同，operation 的 route 以 §11.6 的規則（不寬鬆）涵蓋請求的
path。同時符合多個時只算最具體的（佔位符最少）：`/items/special` 不算進 `/items/{id}`。
同一個 operation 只要有一個請求帶認證 header 就是 authenticated（是否真的通過認證由 preflight
判斷，見 usage 與 API）。
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from secscan.grants.domain.matching import Route, covers, parse_route
from secscan.guard.domain.telemetry import ForwardedRequest


@dataclass(frozen=True, slots=True)
class FrozenOperation:
    """scan 凍結、在 grant 範圍內的 operation（scan_operations 中 ineligible_reason 為 NULL）。"""

    ordinal: int
    method: str
    path: str


def observed_operations(
    operations: Iterable[FrozenOperation], requests: Iterable[ForwardedRequest]
) -> Mapping[int, bool]:
    """ordinal → 是否有帶認證 header 的請求。"""
    routes = [(operation, parse_route(operation.path)) for operation in operations]
    observed: dict[int, bool] = {}
    for request in requests:
        for ordinal in _matches(routes, request):
            observed[ordinal] = observed.get(ordinal, False) or request.authenticated
    return observed


def _matches(routes: list[tuple[FrozenOperation, Route]], request: ForwardedRequest) -> list[int]:
    path = parse_route(request.path)
    candidates = [
        (sum(segment is None for segment in route.segments), operation.ordinal)
        for operation, route in routes
        if operation.method == request.method and covers(route, path, lenient=False)
    ]
    if not candidates:
        return []
    fewest = min(placeholders for placeholders, _ in candidates)
    return [ordinal for placeholders, ordinal in candidates if placeholders == fewest]
