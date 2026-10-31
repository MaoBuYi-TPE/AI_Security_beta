"""轉送的請求涵蓋的 operation（docs/DECISIONS.md §16.6）。

guard 記下的每個轉送的請求與它的上游回應（Exchange）對應到 scan 建立時凍結、在範圍內的
operation：method 相同，operation 的 route 以 §11.6 的規則（不寬鬆）涵蓋請求的 path。同時符合多個
時只算最具體的（佔位符最少）：`/items/special` 不算進 `/items/{id}`。
- 沒有上游回應的請求不算（連不上、被中止，不代表測到了）。
- authenticated：至少一個帶認證 header 的請求取得 401、403 以外的回應（認證被拒絕的不算）。
  憑證本身是否有效另由 preflight 判斷（API 只在 preflight 通過時揭露）。
"""

from collections.abc import Iterable, Mapping, Sized
from dataclasses import dataclass

from secscan.grants.domain.matching import Route, covers, parse_route

REJECTED_CREDENTIALS = frozenset({401, 403})


@dataclass(frozen=True, slots=True)
class FrozenOperation:
    """scan 凍結、在 grant 範圍內的 operation（scan_operations 中 ineligible_reason 為 NULL）。"""

    ordinal: int
    method: str
    path: str


@dataclass(frozen=True, slots=True)
class Exchange:
    """一個轉送的請求（method、不含 query 的 path、是否帶認證 header）與上游的 status。"""

    method: str
    path: str
    authenticated: bool
    status: int | None


def telemetry_complete(exchanges: Sized, *, forwarded: int) -> bool:
    """telemetry 有沒有記下 guard 轉送的請求：summary 先寫、行後寫（§16.3），行數不會比轉送數多，
    中途失敗時最多少一行。少更多是檔案殘缺，不是沒有流量。
    """
    return forwarded - 1 <= len(exchanges) <= forwarded


def observed_operations(
    operations: Iterable[FrozenOperation], exchanges: Iterable[Exchange]
) -> Mapping[int, bool]:
    """ordinal → 是否有帶認證、而且認證沒有被拒絕的請求。"""
    routes = [(operation, parse_route(operation.path)) for operation in operations]
    observed: dict[int, bool] = {}
    for exchange in exchanges:
        if exchange.status is None:
            continue
        accepted = exchange.authenticated and exchange.status not in REJECTED_CREDENTIALS
        for ordinal in _matches(routes, exchange):
            observed[ordinal] = observed.get(ordinal, False) or accepted
    return observed


def _matches(routes: list[tuple[FrozenOperation, Route]], exchange: Exchange) -> list[int]:
    path = parse_route(exchange.path)
    candidates = [
        (sum(segment is None for segment in route.segments), operation.ordinal)
        for operation, route in routes
        if operation.method == exchange.method and covers(route, path, lenient=False)
    ]
    if not candidates:
        return []
    fewest = min(placeholders for placeholders, _ in candidates)
    return [ordinal for placeholders, ordinal in candidates if placeholders == fewest]
