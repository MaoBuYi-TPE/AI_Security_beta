"""路由表：把 (method, path 樣板) 對到 handler 名稱（T30）。

app.handle 與 OpenAPI 規格共用這張表。path 樣板用 `{name}` 代表整段路由參數。
secure.py 與 insecure.py 都必須實作這裡列出的每一個 handler key。
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Route:
    method: str
    template: str  # 例如 /api/orders/{id}
    handler: str  # secure/insecure 的 HANDLERS key
    surface: str  # web 或 api

    @property
    def segments(self) -> tuple[str, ...]:
        return tuple(part for part in self.template.split("/") if part != "")


ROUTES: tuple[Route, ...] = (
    # Web 表面（traditional spider 走得到）。
    Route("GET", "/", "home", "web"),
    Route("GET", "/search", "search", "web"),
    Route("GET", "/greet", "greet", "web"),
    Route("POST", "/login", "login", "web"),
    Route("GET", "/go", "go", "web"),
    Route("GET", "/backup.sql", "backup", "web"),
    # API 表面（api_active_lab，以 OpenAPI 規格掃描）。
    Route("GET", "/me", "me", "api"),
    Route("GET", "/api/users", "users_list", "api"),
    Route("POST", "/api/users", "users_create", "api"),
    Route("GET", "/api/users/{id}", "user_get", "api"),
    Route("GET", "/api/orders/{id}", "order_get", "api"),
    Route("PUT", "/api/orders/{id}", "order_put", "api"),
    # 平台阻擋（前瞻）：path 參數注入，strict-1 下 guard 以 PATH_AMBIGUOUS 擋下。
    Route("GET", "/users/{username}", "user_by_name", "api"),
)

# 所有 handler key，供 secure/insecure 的完整性檢查。
HANDLER_KEYS: frozenset[str] = frozenset(route.handler for route in ROUTES)


def match(method: str, path: str) -> tuple[Route, dict[str, str]] | None:
    """找出相符的 route 與擷取的路由參數；沒有相符的 path 回 None。

    path 相符但 method 不符時，回傳該 path 任一 route 的 405 標記（handler="__405__"）。
    """
    wanted = tuple(part for part in path.split("/") if part != "")
    path_matched = False
    for route in ROUTES:
        params = _capture(route.segments, wanted)
        if params is None:
            continue
        path_matched = True
        if route.method == method:
            return route, params
    if path_matched:
        return Route(method, path, "__405__", "api"), {}
    return None


def _capture(template: tuple[str, ...], wanted: tuple[str, ...]) -> dict[str, str] | None:
    if len(template) != len(wanted):
        return None
    params: dict[str, str] = {}
    for pattern, value in zip(template, wanted, strict=True):
        if pattern.startswith("{") and pattern.endswith("}"):
            params[pattern[1:-1]] = value
        elif pattern != value:
            return None
    return params
