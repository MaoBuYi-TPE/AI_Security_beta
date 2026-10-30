"""grant 的範圍 → ZAP context 的 includePaths／excludePaths（docs/DECISIONS.md §18.4）。

ZAP 以 Java 的 regex 完整比對整個 URL（含 query）。語意和 guard 的 covers() 相同：
- 允許：段數相同、大小寫與結尾的斜線都一致；佔位涵蓋任何一段。
- 排除：段數相同、不分大小寫、忽略結尾的斜線（不涵蓋底下的 path）。
英數字以外的字元一律以反斜線跳脫：Java 與 Python 的 regex 都當成字元本身（測試因此能以 Python
對照）。context 只是讓 ZAP 少送 guard 會拒絕的請求；邊界仍是 guard。

AF 把 context 的每個 url 加成 `url.*` 的 include（不跳脫，ContextWrapper），所以只靠
includePaths 限制不了範圍：excludePaths 另外加一條「完整比對不到任何一條允許的 regex」
（負向前瞻；ZAP 的排除優先於包含）。
"""

from dataclasses import dataclass

from secscan.grants.domain.matching import Route, parse_route
from secscan.grants.domain.scope import Scope
from secscan.targets.domain import Origin

PLACEHOLDER = "[^/?#]+"
QUERY = r"(?:\?.*)?"
_IGNORE_CASE = "(?i)"


@dataclass(frozen=True, slots=True)
class ContextPaths:
    urls: tuple[str, ...]
    include: tuple[str, ...]
    exclude: tuple[str, ...]


def context_paths(origin: Origin, scope: Scope) -> ContextPaths:
    base = quote(str(origin))
    if scope.allow_all_paths:
        include: tuple[str, ...] = (f"{base}/.*",)
    else:
        include = tuple(
            f"{base}{_route(parse_route(path), lenient=False)}{QUERY}" for path in scope.paths
        )
    excluded = tuple(
        f"{_IGNORE_CASE}{base}{_route(parse_route(path), lenient=True)}{QUERY}"
        for path in scope.excluded_paths
    )
    outside = "(?!(?:" + "|".join(f"(?:{pattern})" for pattern in include) + ")$).*"
    return ContextPaths(urls=(f"{origin}/",), include=include, exclude=(*excluded, outside))


def quote(text: str) -> str:
    """英數字以外的字元一律加上反斜線。"""
    return "".join(c if c.isascii() and c.isalnum() else f"\\{c}" for c in text)


def _route(route: Route, *, lenient: bool) -> str:
    path = "/" + "/".join(PLACEHOLDER if part is None else quote(part) for part in route.segments)
    if not route.segments:
        return path
    if lenient:
        return f"{path}/?"
    return f"{path}/" if route.trailing_slash else path
