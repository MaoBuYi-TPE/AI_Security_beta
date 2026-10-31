"""path 與 method 的比對（docs/DECISIONS.md §11.6）。

pattern（grant 的 path）「涵蓋」route（規格的 path，或實際請求的 path）的條件：
- 段數相同，不從前綴推論：排除 `/api/admin` 不包含 `/api/admin/{id}`。
- pattern 的佔位涵蓋任何一段；pattern 的 literal 只涵蓋相同的 literal，不涵蓋 route 中的佔位
  （route 的佔位還包含其他 path）。佔位的名稱不影響比對。
- 允許（lenient=False）：大小寫與結尾的斜線都必須一致。
- 排除（lenient=True）：不分大小寫、忽略結尾的斜線，至少和伺服器一樣寬（§10.8）。
允許往窄、排除往寬，都是安全的一側。

兩者的語法相同（scope.check_path），都只有 ASCII，所以大小寫以 str.lower() 比較。
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Self

from secscan.grants.domain.request_paths import PathAmbiguity, RequestPath
from secscan.grants.domain.scope import Scope, check_path


@dataclass(frozen=True, slots=True)
class Route:
    """已檢查語法的 path：每一段是 literal，或 None（佔位）。根目錄 `/` 沒有任何一段。"""

    segments: tuple[str | None, ...]
    trailing_slash: bool


def parse_route(path: str, *, label: str = "path") -> Route:
    """語法同 grant 的 path；不合規則時拋出 InvalidScopeError（訊息以 label 開頭）。"""
    check_path(path, label=label)
    parts = path[1:].split("/")
    trailing_slash = len(parts) > 1 and parts[-1] == ""
    if parts[-1] == "":
        parts.pop()
    return Route(
        segments=tuple(None if part.startswith("{") else part for part in parts),
        trailing_slash=trailing_slash,
    )


def covers(pattern: Route, route: Route, *, lenient: bool) -> bool:
    """pattern 是否涵蓋 route 的每一個請求。lenient=True 用於排除。"""
    if len(pattern.segments) != len(route.segments):
        return False
    if not lenient and pattern.trailing_slash != route.trailing_slash:
        return False
    return all(
        _segment_covers(expected, actual, lenient=lenient)
        for expected, actual in zip(pattern.segments, route.segments, strict=True)
    )


def _segment_covers(expected: str | None, actual: str | None, *, lenient: bool) -> bool:
    if expected is None:
        return True
    if actual is None:
        return False
    return expected.lower() == actual.lower() if lenient else expected == actual


def covers_request(pattern: Route, request: RequestPath) -> bool:
    """完整允許比對：編碼資料只可出現在同一條 pattern 明確授權的佔位。"""
    if len(pattern.segments) != len(request.segments):
        return False
    if pattern.trailing_slash != request.trailing_slash:
        return False
    return all(
        expected is None or (not actual.encoded and expected == actual.raw)
        for expected, actual in zip(pattern.segments, request.segments, strict=True)
    )


def _request_excluded(pattern: Route, request: RequestPath) -> bool:
    if len(pattern.segments) != len(request.segments):
        return False
    pairs = tuple(zip(pattern.segments, request.segments, strict=True))
    if not all(
        expected is None or actual.encoded or expected.lower() == actual.raw.lower()
        for expected, actual in pairs
    ):
        return False
    if any(expected is not None and actual.encoded for expected, actual in pairs):
        raise PathAmbiguity("exclusion-overlap")
    return True


class IneligibleReason(StrEnum):
    """operation 不在 grant 範圍內的原因（穩定的對外代碼）。"""

    PATH_EXCLUDED = "PATH_EXCLUDED"
    METHOD_NOT_AUTHORIZED = "METHOD_NOT_AUTHORIZED"
    PATH_NOT_AUTHORIZED = "PATH_NOT_AUTHORIZED"


@dataclass(frozen=True, slots=True)
class ScopeRules:
    """grant 的範圍，先把 path 解析好，比對大量 operation 時不必重複解析。"""

    allowed: tuple[Route, ...]
    allow_all_paths: bool
    excluded: tuple[Route, ...]
    methods: frozenset[str]

    @classmethod
    def of(cls, scope: Scope) -> Self:
        return cls(
            allowed=tuple(parse_route(path) for path in scope.paths),
            allow_all_paths=scope.allow_all_paths,
            excluded=tuple(parse_route(path) for path in scope.excluded_paths),
            methods=frozenset(method.value for method in scope.methods),
        )

    def classify(self, *, method: str, path: str) -> IneligibleReason | None:
        """依序判斷：排除 → method → 允許的 path；都通過才回 None（在範圍內）。

        method 是大寫的 HTTP method；grant 不可能允許 TRACE，所以 TRACE 一定是
        METHOD_NOT_AUTHORIZED。path 不合語法時拋出 InvalidScopeError。
        """
        route = parse_route(path)
        if any(covers(pattern, route, lenient=True) for pattern in self.excluded):
            return IneligibleReason.PATH_EXCLUDED
        if method not in self.methods:
            return IneligibleReason.METHOD_NOT_AUTHORIZED
        if self.allow_all_paths or any(
            covers(pattern, route, lenient=False) for pattern in self.allowed
        ):
            return None
        return IneligibleReason.PATH_NOT_AUTHORIZED

    def classify_request(self, *, method: str, path: RequestPath) -> IneligibleReason | None:
        """實際請求的排除 → method → 允許；歧義排除回 PathAmbiguity。"""
        if any(_request_excluded(pattern, path) for pattern in self.excluded):
            return IneligibleReason.PATH_EXCLUDED
        if method not in self.methods:
            return IneligibleReason.METHOD_NOT_AUTHORIZED
        if self.allow_all_paths:
            if path.encoded:
                raise PathAmbiguity("no-route-parameter")
            return None
        if any(covers_request(pattern, path) for pattern in self.allowed):
            return None
        return IneligibleReason.PATH_NOT_AUTHORIZED
