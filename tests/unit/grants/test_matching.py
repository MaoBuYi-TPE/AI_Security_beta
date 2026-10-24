"""route 層級的 path 與 method 比對（docs/DECISIONS.md §11.6）；純函式。

- pattern（grant 的 path）涵蓋 route（規格的 path）：段數相同；佔位涵蓋任何一段，literal 只涵蓋
  相同的 literal。允許要大小寫與結尾斜線都一致；排除不分大小寫、忽略結尾斜線；都不推論前綴。
- 判斷的先後：PATH_EXCLUDED → METHOD_NOT_AUTHORIZED → PATH_NOT_AUTHORIZED。
"""

import pytest
from hypothesis import find, given
from hypothesis import strategies as st

from secscan.grants.domain.matching import (
    IneligibleReason,
    Route,
    ScopeRules,
    covers,
    parse_route,
)
from secscan.grants.domain.scope import InvalidScopeError, Scope, build_scope
from secscan.targets.domain import parse_origin

TARGET = parse_origin("http://vampi-vuln:5000")
EXCLUDED = IneligibleReason.PATH_EXCLUDED
METHOD = IneligibleReason.METHOD_NOT_AUTHORIZED
PATH = IneligibleReason.PATH_NOT_AUTHORIZED


def _scope(
    *,
    paths: tuple[str, ...] = (),
    allow_all_paths: bool = False,
    excluded: tuple[str, ...] = (),
    methods: tuple[str, ...] = ("GET",),
) -> Scope:
    return build_scope(
        target_origin=TARGET,
        origins=["http://vampi-vuln:5000"],
        ips=["10.89.7.20"],
        paths=list(paths),
        allow_all_paths=allow_all_paths,
        excluded_paths=list(excluded),
        methods=list(methods),
    )


# --- route ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "segments", "trailing_slash"),
    [
        ("/", (), False),
        ("/users/v1", ("users", "v1"), False),
        ("/users/v1/", ("users", "v1"), True),
        ("/users/v1/{username}", ("users", "v1", None), False),
        ("/{a}/{b}/", (None, None), True),
    ],
)
def test_parse_route(path: str, segments: tuple[str | None, ...], trailing_slash: bool) -> None:
    assert parse_route(path) == Route(segments=segments, trailing_slash=trailing_slash)


def test_placeholder_names_do_not_matter() -> None:
    """只差在佔位名稱的兩個 route 是同一個（規格中不可並存）。"""
    assert parse_route("/users/{id}") == parse_route("/users/{name}")


@pytest.mark.parametrize("path", ["users", "/a//b", "/a/../b", "/a%2fb", "/{id}.json", "/a;b"])
def test_parse_route_uses_the_grant_path_syntax(path: str) -> None:
    with pytest.raises(InvalidScopeError):
        parse_route(path)


# --- covers -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "route", "strict", "lenient"),
    [
        ("/users/v1", "/users/v1", True, True),
        ("/users/v1/{username}", "/users/v1/{username}", True, True),
        # 佔位涵蓋 literal；literal 不涵蓋佔位（後者還包含其他 path）。
        ("/users/v1/{x}", "/users/v1/_debug", True, True),
        ("/users/v1/_debug", "/users/v1/{username}", False, False),
        # 大小寫：允許要一致，排除不分。
        ("/users/v1", "/Users/V1", False, True),
        ("/API/Logout", "/api/logout", False, True),
        # 結尾的斜線：允許要一致，排除忽略。
        ("/users/v1", "/users/v1/", False, True),
        ("/users/v1/", "/users/v1", False, True),
        # 段數不同就不涵蓋：不從前綴推論。
        ("/api/admin", "/api/admin/{id}", False, False),
        ("/api/admin", "/api/admin/users", False, False),
        ("/api/{x}", "/api/admin/users", False, False),
        ("/api/admin/users", "/api/admin", False, False),
        ("/", "/", True, True),
        ("/", "/users", False, False),
        ("/{x}", "/", False, False),
        # 不同的 literal。
        ("/api/admins", "/api/admin", False, False),
    ],
)
def test_covers(pattern: str, route: str, strict: bool, lenient: bool) -> None:
    assert covers(parse_route(pattern), parse_route(route), lenient=False) is strict
    assert covers(parse_route(pattern), parse_route(route), lenient=True) is lenient


_LITERALS = ("users", "Users", "v1", "_debug", "api", "API", "a")
_SEGMENTS = st.one_of(st.sampled_from(_LITERALS), st.just("{id}"))


@st.composite
def _paths(draw: st.DrawFn) -> str:
    segments = draw(st.lists(_SEGMENTS, max_size=4))
    trailing = bool(segments) and draw(st.booleans())
    return "/" + "/".join(segments) + ("/" if trailing else "")


@given(_paths())
def test_every_route_covers_itself(path: str) -> None:
    route = parse_route(path)

    assert covers(route, route, lenient=False)
    assert covers(route, route, lenient=True)


@given(_paths(), _paths())
def test_exclusion_is_at_least_as_wide_as_permission(pattern: str, route: str) -> None:
    if covers(parse_route(pattern), parse_route(route), lenient=False):
        assert covers(parse_route(pattern), parse_route(route), lenient=True)


@given(_paths(), _paths(), st.integers(min_value=0, max_value=3), st.booleans())
def test_placeholders_never_narrow_a_pattern(
    pattern: str, route: str, position: int, lenient: bool
) -> None:
    """把 pattern 的某一段 literal 換成佔位，涵蓋的範圍不會變小。"""
    original = parse_route(pattern)
    if position >= len(original.segments):
        return
    segments = list(original.segments)
    segments[position] = None
    widened = Route(segments=tuple(segments), trailing_slash=original.trailing_slash)

    if covers(original, parse_route(route), lenient=lenient):
        assert covers(widened, parse_route(route), lenient=lenient)


@given(_paths(), _paths())
def test_exclusion_ignores_case(pattern: str, route: str) -> None:
    expected = covers(parse_route(pattern), parse_route(route), lenient=True)

    assert covers(parse_route(pattern.upper()), parse_route(route.lower()), lenient=True) is (
        expected
    )


@pytest.mark.parametrize(("lenient", "expected"), [(False, True), (False, False), (True, False)])
def test_path_strategy_reaches_both_outcomes(lenient: bool, expected: bool) -> None:
    """上面的性質不能只測到其中一種結果（找不到時 find 會拋出 NoSuchExample）。"""
    find(
        st.tuples(_paths(), _paths()),
        lambda pair: (
            covers(parse_route(pair[0]), parse_route(pair[1]), lenient=lenient) is expected
        ),
    )


# --- 判斷 -------------------------------------------------------------------------------------


def test_vampi_like_scope() -> None:
    rules = ScopeRules.of(
        _scope(
            paths=("/users/v1", "/users/v1/{username}", "/books/v1/{book_title}"),
            excluded=("/users/v1/_debug",),
            methods=("GET", "HEAD"),
        )
    )

    assert rules.classify(method="GET", path="/users/v1") is None
    assert rules.classify(method="GET", path="/users/v1/{username}") is None
    assert rules.classify(method="HEAD", path="/books/v1/{book_title}") is None
    assert rules.classify(method="GET", path="/users/v1/_debug") is EXCLUDED
    assert rules.classify(method="DELETE", path="/users/v1/{username}") is METHOD
    assert rules.classify(method="GET", path="/books/v1") is PATH
    assert rules.classify(method="GET", path="/me") is PATH


def test_exclusion_is_reported_before_the_method() -> None:
    rules = ScopeRules.of(_scope(paths=("/a",), excluded=("/b",), methods=("GET",)))

    assert rules.classify(method="POST", path="/b") is EXCLUDED
    assert rules.classify(method="POST", path="/c") is METHOD


def test_exclusion_wins_over_allow_all_paths() -> None:
    rules = ScopeRules.of(_scope(allow_all_paths=True, excluded=("/createdb",)))

    assert rules.classify(method="GET", path="/createdb") is EXCLUDED
    assert rules.classify(method="GET", path="/CreateDB/") is EXCLUDED
    assert rules.classify(method="GET", path="/anything/{id}") is None


def test_trace_can_never_be_authorized() -> None:
    rules = ScopeRules.of(
        _scope(
            allow_all_paths=True,
            methods=("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"),
        )
    )

    assert rules.classify(method="TRACE", path="/users") is METHOD
    assert rules.classify(method="get", path="/users") is METHOD


def test_allowed_paths_are_compared_strictly() -> None:
    rules = ScopeRules.of(_scope(paths=("/users/v1",)))

    assert rules.classify(method="GET", path="/users/v1/") is PATH
    assert rules.classify(method="GET", path="/Users/v1") is PATH
    assert rules.classify(method="GET", path="/users/v1/{id}") is PATH


def test_classify_rejects_paths_outside_the_syntax() -> None:
    rules = ScopeRules.of(_scope(paths=("/users",)))

    with pytest.raises(InvalidScopeError):
        rules.classify(method="GET", path="/users/%2e%2e")
