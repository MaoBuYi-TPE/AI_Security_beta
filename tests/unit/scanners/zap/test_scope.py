"""grant 的範圍 → ZAP context 的 includePaths／excludePaths（docs/DECISIONS.md §18.4）。

ZAP 以 Java 的 regex 完整比對整個 URL。這裡以 Python 的 re 對照：英數字以外的字元一律以反斜線
跳脫，兩種 regex 都當成字元本身；佔位與 query 只用兩者語意相同的語法。性質測試確認和 guard 的
covers() 判斷相同（允許：段數、大小寫與結尾的斜線都一致；排除：不分大小寫、忽略結尾的斜線）。
"""

import re
from ipaddress import IPv4Address

from hypothesis import given
from hypothesis import strategies as st

from secscan.grants.domain.matching import covers, parse_route
from secscan.grants.domain.scope import HttpMethod, Scope
from secscan.scanners.domain.zap.scope import ContextPaths, context_paths, quote
from secscan.targets.domain import Origin, parse_origin

ORIGIN = parse_origin("http://lab-web:3000")


def _scope(
    paths: tuple[str, ...] = (),
    *,
    excluded: tuple[str, ...] = (),
    allow_all: bool = False,
    origin: Origin = ORIGIN,
) -> Scope:
    return Scope(
        origins=(origin,),
        ips=(IPv4Address("10.89.7.20"),),
        paths=paths,
        allow_all_paths=allow_all,
        excluded_paths=excluded,
        methods=(HttpMethod.GET,),
    )


def _matches(patterns: tuple[str, ...], url: str) -> bool:
    return any(re.fullmatch(pattern, url) is not None for pattern in patterns)


def _included(paths: ContextPaths, url: str) -> bool:
    """ZAP 的 context：每個 url 都成為 `url.*` 的 include（AF 的 ContextWrapper，不跳脫），再加上
    includePaths；符合任何一條 exclude 就不在 context 中。
    """
    includes = (*(f"{context_url}.*" for context_url in paths.urls), *paths.include)
    return _matches(includes, url) and not _matches(paths.exclude, url)


def test_a_literal_path_matches_exactly_with_any_query() -> None:
    paths = context_paths(ORIGIN, _scope(("/api/items",)))

    assert _included(paths, "http://lab-web:3000/api/items")
    assert _included(paths, "http://lab-web:3000/api/items?page=2&q=%27")
    assert not _included(paths, "http://lab-web:3000/api/items/7")
    assert not _included(paths, "http://lab-web:3000/api/items/")
    assert not _included(paths, "http://lab-web:3000/API/items")
    assert not _included(paths, "http://lab-web:3000/api")
    assert not _included(paths, "http://other:3000/api/items")
    assert not _included(paths, "http://lab-web:3001/api/items")


def test_the_context_url_does_not_widen_the_scope() -> None:
    # AF 把 urls 的每一個都加成 `url.*`：沒有另外排除的話，整個 origin 都會在 context 中。
    paths = context_paths(ORIGIN, _scope(("/api/items",)))

    assert paths.urls == ("http://lab-web:3000/",)
    assert not _included(paths, "http://lab-web:3000/")
    assert not _included(paths, "http://lab-web:3000/other")


def test_characters_are_literal_not_regex() -> None:
    paths = context_paths(ORIGIN, _scope(("/a.b/c+d",)))

    assert _included(paths, "http://lab-web:3000/a.b/c+d")
    assert not _included(paths, "http://lab-web:3000/aXb/c+d")
    assert not _included(paths, "http://lab-web:3000/a.b/ccd")


def test_a_placeholder_covers_one_segment() -> None:
    paths = context_paths(ORIGIN, _scope(("/api/items/{id}",)))

    assert _included(paths, "http://lab-web:3000/api/items/7")
    assert _included(paths, "http://lab-web:3000/api/items/abc?x=1")
    assert not _included(paths, "http://lab-web:3000/api/items/7/edit")
    assert not _included(paths, "http://lab-web:3000/api/items/")


def test_allow_all_paths_covers_the_whole_origin_only() -> None:
    paths = context_paths(ORIGIN, _scope(allow_all=True))

    assert _included(paths, "http://lab-web:3000/")
    assert _included(paths, "http://lab-web:3000/anything/at/all?x=1")
    assert not _included(paths, "http://lab-web:30001/")
    assert not _included(paths, "http://lab-web.evil:3000/")


def test_excluded_paths_ignore_case_and_the_trailing_slash_but_not_subpaths() -> None:
    paths = context_paths(ORIGIN, _scope(allow_all=True, excluded=("/api/admin",)))

    assert not _included(paths, "http://lab-web:3000/api/admin")
    assert not _included(paths, "http://lab-web:3000/API/Admin/")
    assert not _included(paths, "http://lab-web:3000/api/admin?x=1")
    assert _included(paths, "http://lab-web:3000/api/admin/7")


def test_the_default_port_is_omitted_like_zap_writes_urls() -> None:
    origin = parse_origin("http://lab-web")

    paths = context_paths(origin, _scope(("/",), origin=origin))

    assert _included(paths, "http://lab-web/")
    assert not _included(paths, "http://lab-web:80/")


def test_quote_escapes_every_non_alphanumeric_character() -> None:
    assert quote("a.b-C_9~$") == r"a\.b\-C\_9\~\$"
    assert re.fullmatch(quote("!$&'()+,=:@~._-"), "!$&'()+,=:@~._-") is not None


def test_no_pattern_contains_a_plan_variable() -> None:
    # grant 的 path 可以有 $，但跳脫之後不會出現 AF 的變數寫法。
    paths = context_paths(ORIGIN, _scope(("/$", "/a$/{id}"), excluded=("/$x",)))

    assert all("${" not in pattern for pattern in (*paths.include, *paths.exclude))


# --- 和 guard 的 covers() 對照 -------------------------------------------------------------------

_SEGMENTS = ("a", "B", "b", "x.y", "$", "~1", "c+d", "@:=")
_literal = st.sampled_from(_SEGMENTS)
_pattern_segment = st.one_of(_literal, st.just("{id}"))


def _path(segments: st.SearchStrategy[str]) -> st.SearchStrategy[str]:
    return st.builds(
        lambda parts, slash: "/" + "/".join(parts) + ("/" if slash and parts else ""),
        st.lists(segments, max_size=3),
        st.booleans(),
    )


@given(
    allowed=st.lists(_path(_pattern_segment), min_size=1, max_size=4, unique=True),
    excluded=st.lists(_path(_pattern_segment), max_size=3, unique=True),
    request=_path(_literal),
    query=st.sampled_from(("", "?q=1", "?a=%27&b")),
)
def test_matches_the_guard_rules(
    allowed: list[str], excluded: list[str], request: str, query: str
) -> None:
    excluded = [path for path in excluded if path not in allowed]
    paths = context_paths(ORIGIN, _scope(tuple(allowed), excluded=tuple(excluded)))
    route = parse_route(request)
    url = f"http://lab-web:3000{request}{query}"

    allowed_by_guard = any(covers(parse_route(path), route, lenient=False) for path in allowed)
    excluded_by_guard = any(covers(parse_route(path), route, lenient=True) for path in excluded)

    assert _included(paths, url) == (allowed_by_guard and not excluded_by_guard)
    assert not _included(paths, f"http://other:3000{request}{query}")


def test_a_trailing_line_break_does_not_slip_past_the_outside_exclusion() -> None:
    """審查 L3：Java 與 Python 的 `$` 都會在結尾的換行之前成立；改用「後面沒有任何字元」。

    以 DOTALL 比對（`.*` 也吃換行）：允許的 URL 後面接換行，仍然被範圍外的排除擋下。
    """
    paths = context_paths(ORIGIN, _scope(("/api/items",)))
    outside = paths.exclude[-1]

    assert re.fullmatch(outside, "http://lab-web:3000/api/items", re.DOTALL) is None
    assert re.fullmatch(outside, "http://lab-web:3000/api/items\n", re.DOTALL) is not None
