"""保守的 fingerprint 與 route 樣板化（T19；docs/DECISIONS.md §25.6）。

每個身分欄位都敏感（改任何一個就是另一個 finding）；fingerprint 只由這些欄位決定。
"""

import dataclasses
import json
from uuid import UUID

from hypothesis import given
from hypothesis import strategies as st

from secscan.findings.domain.fingerprint import (
    FingerprintInputs,
    Position,
    RouteIndex,
    RouteSource,
    fingerprint,
    position,
)
from secscan.findings.domain.taxonomy import FINGERPRINT_VERSION, FindingKind
from secscan.grants.domain.matching import parse_route
from secscan.scans.domain.coverage import FrozenOperation, most_specific, operation_routes

TARGET = UUID("11111111-2222-4333-8444-555555555555")
BASE = FingerprintInputs(
    target_id=TARGET,
    kind=FindingKind.SECURITY,
    rule_group="zap-sql-injection",
    method="GET",
    route="/search",
    route_templated=False,
    parameter_location="query",
    parameter_name="q",
    auth_role="anonymous",
    auth_verified=True,
    resource=None,
)

_texts = st.text(alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x2FFF), max_size=40)
_changes = st.one_of(
    st.builds(lambda value: {"target_id": value}, st.uuids()),
    st.builds(lambda value: {"kind": value}, st.sampled_from(FindingKind)),
    st.builds(lambda value: {"rule_group": value}, _texts),
    st.builds(lambda value: {"method": value}, st.sampled_from(["POST", "PUT", "get", "HEAD"])),
    st.builds(lambda value: {"route": value}, _texts),
    st.builds(lambda value: {"route_templated": value}, st.booleans()),
    st.builds(lambda value: {"parameter_location": value}, st.none() | _texts),
    st.builds(lambda value: {"parameter_name": value}, st.none() | _texts),
    st.builds(lambda value: {"auth_role": value}, _texts),
    st.builds(lambda value: {"auth_verified": value}, st.booleans()),
    st.builds(lambda value: {"resource": value}, st.none() | _texts),
)


def test_the_fingerprint_is_the_sha256_of_the_canonical_document() -> None:
    document = BASE.document()

    assert document["v"] == FINGERPRINT_VERSION
    assert document["auth"] == {"role": "anonymous", "verified": True}
    assert len(fingerprint(BASE)) == 64
    assert fingerprint(BASE) == fingerprint(dataclasses.replace(BASE))
    # 欄位的順序不影響（canonical JSON）。
    assert json.dumps(document, sort_keys=True) == json.dumps(
        dict(reversed(document.items())), sort_keys=True
    )


@given(_changes)
def test_every_identity_field_changes_the_fingerprint(change: dict[str, object]) -> None:
    changed = dataclasses.replace(BASE, **change)  # type: ignore[arg-type]

    if changed == BASE:
        assert fingerprint(changed) == fingerprint(BASE)
    else:
        assert fingerprint(changed) != fingerprint(BASE)


def test_unverified_identity_is_a_different_finding() -> None:
    """T16 的交接：身分失效的 run 不能併入已驗證身分的 finding。"""
    verified = dataclasses.replace(BASE, auth_role="standard_user", auth_verified=True)
    unverified = dataclasses.replace(verified, auth_verified=False)

    assert fingerprint(verified) != fingerprint(unverified)


def test_a_literal_path_with_braces_is_not_the_template() -> None:
    """安全審查：字面的 `/orders/{id}`（工具保留大括號）不能併入整個樣板層級的 finding。"""
    literal = dataclasses.replace(BASE, route="/api/orders/{id}", route_templated=False)
    template = dataclasses.replace(literal, route_templated=True)

    assert fingerprint(literal) != fingerprint(template)
    assert Position("/api/orders/{id}", RouteSource.LITERAL).templated is False
    assert Position("/api/orders/{id}", RouteSource.OPENAPI).templated is True
    # 沒有佔位符的 operation 和字面的 path 是同一個（有沒有規格都能合併）。
    assert Position("/api/users", RouteSource.OPENAPI).templated is False


def test_null_and_empty_parameters_are_different() -> None:
    assert fingerprint(dataclasses.replace(BASE, parameter_name=None)) != fingerprint(
        dataclasses.replace(BASE, parameter_name="")
    )


# --- route 樣板化 ----------------------------------------------------------------------------

OPERATIONS = (
    FrozenOperation(0, "GET", "/api/orders/{id}"),
    FrozenOperation(1, "GET", "/api/orders/special"),
    FrozenOperation(2, "GET", "/api/users"),
    FrozenOperation(3, "POST", "/api/users"),
    FrozenOperation(4, "GET", "/api/{kind}/1"),
    FrozenOperation(5, "GET", "/api/items/{a}"),
    FrozenOperation(6, "GET", "/api/{b}/x"),
)
ROUTES = RouteIndex.of(operation_routes(OPERATIONS))


def test_a_single_most_specific_operation_gives_its_template() -> None:
    assert position(ROUTES, "GET", "/api/orders/1001") == Position(
        "/api/orders/{id}", RouteSource.OPENAPI
    )
    # 最具體的優先：/special 不算進 {id}。
    assert position(ROUTES, "GET", "/api/orders/special") == Position(
        "/api/orders/special", RouteSource.OPENAPI
    )
    assert position(ROUTES, "POST", "/api/users") == Position("/api/users", RouteSource.OPENAPI)


def test_no_match_or_a_tie_keeps_the_literal_path() -> None:
    # method 不同、沒有 operation、或兩個一樣具體（不猜是哪一個）。
    assert position(ROUTES, "DELETE", "/api/users") == Position("/api/users", RouteSource.LITERAL)
    assert position(ROUTES, "GET", "/") == Position("/", RouteSource.LITERAL)
    assert position(ROUTES, "GET", "/api/items/x") == Position("/api/items/x", RouteSource.LITERAL)


def test_paths_the_grant_syntax_rejects_stay_literal() -> None:
    for path in ("/api/orders/%27", "/api//orders", "/api/orders/{id}", "/api/orders/a}"):
        assert position(ROUTES, "GET", path) == Position(path, RouteSource.LITERAL)


def test_without_a_spec_every_path_is_literal() -> None:
    empty = RouteIndex.of(operation_routes(()))

    assert position(empty, "GET", "/api/orders/1") == Position("/api/orders/1", RouteSource.LITERAL)


def test_the_index_gives_the_same_matches_as_a_full_scan() -> None:
    """分組只是加速：和直接比對全部的 operation 結果相同。"""
    paths = ["/api/orders/1", "/api/orders/special", "/api/users", "/api/x/1", "/api/items/x", "/"]
    full = operation_routes(OPERATIONS)
    for method in ("GET", "POST", "DELETE"):
        for path in paths:
            parsed = parse_route(path)
            assert ROUTES.candidates(method, parsed) == tuple(
                (operation, route)
                for operation, route in full
                if operation.method == method
                and len(route.segments) == len(parsed.segments)
                and route.trailing_slash == parsed.trailing_slash
            )
            assert most_specific(ROUTES.candidates(method, parsed), method, parsed) == (
                most_specific(full, method, parsed)
            )


def test_trailing_slashes_and_case_are_not_normalized() -> None:
    assert position(ROUTES, "GET", "/api/users/").source is RouteSource.LITERAL
    assert position(ROUTES, "GET", "/API/users").source is RouteSource.LITERAL


_segment = st.sampled_from(["a", "b", "items", "{id}", "{x}", "1"])
_route = st.builds(
    lambda parts, slash: "/" + "/".join(parts) + ("/" if slash and parts else ""),
    st.lists(_segment, max_size=4),
    st.booleans(),
)
_concrete = st.builds(
    lambda parts, slash: "/" + "/".join(parts) + ("/" if slash and parts else ""),
    st.lists(st.sampled_from(["a", "b", "items", "1", "2"]), max_size=4),
    st.booleans(),
)


@given(
    st.lists(st.tuples(st.sampled_from(["GET", "POST"]), _route), max_size=12, unique=True),
    st.sampled_from(["GET", "POST"]),
    _concrete,
)
def test_the_index_never_changes_the_match(
    shapes: list[tuple[str, str]], method: str, path: str
) -> None:
    """分組（method、段數、結尾斜線）只是加速：任何 operation 與 path 的結果都和全量比對相同。"""
    operations = tuple(
        FrozenOperation(ordinal, operation_method, route)
        for ordinal, (operation_method, route) in enumerate(shapes)
    )
    full = operation_routes(operations)
    parsed = parse_route(path)

    assert most_specific(RouteIndex.of(full).candidates(method, parsed), method, parsed) == (
        most_specific(full, method, parsed)
    )
