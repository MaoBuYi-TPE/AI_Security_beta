"""T33：實際請求與宣告路由分離；固定兩個政策的安全邊界。"""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from secscan.grants.domain.matching import IneligibleReason, ScopeRules, covers_request, parse_route
from secscan.grants.domain.request_paths import (
    PathAmbiguity,
    PathEncoding,
    canonical_path,
    parse_request_path,
)
from tests.unit.grants.test_matching import _scope

STRICT = PathEncoding.REJECT
ENCODED = PathEncoding.ROUTE_PARAMETERS
# 獨立列出白名單，避免測試隨實作常數一起變寬。
ENCODABLE = " !\"$&'()+,:<=>@[]^`{|}"


@pytest.mark.parametrize("character", ENCODABLE)
def test_each_permitted_encoded_byte_remains_parameter_data(character: str) -> None:
    raw = f"/users/name%{ord(character):02x}tail"
    request = parse_request_path(raw, encoding=ENCODED)
    assert request.raw == raw
    assert request.encoded
    assert request.segments[1].decoded == f"name{character}tail"
    assert covers_request(parse_route("/users/{name}"), request)
    assert not covers_request(parse_route("/users/name"), request)
    with pytest.raises(PathAmbiguity, match="percent-encoding"):
        parse_request_path(raw, encoding=STRICT)


@pytest.mark.parametrize(
    ("path", "detail"),
    [
        ("x", "syntax"),
        ("//a", "syntax"),
        ("/a//", "syntax"),
        ("/a/../b", "syntax"),
        ("/a/./b", "syntax"),
        ("/a/{x}", "syntax"),
        ("/a/é", "syntax"),
        ("/a/a b", "syntax"),
        ("/a/a;b", "syntax"),
        ("/a/a\\b", "syntax"),
        ("/a/?x", "syntax"),
        ("/a/#x", "syntax"),
        ("/" + "a" * 512, "syntax"),
        ("/a/%", "invalid-percent"),
        ("/a/%2", "invalid-percent"),
        ("/a/%G1", "invalid-percent"),
        ("/a/%+2", "invalid-percent"),
        ("/a/%-1", "invalid-percent"),
        ("/a/%u002e", "invalid-percent"),
        ("/a/%%27", "invalid-percent"),
        ("/a/%2f", "encoded-separator"),
        ("/a/%5C", "encoded-separator"),
        ("/a/%3F", "encoded-separator"),
        ("/a/%23", "encoded-separator"),
        ("/a/%3B", "encoded-separator"),
        ("/a/%252e", "double-encoding"),
        ("/a/%252f", "double-encoding"),
        ("/a/%2527", "double-encoding"),
        ("/a/%00", "encoded-control"),
        ("/a/%0D%0A", "encoded-control"),
        ("/a/%7f", "encoded-control"),
        ("/a/%C0%AF", "encoded-control"),
        ("/a/%E2%80%AE", "encoded-control"),
        ("/a/%41", "non-canonical"),
        ("/a/%7E", "non-canonical"),
        ("/a/%2e", "non-canonical"),
        ("/a/.%2e", "non-canonical"),
        ("/a/%2a", "encoded-wildcard"),
        ("/a/..+", "dot-segment"),
        ("/a/+", "dot-segment"),
        ("/a/%20", "dot-segment"),
        ("/a/.%20%2B", "dot-segment"),
    ],
)
def test_ambiguous_syntax_has_stable_non_sensitive_detail(path: str, detail: str) -> None:
    with pytest.raises(PathAmbiguity) as error:
        parse_request_path(path, encoding=ENCODED)
    assert error.value.detail == detail
    assert str(error.value) == detail


@pytest.mark.parametrize("path", ["/", "/a", "/a/", "/a/b", "/a/.hidden", "/a/name+part"])
def test_normal_paths_keep_shape_and_data(path: str) -> None:
    strict = parse_request_path(path, encoding=STRICT)
    experimental = parse_request_path(path, encoding=ENCODED)
    assert strict == experimental
    assert not strict.encoded
    assert strict.trailing_slash == (path != "/" and path.endswith("/"))


def test_strict_keeps_legacy_plus_dot_segment_behavior() -> None:
    assert parse_request_path("/a/..+", encoding=STRICT).segments[-1].decoded == "..+"


def test_encoded_braces_are_never_a_declaration_placeholder() -> None:
    path = parse_request_path("/a/%7Bx%7D", encoding=ENCODED)
    assert path.segments[1].decoded == "{x}"
    assert path.segments[1].encoded
    assert covers_request(parse_route("/a/{id}"), path)
    assert not covers_request(parse_route("/a/x"), path)


@pytest.mark.parametrize("character", "!$&'()+,=:@")
@pytest.mark.parametrize("placement", ["final-literal", "literal-before-parameter"])
def test_encoding_cannot_stand_in_for_an_equal_authorized_literal(
    character: str, placement: str
) -> None:
    """突變測試的缺口：解碼值即使完全等於 literal，也沒有參數授權。"""
    if placement == "final-literal":
        declaration = plain = f"/a/name{character}"
        encoded = f"/a/name%{ord(character):02X}"
    else:
        declaration = f"/a{character}/{{id}}"
        plain = f"/a{character}/x"
        encoded = f"/a%{ord(character):02X}/x"
    rules = ScopeRules.of(_scope(paths=(declaration,)))
    request = parse_request_path(encoded, encoding=ENCODED)

    assert "/" + "/".join(segment.decoded for segment in request.segments) == plain
    assert not covers_request(parse_route(declaration), request)
    assert (
        rules.classify_request(method="GET", path=request) is IneligibleReason.PATH_NOT_AUTHORIZED
    )
    assert (
        rules.classify_request(method="GET", path=parse_request_path(plain, encoding=ENCODED))
        is None
    )


@pytest.mark.parametrize(
    ("allowed", "excluded", "path", "reason", "detail"),
    [
        (("/a/{x}",), (), "/a/name%27", None, None),
        (("/a/name",), (), "/a/name%27", IneligibleReason.PATH_NOT_AUTHORIZED, None),
        (("/a/{x}",), (), "/a/name%27/", IneligibleReason.PATH_NOT_AUTHORIZED, None),
        (("/a/{x}",), (), "/A/name%27", IneligibleReason.PATH_NOT_AUTHORIZED, None),
        (("/a/{x}",), (), "/a/name%27/b", IneligibleReason.PATH_NOT_AUTHORIZED, None),
        (("/a/{x}/{y}",), ("/a/b/c",), "/a/b%20/c%20", None, "exclusion-overlap"),
        (("/a/{x}",), ("/a/admin",), "/a/name%27", None, "exclusion-overlap"),
        (("/a/{x}",), ("/A/{id}/",), "/a/name%27", IneligibleReason.PATH_EXCLUDED, None),
        (("/a/{x}",), ("/b/admin",), "/a/name%27", None, None),
        (("/a/{x}/c", "/a/b/{y}"), (), "/a/b%27/c%27", IneligibleReason.PATH_NOT_AUTHORIZED, None),
        ((), (), "/a/name%27", None, "no-route-parameter"),
    ],
)
def test_request_authorization_and_whole_route_exclusions(
    allowed: tuple[str, ...],
    excluded: tuple[str, ...],
    path: str,
    reason: IneligibleReason | None,
    detail: str | None,
) -> None:
    rules = ScopeRules.of(_scope(paths=allowed, allow_all_paths=not allowed, excluded=excluded))
    request = parse_request_path(path, encoding=ENCODED)
    if detail is not None:
        with pytest.raises(PathAmbiguity, match=detail):
            rules.classify_request(method="GET", path=request)
    else:
        assert rules.classify_request(method="GET", path=request) is reason


def test_exclusion_precedes_method_and_method_precedes_permission() -> None:
    rules = ScopeRules.of(_scope(paths=("/a/{x}",), excluded=("/a/admin",)))
    with pytest.raises(PathAmbiguity, match="exclusion-overlap"):
        rules.classify_request(
            method="DELETE", path=parse_request_path("/a/x%27", encoding=ENCODED)
        )
    assert (
        rules.classify_request(
            method="DELETE", path=parse_request_path("/b/x%27", encoding=ENCODED)
        )
        is IneligibleReason.METHOD_NOT_AUTHORIZED
    )


def test_canonical_path_only_changes_hex_case() -> None:
    assert canonical_path("/a/Raw+Name%3c%7bx%7d") == "/a/Raw+Name%3C%7Bx%7D"
    assert canonical_path("/a/%20") == "/a/%20"
    assert canonical_path("/a/%G1/%") == "/a/%G1/%"


@given(st.sampled_from(tuple(ENCODABLE)), st.text(alphabet="abcXYZ09_", min_size=1, max_size=24))
def test_hex_case_and_parameter_replacement_invariants(character: str, literal: str) -> None:
    rules = ScopeRules.of(_scope(paths=("/a/{id}",)))
    raw = f"/a/{literal}%{ord(character):02X}"
    assert (
        rules.classify_request(method="GET", path=parse_request_path(raw, encoding=ENCODED)) is None
    )
    lower = raw[:-2] + raw[-2:].lower()
    assert (
        rules.classify_request(method="GET", path=parse_request_path(lower, encoding=ENCODED))
        is None
    )
    assert (
        rules.classify_request(
            method="GET", path=parse_request_path(f"/a/{literal}", encoding=STRICT)
        )
        is None
    )
