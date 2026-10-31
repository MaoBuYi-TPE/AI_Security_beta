"""兩政策的固定語料與解析模型；探索反例不當成已證明安全。"""

import re

import pytest
from hypothesis import given
from hypothesis import strategies as st

from secscan.grants.domain.matching import IneligibleReason, ScopeRules
from secscan.grants.domain.request_paths import PathEncoding, parse_request_path
from secscan.guard.domain.requests import Reason, ambiguity_detail, scope_reason
from tests.guard_path_cases import PATH_CASES, GoldenCase
from tests.unit.grants.test_matching import _scope
from tests.url_models import Transform, apply_chain, express_segments

STRICT = PathEncoding.REJECT
ENCODED = PathEncoding.ROUTE_PARAMETERS
RULES = ScopeRules.of(_scope(paths=("/a/{id}",)))


@pytest.mark.parametrize("case", PATH_CASES, ids=lambda case: case.path)
def test_frozen_policy_corpus(case: GoldenCase) -> None:
    for encoding, reason, detail in (
        (STRICT, case.strict_reason, case.strict_detail),
        (ENCODED, case.encoded_reason, case.encoded_detail),
    ):
        assert scope_reason("GET", case.path, RULES, encoding) == reason
        assert ambiguity_detail("GET", case.path, RULES, encoding) == detail


def _legacy_path_reason(path: str) -> Reason | None:
    """凍結 T11 到 T16 語法的獨立 oracle，不呼叫新的請求解析器或匹配器。"""
    if len(path) > 512 or not path.startswith("/"):
        return Reason.PATH_AMBIGUOUS
    segments = path[1:].split("/")
    if segments[-1] == "":
        segments.pop()
    for segment in segments:
        if (
            segment in {"", ".", ".."}
            or re.fullmatch(r"[A-Za-z0-9._~!$&'()+,=:@-]+", segment) is None
        ):
            return Reason.PATH_AMBIGUOUS
    return (
        None
        if len(segments) == 2 and segments[0] == "a" and not path.endswith("/")
        else Reason.PATH_NOT_AUTHORIZED
    )


@given(st.text(alphabet="/abcXYZ19._~!$&'()+,=:@-%;{}\\\x00é ", max_size=550))
def test_strict_path_behavior_matches_the_frozen_legacy_oracle(path: str) -> None:
    assert scope_reason("GET", path, RULES, STRICT) is _legacy_path_reason(path)


@pytest.mark.parametrize(
    ("path", "chain", "expected"),
    [
        ("/a/%252F", (Transform.DECODE_UTF8, Transform.DECODE_UTF8), "/a//"),
        ("/a/a%20b", (Transform.DECODE_LATIN1,), "/a/a b"),
        ("/a/%C0%AF", (Transform.DECODE_UTF8,), None),
        ("/a/%C0%AF", (Transform.DECODE_LATIN1,), "/a/À¯"),
        ("/a/+..+", (Transform.PLUS_SPACE, Transform.TRIM_SEGMENTS, Transform.DOT_SEGMENTS), "/a/"),
        ("/a/..;/b", (Transform.STRIP_PARAMETERS, Transform.DOT_SEGMENTS), "/b"),
        (
            "/A\\b//c",
            (Transform.BACKSLASH, Transform.CASEFOLD, Transform.COLLAPSE_SLASHES),
            "/a/b/c",
        ),
        ("/a/admin.json/%27", (Transform.STRIP_EXTENSION, Transform.DECODE_UTF8), "/a/admin/'"),
    ],
)
def test_models_have_explicit_ordered_semantics(
    path: str,
    chain: tuple[Transform, ...],
    expected: str | None,
) -> None:
    assert apply_chain(path, chain) == expected


def test_express_routes_before_decoding_parameter_slashes() -> None:
    assert express_segments("/a/x%2Fy") == ("a", "x/y")
    assert apply_chain("/a/x%2Fy", (Transform.DECODE_UTF8,)) == "/a/x/y"
    assert express_segments("/a/%C0%AF") is None


def test_unsupported_extension_alias_counterexample_is_preserved() -> None:
    rules = ScopeRules.of(_scope(paths=("/a/{x}/{y}",), excluded=("/a/admin/{id}",)))
    raw = "/a/admin.json/%27"
    assert scope_reason("GET", raw, rules, ENCODED) is None
    transformed = apply_chain(raw, (Transform.STRIP_EXTENSION, Transform.DECODE_UTF8))
    assert transformed == "/a/admin/'"
    assert rules.classify(method="GET", path=transformed) is IneligibleReason.PATH_EXCLUDED


@given(
    st.permutations(
        (
            Transform.DECODE_UTF8,
            Transform.STRIP_EXTENSION,
            Transform.CASEFOLD,
            Transform.COLLAPSE_SLASHES,
        )
    )
)
def test_ordered_exploration_retains_the_known_alias_counterexample(chain: list[Transform]) -> None:
    rules = ScopeRules.of(_scope(paths=("/a/{x}/{y}",), excluded=("/a/admin/{id}",)))
    raw = "/a/admin.json/%27"
    assert scope_reason("GET", raw, rules, ENCODED) is None
    transformed = apply_chain(raw, chain)
    assert transformed == "/a/admin/'"
    assert rules.classify(method="GET", path=transformed) is IneligibleReason.PATH_EXCLUDED


@given(
    st.text(alphabet="abcXYZ09", min_size=1, max_size=15),
    st.sampled_from(tuple(" !\"$&'()+,:<=>@[]^`{|}")),
    st.lists(
        st.sampled_from((Transform.DECODE_UTF8, Transform.DECODE_LATIN1)), min_size=1, max_size=4
    ),
)
def test_accepted_parameters_keep_segment_boundaries_under_repeated_decoding(
    literal: str,
    character: str,
    chain: list[Transform],
) -> None:
    raw = f"/a/{literal}%{ord(character):02X}"
    assert scope_reason("GET", raw, RULES, ENCODED) is None
    path = parse_request_path(raw, encoding=ENCODED)
    transformed = apply_chain(raw, chain)
    assert transformed is not None
    assert transformed.split("/")[1:] == [segment.decoded for segment in path.segments]
    assert express_segments(raw) == tuple(segment.decoded for segment in path.segments)
