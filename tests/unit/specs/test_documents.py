"""上傳的規格轉成 JSON 值（docs/DECISIONS.md §11.2）；純函式，不做任何 I/O。

每一類拒絕的情形至少一例，並確認錯誤訊息只有原因與位置、不含輸入的值。
"""

import json
from collections.abc import Callable, Iterator
from typing import Any

import pytest
import yaml
from hypothesis import given
from hypothesis import strategies as st

from secscan.core.json_types import JsonValue
from secscan.specs.domain import documents
from secscan.specs.domain.documents import (
    DEFAULT_LIMITS,
    MAX_INT_DIGITS,
    DocumentLimits,
    InvalidSpecError,
    SpecFormat,
    SpecProblem,
    parse_document,
    pointer_text,
)

JSON, YAML = SpecFormat.JSON, SpecFormat.YAML
INVALID, UNSUPPORTED, TOO_LARGE = (
    SpecProblem.INVALID,
    SpecProblem.UNSUPPORTED,
    SpecProblem.TOO_LARGE,
)
CANARY = "canary-value-0042"
SMALL = DocumentLimits(max_bytes=4096, max_depth=4, max_nodes=10)


def _yaml(text: str, limits: DocumentLimits = DEFAULT_LIMITS) -> JsonValue:
    return parse_document(text.encode(), YAML, limits=limits)


def _json(text: str, limits: DocumentLimits = DEFAULT_LIMITS) -> JsonValue:
    return parse_document(text.encode(), JSON, limits=limits)


def _rejected(parse: Callable[[], object]) -> InvalidSpecError:
    with pytest.raises(InvalidSpecError) as raised:
        parse()
    return raised.value


def test_default_limits_match_the_decisions() -> None:
    expected = DocumentLimits(max_bytes=1024 * 1024, max_depth=64, max_nodes=100_000)
    assert expected == DEFAULT_LIMITS
    assert MAX_INT_DIGITS == 4300


# --- 共同規則 ---------------------------------------------------------------------------------


@pytest.mark.parametrize("spec_format", list(SpecFormat))
def test_size_limit_is_checked_before_parsing(spec_format: SpecFormat) -> None:
    at_limit = b'{"a": "' + b"x" * (SMALL.max_bytes - 9) + b'"}'
    assert len(at_limit) == SMALL.max_bytes

    assert parse_document(at_limit, spec_format, limits=SMALL) == {"a": "x" * (SMALL.max_bytes - 9)}
    error = _rejected(lambda: parse_document(at_limit + b" ", spec_format, limits=SMALL))
    assert error.problem is TOO_LARGE


@pytest.mark.parametrize("spec_format", list(SpecFormat))
@pytest.mark.parametrize(
    "content",
    [b"", b"\xef\xbb\xbf{}", b'{"a": "\xff"}', b'{"a": "\xed\xa0\x80"}', b"\xff\xfe{\x00}\x00"],
    ids=["empty", "bom", "invalid-utf8", "encoded-surrogate", "utf16"],
)
def test_content_must_be_utf8_without_bom(spec_format: SpecFormat, content: bytes) -> None:
    assert _rejected(lambda: parse_document(content, spec_format)).problem is INVALID


@pytest.mark.parametrize("spec_format", list(SpecFormat))
@pytest.mark.parametrize("text", ["[]", '"x"', "1", "null"])
def test_top_level_must_be_an_object(spec_format: SpecFormat, text: str) -> None:
    assert _rejected(lambda: parse_document(text.encode(), spec_format)).problem is INVALID


@pytest.mark.parametrize("spec_format", list(SpecFormat))
def test_depth_limit(spec_format: SpecFormat) -> None:
    def nested(depth: int) -> bytes:
        return ('{"a": ' * depth + "1" + "}" * depth).encode()

    assert parse_document(nested(SMALL.max_depth), spec_format, limits=SMALL)
    error = _rejected(
        lambda: parse_document(nested(SMALL.max_depth + 1), spec_format, limits=SMALL)
    )
    assert error.problem is INVALID
    assert "層" in error.message


@pytest.mark.parametrize("spec_format", list(SpecFormat))
def test_node_limit_counts_keys_values_and_collections(spec_format: SpecFormat) -> None:
    def items(count: int) -> bytes:
        # 最外層物件、key "a"、陣列，再加上 count 個元素。
        return ('{"a": [' + ", ".join(["0"] * count) + "]}").encode()

    limit = SMALL.max_nodes
    assert parse_document(items(limit - 3), spec_format, limits=SMALL)
    error = _rejected(lambda: parse_document(items(limit - 2), spec_format, limits=SMALL))
    assert error.problem is INVALID
    assert "節點" in error.message


def test_default_depth_limit_is_enforced_without_recursion() -> None:
    """很深的輸入在超過上限時就停下，不依賴 RecursionError。"""
    deep = "[" * 200_000 + "]" * 200_000
    content = f'{{"a": {deep}}}'.encode()
    for spec_format in SpecFormat:
        with pytest.raises(InvalidSpecError) as raised:
            parse_document(content, spec_format)
        assert raised.value.problem is INVALID


@pytest.mark.parametrize("spec_format", list(SpecFormat))
@pytest.mark.parametrize(
    "text",
    ['{"a": "x\\u0000y"}', '{"x\\u0000": 1}', '{"a": "\\udc00"}', '{"a": "\\ud83d"}'],
    ids=["nul-value", "nul-key", "lone-low-surrogate", "lone-high-surrogate"],
)
def test_strings_must_be_encodable_and_free_of_nul(spec_format: SpecFormat, text: str) -> None:
    error = _rejected(lambda: parse_document(text.encode(), spec_format))
    assert error.problem is INVALID
    assert "#/" in error.message


@pytest.mark.parametrize("spec_format", list(SpecFormat))
def test_integers_are_limited_to_python_digits(spec_format: SpecFormat) -> None:
    largest = "9" * MAX_INT_DIGITS
    assert parse_document(f'{{"a": {largest}}}'.encode(), spec_format) == {"a": int(largest)}
    too_long = "1" + "0" * MAX_INT_DIGITS
    error = _rejected(lambda: parse_document(f'{{"a": {too_long}}}'.encode(), spec_format))
    assert error.problem is INVALID


def test_huge_hexadecimal_yaml_integers_are_rejected() -> None:
    """0x 不受 Python 的位數上限限制，但轉成十進位輸出時會。"""
    error = _rejected(lambda: _yaml("a: 0x" + "f" * 4000))
    assert error.problem is INVALID


@pytest.mark.parametrize("spec_format", list(SpecFormat))
def test_duplicate_keys_are_rejected(spec_format: SpecFormat) -> None:
    text = '{"paths": {"a": 1, "a": 2}}'
    error = _rejected(lambda: parse_document(text.encode(), spec_format))
    assert error.problem is INVALID


# --- JSON ------------------------------------------------------------------------------------


def test_json_values() -> None:
    text = '{"s": "é😀\\u00e9\\ud83d\\ude00", "i": -12, "f": 1.5e3, "b": [true, false, null]}'

    assert _json(text) == {"s": "é😀é😀", "i": -12, "f": 1500.0, "b": [True, False, None]}


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity", "1e400", "-1e400"])
def test_json_numbers_must_be_finite(constant: str) -> None:
    assert _rejected(lambda: _json(f'{{"a": {constant}}}')).problem is INVALID


def test_json_syntax_errors_give_a_position_without_echoing_input() -> None:
    error = _rejected(lambda: _json(f'{{\n  "a": "{CANARY}",\n  "b" 1\n}}'))

    assert error.problem is INVALID
    assert "第 3 行" in error.message
    assert CANARY not in error.message


def test_json_depth_scan_ignores_brackets_inside_strings() -> None:
    brackets = "[" * 100 + '\\"' + "{" * 100
    assert _json(f'{{"a": "{brackets}"}}', SMALL) == {"a": brackets.replace('\\"', '"')}


def test_backslash_outside_strings_is_a_syntax_error() -> None:
    assert _rejected(lambda: _json('{"a": 1}\\')).problem is INVALID


def test_yaml_positions_are_optional() -> None:
    """PyYAML 的錯誤通常有位置；沒有時訊息只是少了位置，不會失敗。"""
    assert documents._position(None) == ""


def test_json_depth_scan_is_linear_on_unterminated_strings() -> None:
    """未結束的字串、大量的跳脫：先檢查深度時不可退化成平方時間（失敗得很快）。"""
    nasty = '{"a": "' + '\\"' * 400_000
    assert _rejected(lambda: _json(nasty)).problem is INVALID


# --- YAML ------------------------------------------------------------------------------------


def test_yaml_values_follow_the_yaml_12_core_schema() -> None:
    text = "\n".join(
        [
            "str_yes: yes",
            "str_on: on",
            "str_date: 2024-01-01",
            "str_underscore: 1_000",
            "str_sexagesimal: 1:30",
            "str_quoted_true: 'true'",
            'str_quoted_number: "1"',
            "int: 17",
            "int_leading_zero: 017",
            "int_plus: +5",
            "int_hex: 0x1F",
            "int_octal: 0o17",
            "float: 1e3",
            "float_dot: .5",
            "float_neg: -2.5E-1",
            "null_tilde: ~",
            "null_word: Null",
            "null_empty:",
            "bool_upper: TRUE",
            "bool_false: false",
            "block: |",
            "  line",
            "folded: >-",
            "  a",
            "  b",
            "200: ok",
            "true: key",
            "null: key",
        ]
    )

    assert _yaml(text) == {
        "str_yes": "yes",
        "str_on": "on",
        "str_date": "2024-01-01",
        "str_underscore": "1_000",
        "str_sexagesimal": "1:30",
        "str_quoted_true": "true",
        "str_quoted_number": "1",
        "int": 17,
        "int_leading_zero": 17,
        "int_plus": 5,
        "int_hex": 31,
        "int_octal": 15,
        "float": 1000.0,
        "float_dot": 0.5,
        "float_neg": -0.25,
        "null_tilde": None,
        "null_word": None,
        "null_empty": None,
        "bool_upper": True,
        "bool_false": False,
        "block": "line\n",
        "folded": "a b",
        "200": "ok",
        "true": "key",
        "null": "key",
    }


def test_yaml_explicit_document_markers_are_fine() -> None:
    assert _yaml("---\na: [1, {b: c}]\n...\n") == {"a": [1, {"b": "c"}]}


@pytest.mark.parametrize(
    ("text", "problem"),
    [
        ("a: &x 1\nb: 2\n", UNSUPPORTED),
        ("a: &x [1]\nb: *x\n", UNSUPPORTED),
        ("a: *undefined\n", UNSUPPORTED),
        ("a: !!python/object/apply:os.system [echo]\n", UNSUPPORTED),
        ("a: !!str 5\n", UNSUPPORTED),
        ("a: ! 5\n", UNSUPPORTED),
        ("a: !custom {b: 1}\n", UNSUPPORTED),
        ("a: !!binary aGk=\n", UNSUPPORTED),
        ("!!map {a: 1}\n", UNSUPPORTED),
        ("a: 1\n---\nb: 2\n", UNSUPPORTED),
        ("%YAML 1.2\n---\na: 1\n", UNSUPPORTED),
        ("%TAG !e! tag:example.com,2000:\n---\na: 1\n", UNSUPPORTED),
        ("? [a, b]\n: c\n", UNSUPPORTED),
        ("{[a]: b}\n", UNSUPPORTED),
        ("? {a: 1}\n: c\n", UNSUPPORTED),
        ("<<: {a: 1}\nb: 2\n", UNSUPPORTED),
        ("a: .inf\n", INVALID),
        ("a: -.Inf\n", INVALID),
        ("a: .NaN\n", INVALID),
        ("a: 1\na: 2\n", INVALID),
        ("a:\n\t- 1\n", INVALID),
        ("a: [1, 2\n", INVALID),
        ('a: "x\\0y"\n', INVALID),
        ('a: "\\ud83d\\ude00"\n', INVALID),
        ("a: x\u2028y\n", UNSUPPORTED),
        ('a: "x\u0085y"\n', UNSUPPORTED),
        ("a: x\u2029\n", UNSUPPORTED),
        ("# only a comment\n", INVALID),
        ("---\n", INVALID),
        ("a: \x01\n", INVALID),
        ("a: x\x7fy\n", INVALID),
    ],
    ids=[
        "anchor",
        "alias",
        "alias-without-anchor",
        "python-tag",
        "str-tag",
        "non-specific-tag",
        "local-tag",
        "binary-tag",
        "tagged-root",
        "two-documents",
        "yaml-directive",
        "tag-directive",
        "complex-key-sequence",
        "flow-complex-key",
        "complex-key-mapping",
        "merge-key",
        "inf",
        "negative-inf",
        "nan",
        "duplicate-key",
        "tab-indent",
        "unclosed-flow",
        "nul-escape",
        "surrogate-pair-escape",
        "line-separator",
        "next-line",
        "paragraph-separator",
        "empty-stream",
        "empty-document",
        "control-character",
        "delete-character",
    ],
)
def test_yaml_rejections(text: str, problem: SpecProblem) -> None:
    assert _rejected(lambda: _yaml(text)).problem is problem


def test_billion_laughs_is_rejected_at_the_first_anchor() -> None:
    lines = ['a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]']
    for index in range(1, 9):
        previous, current = chr(ord("a") + index - 1), chr(ord("a") + index)
        lines.append(f"{current}: &{current} [{', '.join([f'*{previous}'] * 9)}]")

    error = _rejected(lambda: _yaml("\n".join(lines)))

    assert error.problem is UNSUPPORTED
    assert "第 1 行" in error.message


def test_quoted_merge_key_is_a_plain_string_key() -> None:
    """只有 plain 的 `<<` 是 YAML 1.1 的 merge key；加引號就是一般的字串。"""
    assert _yaml("'<<': 1\n") == {"<<": 1}


def test_yaml_errors_give_lines_without_echoing_input() -> None:
    duplicate = _rejected(lambda: _yaml(f"a: 1\nb: {CANARY}\na: {CANARY}\n"))
    syntax = _rejected(lambda: _yaml(f"a: {CANARY}\nb: [\n"))

    assert "第 3 行" in duplicate.message
    assert "第 3 行" in syntax.message or "第 2 行" in syntax.message
    for error in (duplicate, syntax):
        assert CANARY not in error.message


# --- 性質 -------------------------------------------------------------------------------------

# BMP、沒有 surrogate 與 NUL。DEL 也排除：json.dumps 不跳脫 DEL，但 YAML 不允許它直接出現
# （YAML 的字元集，test_yaml_rejections 的 control-character 是同一類）。
_TEXT = st.text(
    alphabet=st.characters(
        max_codepoint=0xFFFF, exclude_categories=["Cs"], exclude_characters="\x00\x7f"
    ),
    max_size=12,
)
_JSON_VALUES = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-(10**30), max_value=10**30)
    | st.floats(allow_nan=False, allow_infinity=False)
    | _TEXT,
    lambda children: st.lists(children, max_size=4) | st.dictionaries(_TEXT, children, max_size=4),
    max_leaves=20,
)


@given(st.dictionaries(_TEXT, _JSON_VALUES, max_size=5))
def test_json_text_means_the_same_to_both_parsers(document: dict[str, JsonValue]) -> None:
    """JSON 是 YAML 1.2 的子集：同一段 JSON 以兩個 parser 解析，結果都等於原本的值。"""
    text = json.dumps(document, ensure_ascii=True).encode()

    assert parse_document(text, JSON) == document
    assert parse_document(text, YAML) == document


# --- 位置 -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tokens", "expected"),
    [
        ((), "#"),
        (("paths", "/users/{id}", "get"), "#/paths/~1users~1{id}/get"),
        (("a~b", 3), "#/a~0b/3"),
        (("é\u202e",), "#/\\u00e9\\u202e"),
        (("😀",), "#/\\U0001f600"),
    ],
)
def test_pointer_text(tokens: tuple[str | int, ...], expected: str) -> None:
    assert pointer_text(tokens) == expected


def test_pointer_text_is_truncated() -> None:
    text = pointer_text(("x" * 500,))

    assert len(text) <= 121
    assert text.endswith("…")


@pytest.mark.parametrize(
    "text",
    ["a: [" + ", ".join(["0"] * 1000) + "]", "a: " + "[" * 1000 + "]" * 1000],
    ids=["many-nodes", "deep"],
)
def test_yaml_parsing_stops_as_soon_as_a_limit_is_exceeded(
    text: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """超過節點或深度上限時立刻停下，不先解析完整份文件（純 Python 的 parser 很慢）。"""
    consumed: list[object] = []
    original = yaml.parse

    def counting(*args: Any, **kwargs: Any) -> Iterator[yaml.Event]:
        for event in original(*args, **kwargs):
            consumed.append(event)
            yield event

    monkeypatch.setattr(yaml, "parse", counting)

    assert _rejected(lambda: _yaml(text, SMALL)).problem is INVALID
    assert len(consumed) < 2 * SMALL.max_nodes
