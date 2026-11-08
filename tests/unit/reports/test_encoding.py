"""SEC-17：不可信的字串以 CommonMark 實際解析後只會出現在 code token 中；JSON 已跳脫。"""

import json
import re
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from markdown_it import MarkdownIt
from markdown_it.token import Token

from secscan.reports.domain.encoding import (
    EMPTY,
    LINE_SEPARATOR,
    PARAGRAPH_SEPARATOR,
    code_block,
    code_span,
    to_json,
)

MALICIOUS = (
    "<script>alert(1)</script>",
    "[click](http://evil.example/x)",
    "![img](http://evil.example/x.png)",
    "<http://evil.example>",
    "www.evil.example",
    "admin@evil.example",
    "line\n# heading",
    "line\n<div onclick=x>",
    "text\n===",
    "text\n---",
    "``` fenced\n```",
    "````",
    "`a``b```c",
    "| a | b |\n|---|---|",
    "[ref]: http://evil.example",
    "> quote\n> more",
    "- item\n  ```\n  code",
    "‮evil‬",
    "nul\x00 esc\x1b[31m",
    f"sep{LINE_SEPARATOR}x{PARAGRAPH_SEPARATOR}y",
    "\r\n<img src=x onerror=alert(1)>",
    " ` ",
    "&lt;script&gt;",
    "x" * 5000,
    "多位元組的字串🙂",
)
_URL = re.compile(r"[a-z][a-z0-9+.-]*://|www\.|@[a-z0-9-]+\.", re.IGNORECASE)
_MD = MarkdownIt("commonmark").enable("table")
_CODE = re.compile(r"<code>.*?</code>", re.DOTALL)


def flatten(tokens: list[Token]) -> list[Token]:
    flat: list[Token] = []
    for token in tokens:
        flat.append(token)
        if token.children:
            flat.extend(flatten(token.children))
    return flat


def assert_safe(document: str) -> list[Token]:
    tokens = flatten(_MD.parse(document))
    forbidden = {"html_block", "html_inline", "link_open", "image"}
    assert not [token.type for token in tokens if token.type in forbidden]
    for token in tokens:
        if token.type == "text":
            assert not _URL.search(token.content), token.content
    rendered = _MD.render(document).lower()
    # code 元素中的內容已跳脫成文字（&lt;…&gt;）；其餘部分不得出現任何標籤或屬性。
    outside = _CODE.sub("", rendered)
    for needle in ("<a", "<img", "<script", "<div", "href=", "src=", "onerror", "onclick"):
        assert needle not in outside
    assert "<code>" not in outside
    return tokens


@pytest.mark.parametrize("value", MALICIOUS)
def test_code_spans_keep_untrusted_values_inside_one_code_token(value: str) -> None:
    document = f"- label：{code_span(value)}\n- after：x\n"
    tokens = assert_safe(document)
    codes = [token for token in tokens if token.type == "code_inline"]
    assert len(codes) == 1
    assert "\n" not in codes[0].content
    # 清單仍然只有兩項：值沒有開出新的區塊。
    assert sum(token.type == "list_item_open" for token in tokens) == 2


@pytest.mark.parametrize("value", MALICIOUS)
def test_code_blocks_cannot_be_closed_by_their_content(value: str) -> None:
    document = f"# title\n\n{code_block(value)}\n\nafter\n"
    tokens = assert_safe(document)
    fences = [token for token in tokens if token.type == "fence"]
    assert len(fences) == 1
    assert fences[0].info == ""
    assert [token.type for token in tokens if token.type.endswith("_open")] == [
        "heading_open",
        "paragraph_open",
    ]


@given(st.text(max_size=200))
def test_arbitrary_text_stays_in_code(value: str) -> None:
    span = assert_safe(f"- label：{code_span(value)}\n")
    if value:
        assert sum(token.type == "code_inline" for token in span) == 1
    block = assert_safe(f"{code_block(value)}\n")
    assert sum(token.type == "fence" for token in block) == 1


def test_empty_value_uses_the_platform_marker() -> None:
    assert code_span("") == EMPTY


def test_json_escapes_html_and_line_separators() -> None:
    document: dict[str, Any] = {
        "value": f"</script><b>&{LINE_SEPARATOR}{PARAGRAPH_SEPARATOR}",
        "n": 1,
    }
    serialized = to_json(document)
    for raw in ("<", ">", "&", LINE_SEPARATOR, PARAGRAPH_SEPARATOR):
        assert raw not in serialized
    assert json.loads(serialized) == document
    with pytest.raises(ValueError, match="Out of range"):
        to_json({"bad": float("nan")})
