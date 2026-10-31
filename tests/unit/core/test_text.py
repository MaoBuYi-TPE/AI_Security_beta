"""文字欄位的共用規則：非空白、有長度上限、不含控制字元與不可見的格式字元。

格式字元（Unicode 類別 Cf）包含 bidi 控制字元：例如 U+202E 會讓「ok」後面的文字反向顯示，
admin 核對授權文件編號或日後的報告時會看到誤導的內容。測試字元以程式產生，原始碼中不放。
"""

import unicodedata

import pytest
from hypothesis import given
from hypothesis import strategies as st

from secscan.core.text import display_text, require_text

RIGHT_TO_LEFT_OVERRIDE = chr(0x202E)
ZERO_WIDTH_SPACE = chr(0x200B)
BYTE_ORDER_MARK = chr(0xFEFF)
ESCAPE = chr(0x1B)


@pytest.mark.parametrize("value", ["API 教學靶場", "VAmPI", "已核對 lab 資產：10.89.7.20", "a b"])
def test_accepts_ordinary_text(value: str) -> None:
    require_text(value, field="name", max_length=100)


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("", "空白"),
        ("   ", "空白"),
        ("x" * 101, "100"),
        ("lab\x00", "NUL"),
        (f"ok{RIGHT_TO_LEFT_OVERRIDE}evil", "控制字元"),
        (f"a{ZERO_WIDTH_SPACE}b", "控制字元"),
        (f"{BYTE_ORDER_MARK}lab", "控制字元"),
        (f"{ESCAPE}[2Jlab", "控制字元"),
        ("line\nbreak", "控制字元"),
        ("tab\there", "控制字元"),
        ("bell\x07", "控制字元"),
    ],
    ids=repr,
)
def test_rejects_blank_long_or_invisible_characters(value: str, reason: str) -> None:
    with pytest.raises(ValueError, match=reason) as caught:
        require_text(value, field="name", max_length=100)

    assert str(caught.value).startswith("name")


# --- display_text：工具輸出的多行文字（docs/DECISIONS.md §19.3） ---------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("plain", "plain"),
        ("line 1\nline 2\tcol", "line 1\nline 2\tcol"),
        ("crlf\r\nlone\rcr", "crlf\nlone\ncr"),
        ("nul\x00here", "nul�here"),
        ("esc\x1b[31mred", "esc�[31mred"),
        ("bidi‮evil", "bidi�evil"),
        ("zero​width", "zero�width"),
        ("lone\ud800surrogate", "lone�surrogate"),
        ("全形\u3000空白與中文", "全形\u3000空白與中文"),
        ("&lt;p&gt;escaped", "&lt;p&gt;escaped"),
    ],
)
def test_display_text_replaces_what_cannot_be_stored_or_shown(raw: str, expected: str) -> None:
    assert display_text(raw, max_length=100) == (expected, False)


def test_display_text_truncates_and_says_so() -> None:
    assert display_text("abcdef", max_length=4) == ("abcd", True)
    assert display_text("abcd", max_length=4) == ("abcd", False)


def test_display_text_truncates_after_replacing() -> None:
    """長度以替換之後的字元計算（\\r\\n 變成一個 \\n）。"""
    assert display_text("a\r\nb", max_length=3) == ("a\nb", False)


@given(st.text(alphabet=st.characters(min_codepoint=0, max_codepoint=0x10FFFF)), st.integers(0, 50))
def test_display_text_always_produces_storable_text(raw: str, max_length: int) -> None:
    text, truncated = display_text(raw, max_length=max_length)

    assert len(text) <= max_length
    assert "\x00" not in text
    assert "\r" not in text
    text.encode("utf-8")  # 沒有孤立的 surrogate
    assert all(
        character in "\n\t" or unicodedata.category(character) not in {"Cc", "Cf", "Cs"}
        for character in text
    )
    assert truncated is (len(display_text(raw, max_length=10**6)[0]) > max_length)
