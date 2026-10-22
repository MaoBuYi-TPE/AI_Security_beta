"""文字欄位的共用規則：非空白、有長度上限、不含控制字元與不可見的格式字元。

格式字元（Unicode 類別 Cf）包含 bidi 控制字元：例如 U+202E 會讓「ok」後面的文字反向顯示，
admin 核對授權文件編號或日後的報告時會看到誤導的內容。測試字元以程式產生，原始碼中不放。
"""

import pytest

from secscan.core.text import require_text

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
