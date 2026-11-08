"""報告的安全編碼（SEC-17；docs/DECISIONS.md §28.5）。純函式。

Markdown：不可信的字串一律當成資料。
- 單行的值只放在 code span：換行、CR、tab、U+2028／U+2029 換成可見的符號，其他控制字元、格式字元
  （含 bidi）換成 U+FFFD。原因：Markdown 先解析區塊、後解析行內；code span 中留著換行，下一行就能
  開出 HTML 區塊、標題或 setext 底線。backtick 的數量比內容中最長的連續 backtick 多一個，前後各留
  一個空白（CommonMark 會剝掉，內容不變）。
- 多行的值只放在最上層的 fenced code block：info string 是空的，fence 比內容中最長的連續 backtick
  還長，所以內容中沒有任何一行能結束它。
- 平台的文字（標籤、enum、整數、時間）才放在 code 以外；不輸出連結、圖片、HTML 或參考定義。

JSON：鍵的順序由呼叫端固定；allow_nan=False；`<`、`>`、`&`、U+2028、U+2029 以 \\u 跳脫（這些
字元在 JSON 中只可能出現在字串裡），報告被當成 HTML 或 JavaScript 開啟也不會被解讀。
"""

import json
import re
import unicodedata

from secscan.core.json_types import JsonValue

REPLACEMENT = chr(0xFFFD)
EMPTY = "（空白）"
LINE_SEPARATOR = chr(0x2028)
PARAGRAPH_SEPARATOR = chr(0x2029)
_NEWLINE_SYMBOL = chr(0x2424)
_VISIBLE = {
    "\n": _NEWLINE_SYMBOL,
    "\r": chr(0x240D),
    "\t": chr(0x2409),
    LINE_SEPARATOR: _NEWLINE_SYMBOL,
    PARAGRAPH_SEPARATOR: _NEWLINE_SYMBOL,
}
_REPLACED = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp", "Co", "Cn"})
_BLOCK_KEPT = frozenset("\n\t")
_BACKTICKS = re.compile(r"`+")
_JSON_ESCAPES = {
    "<": "\\u003c",
    ">": "\\u003e",
    "&": "\\u0026",
    LINE_SEPARATOR: "\\u2028",
    PARAGRAPH_SEPARATOR: "\\u2029",
}
_JSON_ESCAPE_PATTERN = re.compile("[<>&" + LINE_SEPARATOR + PARAGRAPH_SEPARATOR + "]")


def _longest_backticks(text: str) -> int:
    return max((len(run) for run in _BACKTICKS.findall(text)), default=0)


def code_span(value: str) -> str:
    """單行的不可信值：一定是一個完整的 code span。空字串顯示成平台的標記。"""
    text = "".join(
        _VISIBLE.get(character)
        or (REPLACEMENT if unicodedata.category(character) in _REPLACED else character)
        for character in value
    )
    if not text:
        return EMPTY
    fence = "`" * (_longest_backticks(text) + 1)
    return f"{fence} {text} {fence}"


def code_block(value: str) -> str:
    """多行的不可信值：最上層的 fenced code block（呼叫端前後要留空行，不可放在清單中）。"""
    unified = value.replace("\r\n", "\n").replace("\r", "\n")
    text = "".join(
        character
        if character in _BLOCK_KEPT
        else (
            _VISIBLE.get(character)
            or (REPLACEMENT if unicodedata.category(character) in _REPLACED else character)
        )
        for character in unified
    )
    fence = "`" * max(3, _longest_backticks(text) + 1)
    return f"{fence}\n{text}\n{fence}"


def to_json(document: JsonValue) -> str:
    serialized = json.dumps(
        document, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=False
    )
    return _JSON_ESCAPE_PATTERN.sub(lambda match: _JSON_ESCAPES[match.group(0)], serialized)
