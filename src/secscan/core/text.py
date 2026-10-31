"""文字欄位的共用規則；只用標準函式庫，domain 模組可以安全 import。

DB 也有 `char_length(btrim(x)) > 0` 的 CHECK，但 btrim 只清半形空白；這裡用 Python 的
str.strip()，連全形空白、tab、換行也視為空白，並在送進 DB 前擋下過長字串、控制字元與
不可見的格式字元（Unicode 類別 Cc、Cf，例如 ESC、換行、零寬空白與 bidi 控制字元）。
這些欄位都是單行文字；bidi 控制字元會讓 admin 核對的授權文件編號、日後的報告顯示成誤導的內容。
"""

import unicodedata

_INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf"})


def require_text(value: str, *, field: str, max_length: int) -> None:
    """非空白、不超過 max_length 個字元、不含控制字元或格式字元；不符合就拋出 ValueError。

    訊息以欄位名稱開頭，只說明原因，不含輸入內容。
    """
    if not value.strip():
        raise ValueError(f"{field} 不可為空白")
    if len(value) > max_length:
        raise ValueError(f"{field} 不可超過 {max_length} 個字元")
    if "\x00" in value:
        raise ValueError(f"{field} 不可包含 NUL 字元")
    if any(unicodedata.category(character) in _INVISIBLE_CATEGORIES for character in value):
        raise ValueError(
            f"{field} 不可包含控制字元或不可見的格式字元（例如換行、tab、bidi 控制字元）"
        )


REPLACEMENT = "�"
# 多行文字保留換行與 tab；其他控制字元、格式字元（bidi、零寬）與孤立的 surrogate 都換掉。
_KEPT = frozenset("\n\t")
_REPLACED_CATEGORIES = frozenset({"Cc", "Cf", "Cs"})


def display_text(value: str, *, max_length: int) -> tuple[str, bool]:
    """不可信的多行文字（工具的輸出，docs/DECISIONS.md §19.3）改成能保存、顯示的形式。

    PostgreSQL 的 text 不接受 NUL、UTF-8 不能編碼孤立的 surrogate：不換掉會讓寫入失敗。換行統一成
    \\n；其他控制字元、格式字元以 U+FFFD 取代（看得出原本有東西）。不轉換 HTML 的跳脫。回傳
    （文字, 是否因超過 max_length 個字元而截斷）。
    """
    unified = value.replace("\r\n", "\n").replace("\r", "\n")
    cleaned = "".join(
        character
        if character in _KEPT or unicodedata.category(character) not in _REPLACED_CATEGORIES
        else REPLACEMENT
        for character in unified
    )
    if len(cleaned) > max_length:
        return cleaned[:max_length], True
    return cleaned, False
