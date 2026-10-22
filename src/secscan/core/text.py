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
