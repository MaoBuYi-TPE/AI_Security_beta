"""文字欄位的共用規則；只用標準函式庫，domain 模組可以安全 import。

DB 也有 `char_length(btrim(x)) > 0` 的 CHECK，但 btrim 只清半形空白；這裡用 Python 的
str.strip()，連全形空白、tab、換行也視為空白，並在送進 DB 前擋下過長字串與 NUL 字元。
"""


def require_text(value: str, *, field: str, max_length: int) -> None:
    """非空白、不超過 max_length 個字元、不含 NUL；不符合就拋出 ValueError（訊息含欄位名稱）。"""
    if not value.strip():
        raise ValueError(f"{field} 不可為空白")
    if len(value) > max_length:
        raise ValueError(f"{field} 不可超過 {max_length} 個字元")
    if "\x00" in value:
        raise ValueError(f"{field} 不可包含 NUL 字元")
