"""有界的 URL 解析模型；不是所有伺服器的安全保證。

apply_chain 按給定順序執行，重複列出轉換才重複執行。資料是 path（不含 query）。
解碼先檢查每個 percent triplet；錯誤或 UTF-8 無法嚴格解碼回 None。其餘轉換保留空段，
除非明確選 COLLAPSE_SLASHES/DOT_SEGMENTS。ASCII casefold 也作用在普通段落，不能拿它
正規化授權清單以擴大實際授權。模型的已知反例必須保留。
"""

import re
from enum import StrEnum
from urllib.parse import unquote_to_bytes

_INVALID_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")


class Transform(StrEnum):
    DECODE_LATIN1 = "decode-latin1"
    DECODE_UTF8 = "decode-utf8"
    PLUS_SPACE = "plus-space"
    TRIM_SEGMENTS = "trim-segments"
    STRIP_EXTENSION = "strip-extension"
    STRIP_PARAMETERS = "strip-parameters"
    BACKSLASH = "backslash"
    CASEFOLD = "casefold"
    COLLAPSE_SLASHES = "collapse-slashes"
    DOT_SEGMENTS = "dot-segments"


def apply_chain(path: str, transforms: tuple[Transform, ...] | list[Transform]) -> str | None:
    value = path
    for transform in transforms:
        transformed = _apply(value, transform)
        if transformed is None:
            return None
        value = transformed
    return value


def _apply(path: str, transform: Transform) -> str | None:
    if transform in {Transform.DECODE_LATIN1, Transform.DECODE_UTF8}:
        return _decode(path, "latin-1" if transform is Transform.DECODE_LATIN1 else "utf-8")
    if transform is Transform.PLUS_SPACE:
        return path.replace("+", " ")
    if transform is Transform.TRIM_SEGMENTS:
        # 每段刪除前後 ASCII 空白，再刪掉尾端所有點／ASCII 空白；不動中間空白。
        return "/".join(segment.strip(" ").rstrip(" .") for segment in path.split("/"))
    if transform is Transform.STRIP_EXTENSION:
        # 每段最後一個點及其後綴被移除；. 與 .. 本身留給 DOT_SEGMENTS。
        return "/".join(
            segment.rsplit(".", 1)[0] if "." in segment and segment not in {".", ".."} else segment
            for segment in path.split("/")
        )
    if transform is Transform.STRIP_PARAMETERS:
        return "/".join(segment.partition(";")[0] for segment in path.split("/"))
    if transform is Transform.BACKSLASH:
        return path.replace("\\", "/")
    if transform is Transform.CASEFOLD:
        return path.translate(
            str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
        )
    if transform is Transform.COLLAPSE_SLASHES:
        return re.sub(r"/+", "/", path)
    if transform is Transform.DOT_SEGMENTS:
        return _remove_dot_segments(path)
    raise ValueError("unknown URL transform")


def _decode(value: str, encoding: str) -> str | None:
    if _INVALID_PERCENT.search(value):
        return None
    try:
        return unquote_to_bytes(value).decode(encoding, errors="strict")
    except UnicodeError:
        return None


def express_segments(path: str) -> tuple[str, ...] | None:
    """Express 類模型：先按 raw slash 分段，再嚴格 decodeURIComponent 各參數資料。

    這裡只描述分段／解碼順序，不模擬 Express 的路由宣告或匹配優先級；由 route echo 驗證。
    """
    if not path.startswith("/"):
        return None
    parts = path[1:].split("/")
    if parts[-1] == "":
        parts.pop()
    decoded = [_decode(part, "utf-8") for part in parts]
    if any(part is None for part in decoded):
        return None
    return tuple(part for part in decoded if part is not None)


def _remove_dot_segments(path: str) -> str:
    """RFC 3986 §5.2.4 字串演算法；不依賴 OS 的路徑規則。"""
    remaining, output = path, ""
    while remaining:
        if remaining.startswith(("../", "./")):
            remaining = remaining.partition("/")[2]
        elif remaining.startswith("/./") or remaining == "/.":
            remaining = "/" + remaining[3:]
        elif remaining.startswith("/../") or remaining == "/..":
            remaining = "/" + remaining[4:]
            output = output.rsplit("/", 1)[0]
        elif remaining in {".", ".."}:
            remaining = ""
        else:
            boundary = remaining.find("/", 1 if remaining.startswith("/") else 0)
            if boundary < 0:
                output += remaining
                remaining = ""
            else:
                output += remaining[:boundary]
                remaining = remaining[boundary:]
    return output
