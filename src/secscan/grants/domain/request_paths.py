"""T33 的實際請求 path：分段後受控解碼；不改寫 URI、不解析宣告用的佔位。

REJECT 凍結原有安全語法；ROUTE_PARAMETERS 只允許 E 白名單的編碼資料。
語法解析不代表授權：ScopeRules.classify_request 仍須確認完整路由及排除。
"""

import re
import string
from dataclasses import dataclass
from enum import StrEnum

from secscan.grants.domain.scope import PATH_MAX_LENGTH

_LITERAL = frozenset(string.ascii_letters + string.digits + "._~!$&'()+,=:@-")
_UNRESERVED = frozenset(string.ascii_letters + string.digits + "-._~")
_ENCODABLE = frozenset(" !\"$&'()+,:<=>@[]^`{|}")
_SEPARATORS = frozenset("/\\?#;")
_HEX_PAIR = re.compile(r"[0-9A-Fa-f]{2}")
_TRIPLET = re.compile(r"%[0-9A-Fa-f]{2}")


class PathEncoding(StrEnum):
    REJECT = "reject"
    ROUTE_PARAMETERS = "route-parameters"


class PathAmbiguity(ValueError):  # noqa: N818 - T33 的固定 domain 介面名稱
    """安全的固定 detail；例外不包含來自請求的資料。"""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


@dataclass(frozen=True, slots=True)
class RequestSegment:
    raw: str
    decoded: str
    encoded: bool


@dataclass(frozen=True, slots=True)
class RequestPath:
    raw: str
    segments: tuple[RequestSegment, ...]
    trailing_slash: bool

    @property
    def encoded(self) -> bool:
        return any(segment.encoded for segment in self.segments)


def parse_request_path(path: str, *, encoding: PathEncoding) -> RequestPath:
    """解析不含 query 的原始 path；拒絕以 PathAmbiguity.detail 說明，不輸出 path。"""
    if not isinstance(encoding, PathEncoding) or not path.startswith("/"):
        raise PathAmbiguity("syntax")
    if len(path) > PATH_MAX_LENGTH:
        raise PathAmbiguity("syntax")
    parts = path[1:].split("/")
    trailing_slash = len(parts) > 1 and parts[-1] == ""
    if parts[-1] == "":
        parts.pop()
    segments = tuple(_parse_segment(part, encoding) for part in parts)
    return RequestPath(raw=path, segments=segments, trailing_slash=trailing_slash)


def _parse_segment(raw: str, encoding: PathEncoding) -> RequestSegment:
    if not raw or raw in {".", ".."}:
        raise PathAmbiguity("syntax")
    decoded: list[str] = []
    position = 0
    while position < len(raw):
        character = raw[position]
        if character == "%":
            if encoding is PathEncoding.REJECT:
                raise PathAmbiguity("percent-encoding")
            character = _decode_triplet(raw[position + 1 : position + 3])
            position += 3
        else:
            if character not in _LITERAL:
                raise PathAmbiguity("syntax")
            position += 1
        decoded.append(character)
    value = "".join(decoded)
    if encoding is PathEncoding.ROUTE_PARAMETERS and set(value) <= {".", " ", "+"}:
        raise PathAmbiguity("dot-segment")
    return RequestSegment(raw=raw, decoded=value, encoded="%" in raw)


def _decode_triplet(pair: str) -> str:
    if _HEX_PAIR.fullmatch(pair) is None:
        raise PathAmbiguity("invalid-percent")
    character = chr(int(pair, 16))
    if character in _SEPARATORS:
        raise PathAmbiguity("encoded-separator")
    if character == "%":
        raise PathAmbiguity("double-encoding")
    if character == "*":
        raise PathAmbiguity("encoded-wildcard")
    if character in _UNRESERVED:
        raise PathAmbiguity("non-canonical")
    if character not in _ENCODABLE:
        raise PathAmbiguity("encoded-control")
    return character


def canonical_path(path: str) -> str:
    """只統一完整 triplet 的 hex 大小寫；不驗證、不解碼、不改變任何路由結構。"""
    return _TRIPLET.sub(lambda match: match[0].upper(), path)
