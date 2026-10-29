"""preflight 的定義（docs/DECISIONS.md §12.5）：掃描前以已知的受保護端點確認認證有效。

T08 只定義與驗證，T12 才實際執行：
- method 只接受 GET：preflight 不可改變靶場的狀態。
- path：grant 的 path 語法，但不可有 route 佔位。它是實際送出的請求，相對於 target 的 origin
  （含 base path），寫法和 inventory 相同，T09 可以直接拿 grant 的規則判斷是否在範圍內。
- expected_status：200 到 299。
- expected_json：1 到 16 項。key 是 JSON Pointer（RFC 6901），值是字串、整數、布林或 null。
  只看狀態碼分不出登入頁，所以至少要比對一項內容。

比對的語意（T12 照著實作）：嚴格相等，型別也要相同（True 不等於 1）；pointer 指不到就不符合；
回應必須是 JSON。錯誤訊息不回顯輸入：期望值可能是帳號或 email。
"""

import json
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from secscan.auth_profiles.domain.errors import InvalidAuthProfileError
from secscan.grants.domain.scope import path_problem

PREFLIGHT_METHOD = "GET"
MIN_EXPECTED_STATUS = 200
MAX_EXPECTED_STATUS = 299
MAX_EXPECTED_ITEMS = 16
POINTER_MAX_LENGTH = 256
EXPECTED_TEXT_MAX_LENGTH = 256
# RFC 8259 §6：各家實作對 [-(2**53)+1, (2**53)-1] 內的整數看法一致。
MAX_SAFE_INTEGER = 2**53 - 1
_INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf"})
# RFC 6901 §3：~ 只能接 0 或 1。
_BAD_ESCAPE = re.compile(r"~(?![01])")

type ExpectedValue = str | int | bool | None


@dataclass(frozen=True, slots=True, eq=False)
class Preflight:
    """比較時期望值的型別也要相同，順序不影響（以排序後的 JSON 比較）。"""

    method: str
    path: str
    expected_status: int
    expected_json: Mapping[str, ExpectedValue]

    def __post_init__(self) -> None:
        if self.method != PREFLIGHT_METHOD:
            raise InvalidAuthProfileError(
                "preflight.method 只接受 GET（preflight 不可改變靶場的狀態）"
            )
        _check_path(self.path)
        status = self.expected_status
        if type(status) is not int or not MIN_EXPECTED_STATUS <= status <= MAX_EXPECTED_STATUS:
            raise InvalidAuthProfileError(
                f"preflight.expected_status 必須是 {MIN_EXPECTED_STATUS} 到 "
                f"{MAX_EXPECTED_STATUS} 的整數"
            )
        object.__setattr__(self, "expected_json", _checked_expectations(self.expected_json))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Preflight):
            return NotImplemented
        return self._key() == other._key()

    def __hash__(self) -> int:
        return hash(self._key())

    def _key(self) -> tuple[str, str, int, str]:
        # JSON 區分 true 與 1；Python 中 True == 1，直接比較 dict 會把兩者當成相同。
        canonical = json.dumps(dict(self.expected_json), sort_keys=True, separators=(",", ":"))
        return (self.method, self.path, self.expected_status, canonical)


def parse_pointer(pointer: str) -> tuple[str, ...]:
    """JSON Pointer 的 reference token（已解碼：先 ~1 再 ~0）。

    不合規則時拋出 InvalidAuthProfileError。
    """
    problem = _pointer_problem(pointer)
    if problem is not None:
        raise InvalidAuthProfileError(problem)
    return tuple(token.replace("~1", "/").replace("~0", "~") for token in pointer[1:].split("/"))


def _check_path(path: str) -> None:
    problem = path_problem(path)
    if problem is not None:
        raise InvalidAuthProfileError(f"preflight.path：{problem}")
    if "{" in path or "}" in path:
        raise InvalidAuthProfileError(
            "preflight.path 不可有 route 佔位（例如 {id}）："
            "preflight 是實際送出的請求，請寫實際的值"
        )


def _checked_expectations(expected: object) -> Mapping[str, ExpectedValue]:
    if not isinstance(expected, Mapping):
        raise InvalidAuthProfileError("preflight.expected_json 必須是物件（JSON Pointer → 期望值）")
    if not expected:
        raise InvalidAuthProfileError(
            "preflight.expected_json 至少要有 1 項：只看狀態碼分不出登入頁，必須比對回應的內容"
        )
    if len(expected) > MAX_EXPECTED_ITEMS:
        raise InvalidAuthProfileError(f"preflight.expected_json 最多 {MAX_EXPECTED_ITEMS} 項")
    for position, (pointer, value) in enumerate(expected.items(), start=1):
        problem = _pointer_problem(pointer)
        if problem is not None:
            raise InvalidAuthProfileError(
                f"preflight.expected_json 第 {position} 項的 key：{problem}"
            )
        problem = _value_problem(value)
        if problem is not None:
            raise InvalidAuthProfileError(f"preflight.expected_json 第 {position} 項的值{problem}")
    return MappingProxyType(dict(expected))


def _pointer_problem(pointer: object) -> str | None:
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        return "必須是以 / 開頭的 JSON Pointer（RFC 6901），例如 /data/username"
    if len(pointer) > POINTER_MAX_LENGTH:
        return f"JSON Pointer 不可超過 {POINTER_MAX_LENGTH} 個字元"
    if _has_invisible(pointer):
        return "JSON Pointer 不可有控制字元或不可見的格式字元"
    if _BAD_ESCAPE.search(pointer) is not None:
        return "JSON Pointer 中的 ~ 只能寫成 ~0（代表 ~）或 ~1（代表 /）"
    return None


def _value_problem(value: object) -> str | None:
    # bool 是 int 的子類別，先判斷。
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            return "超出整數的範圍（正負 2^53 - 1 以內）"
        return None
    if isinstance(value, str):
        if len(value) > EXPECTED_TEXT_MAX_LENGTH or _has_invisible(value):
            return f"不可超過 {EXPECTED_TEXT_MAX_LENGTH} 個字元，也不可有控制字元或不可見的格式字元"
        return None
    return "只能是字串、整數、true、false 或 null（不比對浮點數、陣列與物件）"


def _has_invisible(text: str) -> bool:
    return any(unicodedata.category(character) in _INVISIBLE_CATEGORIES for character in text)


class _NotJson:
    """回應不是 JSON（和 JSON 的 null 區分）。"""

    def __repr__(self) -> str:
        return "NOT_JSON"


NOT_JSON = _NotJson()
_MISSING = object()


def matches(preflight: Preflight, status: int, body: object) -> bool:
    """§12.5 的比對：狀態碼相同，expected_json 的每一項都嚴格相等（型別也要相同）。

    body 是解析好的 JSON 值；回應不是 JSON 時傳入 NOT_JSON。
    """
    if status != preflight.expected_status or body is NOT_JSON:
        return False
    return all(
        _strictly_equal(_resolve(body, parse_pointer(pointer)), expected)
        for pointer, expected in preflight.expected_json.items()
    )


def _resolve(document: object, tokens: tuple[str, ...]) -> object:
    """RFC 6901 的解析；指不到時回傳 _MISSING。陣列索引不可有前導 0，`-` 指向不存在的元素。"""
    current = document
    for token in tokens:
        if isinstance(current, dict):
            if token not in current:
                return _MISSING
            current = current[token]
        elif isinstance(current, list):
            if re.fullmatch(r"0|[1-9][0-9]*", token) is None or int(token) >= len(current):
                return _MISSING
            current = current[int(token)]
        else:
            return _MISSING
    return current


def _strictly_equal(actual: object, expected: ExpectedValue) -> bool:
    """型別也要相同：bool 與 int 不互通，浮點數不等於期望的整數。"""
    return type(actual) is type(expected) and actual == expected
