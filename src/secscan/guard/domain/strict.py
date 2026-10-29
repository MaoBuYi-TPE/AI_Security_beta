"""runner 與 guard 交換的 JSON 文件（policy、status）共用的嚴格解析（docs/DECISIONS.md §15.3）。

只接受寫入端寫得出來的那一種寫法：UTF-8 的 JSON 物件、key 完全相符、沒有重複的 key、沒有浮點數與
NaN；欄位的型別以 type() 比對（bool 是 int 的子類別，True 不會被當成 1）；UUID 與 IP 這類值
parse 之後轉回字串必須和原本相同。錯誤以呼叫端指定的例外拋出，訊息只有欄位與原因，不含內容。
"""

import json
from collections.abc import Callable, Collection
from typing import Any, NoReturn
from uuid import UUID


class StrictDocument:
    """已確認欄位完全相符的 JSON 物件；取值時檢查型別。"""

    def __init__(self, document: dict[str, Any], error: type[ValueError]) -> None:
        self._document = document
        self._error = error

    def integer(self, field: str) -> int:
        return self._typed(field, int, "整數")

    def raw(self, field: str) -> object:
        """不檢查型別的值（呼叫端自己檢查，例如可以是 null 的欄位）。"""
        return self._document[field]

    def boolean(self, field: str) -> bool:
        return self._typed(field, bool, "布林值")

    def string(self, field: str) -> str:
        return self._typed(field, str, "字串")

    def strings(self, field: str) -> tuple[str, ...]:
        values = self._typed(field, list, "字串的陣列")
        if not all(type(value) is str for value in values):
            raise self._error(f"{field} 必須是字串的陣列")
        return tuple(values)

    def uuid(self, field: str) -> UUID:
        return self.canonical(self.string(field), UUID, field)

    def canonical[T](self, value: str, parse: Callable[[str], T], field: str) -> T:
        """parse 之後再轉回字串必須和原本相同：只接受 canonical 寫法。"""
        try:
            parsed = parse(value)
        except ValueError:
            raise self._error(f"{field} 不合格式") from None
        if str(parsed) != value:
            raise self._error(f"{field} 必須是 canonical 寫法")
        return parsed

    def _typed[T](self, field: str, kind: type[T], label: str) -> T:
        value = self._document[field]
        if type(value) is not kind:
            raise self._error(f"{field} 必須是{label}")
        return value


def load_object(
    raw: bytes,
    *,
    fields: Collection[str],
    max_bytes: int,
    label: str,
    error: type[ValueError],
    floats: bool = False,
) -> StrictDocument:
    """floats=True 時接受浮點數（例如時間）；NaN 與 Infinity 一律拒絕。"""
    if len(raw) > max_bytes:
        raise error(f"{label} 不可超過 {max_bytes} bytes")

    def unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        document: dict[str, Any] = {}
        for key, value in pairs:
            if key in document:
                raise error(f"{label} 有重複的 key")
            document[key] = value
        return document

    def reject(kind: str) -> Callable[[str], NoReturn]:
        def raise_error(_: str) -> NoReturn:
            raise error(f"{label} 不可有{kind}")

        return raise_error

    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_keys,
            parse_float=float if floats else reject("浮點數"),
            parse_constant=reject(" NaN 或 Infinity"),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise error(f"{label} 不是 UTF-8 的 JSON") from None
    if not isinstance(document, dict):
        raise error(f"{label} 必須是 JSON 物件")
    if set(document) != set(fields):
        raise error(f"{label} 的欄位必須完全相符（不可缺少，也不可多出）")
    return StrictDocument(document, error)


def dump_canonical(document: dict[str, object]) -> bytes:
    """排序的 key、沒有多餘的空白、只有 ASCII：同樣的內容永遠是同樣的 bytes。"""
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )
