"""上傳的規格（JSON 或 YAML 的 bytes）轉成 JSON 值（docs/DECISIONS.md §11.2）。

只接受不同 parser 解讀一致、資源有上限的子集：
- 共同：嚴格 UTF-8、不接受 BOM；最外層是物件；巢狀與節點數有上限；key 不可重複；字串不含 NUL
  或孤立的 surrogate；數字是有限值，整數最多 4,300 位（Python 的上限）。
- JSON：標準函式庫 json；拒絕 NaN、Infinity；先以迭代方式檢查巢狀深度，不依賴 RecursionError。
- YAML：PyYAML 純 Python 的事件 API，由這裡的迭代式 composer 組成資料（不用 PyYAML 的遞迴
  composer、constructor 與 C 擴充）。只接受單一文件；不接受 directive、anchor、alias、tag、
  複合 key 與 plain 的 `<<`；key 一律是字串，值依 YAML 1.2 的 core schema 解讀。

這裡不做任何 I/O。錯誤訊息只說明原因與位置（行、欄或 JSON Pointer），不含任何值。
"""

import codecs
import json
import math
import re
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from enum import StrEnum

import yaml

from secscan.core.json_types import JsonObject, JsonValue

MAX_SPEC_BYTES = 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 100_000
MAX_INT_DIGITS = 4300
POINTER_MAX_LENGTH = 120
_INT_LIMIT = 10**MAX_INT_DIGITS
_INT_TOO_LONG = f"整數最多 {MAX_INT_DIGITS:,} 位"

# JSON 的巢狀深度：只看括號、字串的引號與跳脫。逐一前進，最壞情況也是線性時間。
_JSON_STRUCTURE = re.compile(r'[\[\]{},:"\\]')
# YAML 1.1 把它們當成換行，YAML 1.2 不會（只有 LF 與 CR）。
_AMBIGUOUS_LINE_BREAK = re.compile("[\\x85\\u2028\\u2029]")
# 行首的 % 是 directive。PyYAML 會默默忽略 %YAML、%TAG 以外的保留 directive，所以先看原文。
_DIRECTIVE = re.compile(r"^%", re.MULTILINE)
# YAML 1.2 的 core schema（只用於 plain scalar；加引號或 block 的一律是字串）。
_NULL = re.compile(r"(?:null|Null|NULL|~)?")
_TRUE = frozenset({"true", "True", "TRUE"})
_FALSE = frozenset({"false", "False", "FALSE"})
_DECIMAL = re.compile(r"[-+]?[0-9]+")
_OCTAL = re.compile(r"0o[0-7]+")
_HEXADECIMAL = re.compile(r"0x[0-9a-fA-F]+")
_FLOAT = re.compile(r"[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?")
_NON_FINITE = re.compile(r"[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN)")


class SpecFormat(StrEnum):
    JSON = "json"
    YAML = "yaml"


class SpecProblem(StrEnum):
    """規格被拒絕的類別；service 對應成穩定的錯誤碼（docs/DECISIONS.md §11.8）。"""

    INVALID = "invalid"  # 壞掉的文件、超過深度或數量上限
    UNSUPPORTED = "unsupported"  # P0 不支援的功能
    EXTERNAL_REF = "external_ref"  # 參照指向文件以外
    TOO_LARGE = "too_large"  # 超過大小上限


class InvalidSpecError(Exception):
    """規格不能接受。message 只說明原因與位置，不含輸入的值，可以直接回給 client。"""

    def __init__(self, problem: SpecProblem, message: str) -> None:
        super().__init__(message)
        self.problem = problem
        self.message = message


@dataclass(frozen=True, slots=True)
class DocumentLimits:
    max_bytes: int = MAX_SPEC_BYTES
    max_depth: int = MAX_DEPTH
    max_nodes: int = MAX_NODES


DEFAULT_LIMITS = DocumentLimits()


def parse_document(
    content: bytes, spec_format: SpecFormat, *, limits: DocumentLimits = DEFAULT_LIMITS
) -> JsonObject:
    """把上傳的內容轉成 JSON 物件；不能接受時拋出 InvalidSpecError。"""
    if len(content) > limits.max_bytes:
        raise InvalidSpecError(SpecProblem.TOO_LARGE, f"規格不可超過 {limits.max_bytes:,} bytes")
    text = _decode(content)
    if spec_format is SpecFormat.JSON:
        value = _parse_json(text, limits)
    else:
        value = _parse_yaml(text, limits)
    if not isinstance(value, dict):
        raise _invalid("最外層必須是物件（OpenAPI 文件）")
    _check_values(value, limits)
    return value


def pointer_text(tokens: Sequence[str | int]) -> str:
    """錯誤訊息中的位置：JSON Pointer 形式（`#/paths/~1users/get`），只由 key 與陣列索引組成。

    非 ASCII 可見字元以 \\uXXXX 表示（不讓控制字元或 bidi 字元進入訊息），過長就截斷。
    逐字產生、到上限就停：成本與 key 的長度無關（審查發現，先組整串再截斷會讓 CPU 時間平方成長）。
    """
    return _bounded(_pointer_characters(tokens), limit=POINTER_MAX_LENGTH)


def printable(text: str, *, limit: int) -> str:
    """只留 ASCII 可見字元，其他以 \\u 跳脫；超過 limit 個字元就截斷並加上「…」。"""
    return _bounded(iter(text), limit=limit)


def _pointer_characters(tokens: Sequence[str | int]) -> Iterator[str]:
    yield "#"
    for token in tokens:
        yield "/"
        for character in token if isinstance(token, str) else str(token):
            yield {"~": "~0", "/": "~1"}.get(character, character)


def _bounded(characters: Iterator[str], *, limit: int) -> str:
    """把字元（或 ~0、~1 這類已跳脫的片段）逐一轉成可見字元，超過 limit 就停止讀取。"""
    parts: list[str] = []
    length = 0
    for character in characters:
        piece = character if all(" " <= c <= "~" for c in character) else _escape(character)
        if length + len(piece) > limit:
            return "".join(parts) + "…"
        parts.append(piece)
        length += len(piece)
    return "".join(parts)


def _escape(character: str) -> str:
    code = ord(character)
    return f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}"


def _invalid(message: str) -> InvalidSpecError:
    return InvalidSpecError(SpecProblem.INVALID, message)


def _decode(content: bytes) -> str:
    if not content:
        raise _invalid("規格沒有內容")
    if content.startswith(codecs.BOM_UTF8):
        raise _invalid("檔案開頭不可有 BOM（請存成不含 BOM 的 UTF-8）")
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _invalid(f"規格必須是 UTF-8（第 {exc.start + 1} 個 byte 不是合法的 UTF-8）") from None


# --- 共同規則 ---------------------------------------------------------------------------------


def _check_values(document: JsonObject, limits: DocumentLimits) -> None:
    """節點數（key、值與容器各算一個）、字串與整數；以迭代方式走過整份文件。"""
    nodes = 0
    pending: list[tuple[JsonValue, tuple[str | int, ...]]] = [(document, ())]
    while pending:
        value, location = pending.pop()
        nodes += 1
        if isinstance(value, dict):
            nodes += len(value)
            for key, child in value.items():
                _check_text(key, (*location, key))
                pending.append((child, (*location, key)))
        elif isinstance(value, list):
            pending.extend((child, (*location, index)) for index, child in enumerate(value))
        elif isinstance(value, str):
            _check_text(value, location)
        elif isinstance(value, int) and not isinstance(value, bool) and abs(value) >= _INT_LIMIT:
            raise _invalid(f"{pointer_text(location)}：{_INT_TOO_LONG}")
        if nodes > limits.max_nodes:
            raise _invalid(f"節點（key、值與容器）不可超過 {limits.max_nodes:,} 個")


def _check_text(text: str, location: tuple[str | int, ...]) -> None:
    if "\x00" in text:
        raise _invalid(f"{pointer_text(location)}：字串不可包含 NUL 字元")
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        raise _invalid(
            f"{pointer_text(location)}：字串含有孤立的 surrogate"
            "（YAML 中 BMP 以外的字元請直接寫，或用 \\U 跳脫）"
        ) from None


# --- JSON ------------------------------------------------------------------------------------


def _parse_json(text: str, limits: DocumentLimits) -> JsonValue:
    _scan_json_structure(text, limits)
    try:
        value: JsonValue = json.loads(
            text,
            object_pairs_hook=_json_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except json.JSONDecodeError as exc:
        raise _invalid(f"JSON 語法錯誤（第 {exc.lineno} 行第 {exc.colno} 欄）") from None
    except ValueError:
        # json 以 int() 轉換整數，超過 Python 的位數上限時拋出 ValueError。
        raise _invalid(_INT_TOO_LONG) from None
    return value


def _scan_json_structure(text: str, limits: DocumentLimits) -> None:
    """在 json.loads 之前，以迭代方式檢查巢狀深度並估算節點數。

    節點數的上界 = 開括號 + 逗號 + 冒號 + 1（字串外）；它最多是實際節點數的兩倍（多出的是空容器），
    所以超過上限的兩倍才拒絕，不會誤拒合法的文件。這樣 1 MiB 的 [{},{},…] 不會先被整個解析成
    數十萬個物件（審查發現峰值約 70 MiB）；精確的數量由解析後的走訪檢查。
    """
    depth = 0
    estimate = 1
    in_string = False
    position = 0
    while (match := _JSON_STRUCTURE.search(text, position)) is not None:
        character = match.group()
        position = match.end()
        if in_string:
            if character == "\\":
                position += 1  # 跳過被跳脫的字元（例如 \" 或 \\）
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
            continue
        if character in "]}":
            depth -= 1
            continue
        estimate += 1
        if estimate > 2 * limits.max_nodes:
            raise _invalid(f"節點（key、值與容器）不可超過 {limits.max_nodes:,} 個")
        if character in "[{":
            depth += 1
            if depth > limits.max_depth:
                raise _invalid(f"巢狀不可超過 {limits.max_depth} 層")


def _json_object(pairs: list[tuple[str, JsonValue]]) -> JsonObject:
    result = dict(pairs)
    if len(result) != len(pairs):
        counts = Counter(key for key, _ in pairs)
        duplicate = next(key for key, count in counts.items() if count > 1)
        raise _invalid(f"JSON 物件有重複的 key「{printable(duplicate, limit=POINTER_MAX_LENGTH)}」")
    return result


def _reject_constant(name: str) -> JsonValue:
    raise _invalid("JSON 不可使用 NaN、Infinity 或 -Infinity")


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise _invalid("數字超出浮點數可表示的範圍")
    return value


# --- YAML ------------------------------------------------------------------------------------


def _parse_yaml(text: str, limits: DocumentLimits) -> JsonValue:
    ambiguous = _AMBIGUOUS_LINE_BREAK.search(text)
    if ambiguous is not None:
        line = text.count("\n", 0, ambiguous.start()) + 1
        raise InvalidSpecError(
            SpecProblem.UNSUPPORTED,
            f"YAML 第 {line} 行：不可直接使用 U+{ord(ambiguous.group()):04X}"
            "（YAML 1.1 與 1.2 對換行的定義不同），請改用跳脫寫法",
        )
    directive = _DIRECTIVE.search(text)
    if directive is not None:
        line = text.count("\n", 0, directive.start()) + 1
        raise InvalidSpecError(
            SpecProblem.UNSUPPORTED, f"YAML 第 {line} 行：不接受 YAML 的 directive（以 % 開頭的行）"
        )
    composer = _YamlComposer(limits)
    try:
        for event in yaml.parse(text, Loader=yaml.SafeLoader):
            composer.feed(event)
    except yaml.MarkedYAMLError as exc:
        raise _invalid(f"YAML 語法錯誤{_position(exc.problem_mark)}") from None
    except yaml.YAMLError:
        raise _invalid("YAML 含有不允許的字元（例如控制字元）") from None
    except (ValueError, OverflowError):
        # PyYAML 以 chr() 轉換 \\U 跳脫：超出 Unicode 範圍時拋出這兩種例外，不是 YAMLError。
        # composer 自己的錯誤是 InvalidSpecError（不是 ValueError 的子類別），不會被攔到這裡。
        raise _invalid("YAML 的 \\U 跳脫超出 Unicode 的範圍（最大 \\U0010FFFF）") from None
    return composer.result()


def _position(mark: object) -> str:
    """PyYAML 的位置（line、column 從 0 起算）；沒有位置時回空字串。"""
    line, column = getattr(mark, "line", None), getattr(mark, "column", None)
    if not isinstance(line, int) or not isinstance(column, int):
        return ""
    return f"（第 {line + 1} 行第 {column + 1} 欄）"


def _line(event: yaml.Event) -> str:
    line = getattr(event.start_mark, "line", None)
    return f"YAML 第 {line + 1} 行" if isinstance(line, int) else "YAML"


@dataclass(slots=True)
class _Mapping:
    value: JsonObject
    expecting_key: bool = True
    key: str = ""


@dataclass(slots=True)
class _Sequence:
    value: list[JsonValue]


class _YamlComposer:
    """把 YAML 事件組成 JSON 值：以堆疊代替遞迴，超過上限時立刻停下（parser 也跟著停）。"""

    def __init__(self, limits: DocumentLimits) -> None:
        self._limits = limits
        self._stack: list[_Mapping | _Sequence] = []
        self._documents = 0
        self._nodes = 0
        self._root: JsonValue = None
        self._has_root = False

    def feed(self, event: yaml.Event) -> None:
        if isinstance(event, yaml.DocumentStartEvent):
            self._start_document(event)
        elif isinstance(event, yaml.AliasEvent):
            raise _unsupported(event, "不接受 YAML 的 alias（*名稱）")
        elif isinstance(event, yaml.ScalarEvent):
            self._count(event)
            self._scalar(event)
        elif isinstance(event, yaml.MappingStartEvent | yaml.SequenceStartEvent):
            self._count(event)
            self._open(event)
        elif isinstance(event, yaml.CollectionEndEvent):
            self._attach(self._stack.pop().value)
        # StreamStart、StreamEnd、DocumentEnd 沒有內容。

    def result(self) -> JsonValue:
        if not self._has_root:
            raise _invalid("規格沒有內容")
        return self._root

    def _start_document(self, event: yaml.DocumentStartEvent) -> None:
        self._documents += 1
        # directive 在解析之前就已拒絕（_DIRECTIVE）：PyYAML 不會為保留的 directive 產生任何事件。
        if self._documents > 1:
            raise _unsupported(event, "只接受單一份 YAML 文件")

    def _count(self, event: yaml.ScalarEvent | yaml.CollectionStartEvent) -> None:
        if event.anchor is not None:
            raise _unsupported(event, "不接受 YAML 的 anchor（&名稱）")
        if event.tag is not None:
            raise _unsupported(event, "不接受明確的 YAML tag（例如 !!str、!!python/…）")
        self._nodes += 1
        if self._nodes > self._limits.max_nodes:
            raise _invalid(f"節點（key、值與容器）不可超過 {self._limits.max_nodes:,} 個")

    def _open(self, event: yaml.CollectionStartEvent) -> None:
        if self._expecting_key():
            raise _unsupported(event, "不接受以 mapping 或 sequence 當 key")
        if len(self._stack) >= self._limits.max_depth:
            raise _invalid(f"巢狀不可超過 {self._limits.max_depth} 層{_position(event.start_mark)}")
        frame = _Mapping({}) if isinstance(event, yaml.MappingStartEvent) else _Sequence([])
        self._stack.append(frame)

    def _scalar(self, event: yaml.ScalarEvent) -> None:
        top = self._stack[-1] if self._stack else None
        if isinstance(top, _Mapping) and top.expecting_key:
            self._key(top, event)
        else:
            self._attach(_resolve(event))

    def _key(self, frame: _Mapping, event: yaml.ScalarEvent) -> None:
        """key 一律是字串（OAS 3.0 建議的 failsafe schema）：`200:` 是字串 "200"。"""
        key = event.value
        if not event.style and key == "<<":
            raise _unsupported(event, "不接受 YAML 1.1 的 merge key（<<）")
        if key in frame.value:
            raise _invalid(
                f"{_line(event)}：重複的 key「{printable(key, limit=POINTER_MAX_LENGTH)}」"
            )
        frame.key = key
        frame.expecting_key = False

    def _attach(self, value: JsonValue) -> None:
        if not self._stack:
            self._root = value
            self._has_root = True
            return
        top = self._stack[-1]
        if isinstance(top, _Sequence):
            top.value.append(value)
        else:
            top.value[top.key] = value
            top.expecting_key = True

    def _expecting_key(self) -> bool:
        return (
            bool(self._stack)
            and isinstance(top := self._stack[-1], _Mapping)
            and (top.expecting_key)
        )


def _unsupported(event: yaml.Event, reason: str) -> InvalidSpecError:
    return InvalidSpecError(SpecProblem.UNSUPPORTED, f"{_line(event)}：{reason}")


def _resolve(event: yaml.ScalarEvent) -> JsonValue:
    """加引號或 block（|、>）的 scalar 一律是字串；plain 的依 YAML 1.2 core schema 解讀。"""
    text = event.value
    if event.style:
        return text
    if _NULL.fullmatch(text):
        return None
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    if _NON_FINITE.fullmatch(text):
        raise _invalid(f"{_line(event)}：.inf、.nan 不是 JSON 可以表示的數字")
    if _DECIMAL.fullmatch(text):
        return _integer(text, 10)
    if _OCTAL.fullmatch(text):
        return _integer(text[2:], 8)
    if _HEXADECIMAL.fullmatch(text):
        return _integer(text[2:], 16)
    if _FLOAT.fullmatch(text):
        return _finite_float(text)
    return text


def _integer(digits: str, base: int) -> int:
    try:
        return int(digits, base)
    except ValueError:
        raise _invalid(_INT_TOO_LONG) from None
