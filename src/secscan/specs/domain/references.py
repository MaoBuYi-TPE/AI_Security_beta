"""文件中的參照（docs/DECISIONS.md §11.4）。

解析器或掃描工具照著參照去抓外部資源，就是 SSRF 或讀本機檔。這裡只接受同一份文件中的參照，
而且在「任何位置」都檢查（包含 example 與 x- 擴充）：寧可誤拒，也不讓某個工具把它當成參照。

- `$ref`、`operationRef`：`#/…` 形式、只有 ASCII 可見字元、不含 `%` 的 JSON Pointer（RFC 6901），
  必須指到存在的節點；不可形成只由參照組成的循環，參照鏈也有長度上限。
- `discriminator.mapping` 的值：只接受 `#/components/schemas/<名稱>`，而且必須存在。
- 一律拒絕：`externalValue`（工具會去抓外部的範例），以及會改變 JSON Schema 工具解析參照基準的
  識別字（`$id`、`$schema`、`$anchor`…）。

只檢查、不展開：平台本身不解析參照的內容。錯誤訊息指出位置，不含參照的值（可能是帶帳密的 URL）。
"""

import re
from collections.abc import Mapping
from types import MappingProxyType

from secscan.core.json_types import JsonObject, JsonValue
from secscan.specs.domain.documents import InvalidSpecError, SpecProblem, pointer_text

REFERENCE_KEYS = ("$ref", "operationRef")
MAX_REF_CHAIN = 32
FORBIDDEN_KEYS: Mapping[str, str] = MappingProxyType(
    {
        "externalValue": "工具會去抓外部的範例",
        "$id": "會改變 JSON Schema 工具解析參照的基準",
        "$schema": "JSON Schema 工具可能去抓 meta-schema",
        "$anchor": "會改變 JSON Schema 工具解析參照的方式",
        "$dynamicRef": "會改變 JSON Schema 工具解析參照的方式",
        "$dynamicAnchor": "會改變 JSON Schema 工具解析參照的方式",
        "$recursiveRef": "會改變 JSON Schema 工具解析參照的方式",
        "$recursiveAnchor": "會改變 JSON Schema 工具解析參照的方式",
    }
)
# JSON Pointer 的陣列索引：0，或不以 0 開頭的十進位數字（RFC 6901 §4）。位數有上限：int() 不處理
# 超過 4,300 位的字串，文件的節點也不可能多到需要十位數的索引。
_ARRAY_INDEX = re.compile(r"0|[1-9][0-9]{0,8}")
_ESCAPE = re.compile(r"~(?![01])")
# OAS 3.0 對 components 名稱的規定（openapi 也用它檢查名稱）；discriminator 的 mapping 只寫名稱時，
# 用來給出改寫的提示。
COMPONENT_NAME = re.compile(r"[A-Za-z0-9._-]+")
_SCHEMAS = ("components", "schemas")

type Location = tuple[str | int, ...]
type Tokens = tuple[str, ...]


def check_references(document: JsonObject) -> None:
    """不能接受時拋出 InvalidSpecError。

    指向文件以外是 EXTERNAL_REF；P0 不支援的寫法是 UNSUPPORTED；指不到、循環等是 INVALID。
    位置字串只在拋錯時才組，合法的文件不付這個成本。
    """
    references: list[tuple[Location, Tokens]] = []
    pending: list[tuple[JsonValue, Location]] = [(document, ())]
    while pending:
        value, location = pending.pop()
        if isinstance(value, dict):
            references.extend(_check_object(document, value, location))
            pending.extend((child, (*location, key)) for key, child in value.items())
        elif isinstance(value, list):
            pending.extend((child, (*location, index)) for index, child in enumerate(value))
    settled: dict[Tokens, int] = {}
    for location, tokens in references:
        _follow(document, location, tokens, settled)


def _check_object(
    document: JsonObject, value: JsonObject, location: Location
) -> list[tuple[Location, Tokens]]:
    for key, reason in FORBIDDEN_KEYS.items():
        if key in value:
            raise _unsupported(location, f"不接受 {key}（{reason}）")
    found = []
    for key in REFERENCE_KEYS:
        if key in value:
            tokens = _target(document, value[key], location, label=key)
            if key == "$ref":
                found.append((location, tokens))
    discriminator = value.get("discriminator")
    if isinstance(discriminator, dict) and isinstance(
        mapping := discriminator.get("mapping"), dict
    ):
        _check_mapping(document, mapping, (*location, "discriminator", "mapping"))
    return found


def _check_mapping(document: JsonObject, mapping: JsonObject, location: Location) -> None:
    """只接受 `#/components/schemas/<名稱>`。

    只寫名稱也不接受：schema 的名稱本身可以長得像 URL，工具可能把它當成 URI reference。
    """
    label = "discriminator 的 mapping"
    for name, target in mapping.items():
        where = (*location, name)
        if isinstance(target, str) and not target.startswith("#"):
            if COMPONENT_NAME.fullmatch(target):
                raise _unsupported(
                    where, f"{label} 請寫成 #/components/schemas/<名稱>，不接受只寫名稱"
                )
            raise InvalidSpecError(
                SpecProblem.EXTERNAL_REF,
                _at(where, f"{label} 只接受同一份文件中的參照（#/components/schemas/<名稱>）"),
            )
        tokens = _pointer(target, where, label=label)
        if len(tokens) != len(_SCHEMAS) + 1 or tokens[: len(_SCHEMAS)] != _SCHEMAS:
            raise _unsupported(where, f"{label} 只能指向 #/components/schemas/<名稱>")
        _resolve(document, tokens, where)


def _target(
    document: JsonObject, reference: JsonValue, location: Location, *, label: str
) -> Tokens:
    """檢查一個參照並回傳它的 JSON Pointer token；參照必須指到存在的節點。"""
    tokens = _pointer(reference, location, label=label)
    _resolve(document, tokens, location)
    return tokens


def _pointer(reference: JsonValue, location: Location, *, label: str) -> Tokens:
    """只檢查寫法（不看文件），回傳 JSON Pointer 的 token。"""
    if not isinstance(reference, str):
        raise _invalid(location, f"{label} 必須是字串")
    if not reference.startswith("#"):
        raise InvalidSpecError(
            SpecProblem.EXTERNAL_REF, _at(location, f"{label} 只接受同一份文件中的參照（#/…）")
        )
    if not reference.startswith("#/"):
        raise _unsupported(
            location, f"{label} 只接受 JSON Pointer 形式的參照（#/…），不可參照整份文件"
        )
    if "%" in reference or not all("!" <= character <= "~" for character in reference):
        raise _unsupported(
            location, f"{label} 只能使用 ASCII 可見字元，不可包含 percent-encoding 或空白"
        )
    return tuple(_unescape(token, location) for token in reference[2:].split("/"))


def _unescape(token: str, location: Location) -> str:
    if _ESCAPE.search(token):
        raise _invalid(location, "JSON Pointer 的 ~ 只能寫成 ~0 或 ~1")
    return token.replace("~1", "/").replace("~0", "~")


def _resolve(document: JsonObject, tokens: Tokens, location: Location) -> JsonValue:
    node: JsonValue = document
    for token in tokens:
        if isinstance(node, dict) and token in node:
            node = node[token]
        elif isinstance(node, list) and _ARRAY_INDEX.fullmatch(token) and int(token) < len(node):
            node = node[int(token)]
        else:
            raise _invalid(location, "參照指不到文件中的任何節點")
    return node


def _follow(
    document: JsonObject, location: Location, tokens: Tokens, settled: dict[Tokens, int]
) -> None:
    """沿著「只有參照的物件」前進：回到走過的節點就是循環，工具解析時會無窮迴圈。

    settled 記錄已確認的節點還要解析幾次才到終點；許多參照共用同一條鏈時，每條鏈只走一次。
    參照鏈的長度另外計數（不看走過的集合），即使循環的判斷有錯也一定會結束。
    """
    chain: list[Tokens] = []
    current: Tokens | None = tokens
    while current is not None and current not in settled:
        if current in chain:
            raise _invalid(location, "參照形成循環（只由 $ref 組成）")
        if len(chain) >= MAX_REF_CHAIN:
            raise _invalid(location, f"參照鏈不可超過 {MAX_REF_CHAIN} 層")
        chain.append(current)
        current = _next_reference(_resolve(document, current, location), location)
    total = len(chain) + (0 if current is None else settled[current])
    if total > MAX_REF_CHAIN:
        raise _invalid(location, f"參照鏈不可超過 {MAX_REF_CHAIN} 層")
    for index, item in enumerate(chain):
        settled[item] = total - index


def _next_reference(node: JsonValue, location: Location) -> Tokens | None:
    """node 是帶 $ref 的物件時回傳它指向的位置（寫法已在走訪時檢查過）。"""
    if isinstance(node, dict) and isinstance(reference := node.get("$ref"), str):
        return tuple(_unescape(token, location) for token in reference[2:].split("/"))
    return None


def _at(location: Location, message: str) -> str:
    return f"{pointer_text(location)}：{message}"


def _invalid(location: Location, message: str) -> InvalidSpecError:
    return InvalidSpecError(SpecProblem.INVALID, _at(location, message))


def _unsupported(location: Location, message: str) -> InvalidSpecError:
    return InvalidSpecError(SpecProblem.UNSUPPORTED, _at(location, message))
