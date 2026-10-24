"""文件中的參照（docs/DECISIONS.md §11.4）。

解析器或掃描工具照著參照去抓外部資源，就是 SSRF 或讀本機檔。這裡只接受同一份文件中的參照，
而且在「任何位置」都檢查（包含 example 與 x- 擴充）：寧可誤拒，也不讓某個工具把它當成參照。

- `$ref`、`operationRef`：`#/…` 形式、只有 ASCII 可見字元、不含 `%` 的 JSON Pointer（RFC 6901），
  必須指到存在的節點；不可形成只由參照組成的循環，參照鏈也有長度上限。
- `discriminator.mapping` 的值：`components.schemas` 中的名稱，或可解析的內部參照。
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
# JSON Pointer 的陣列索引：0，或不以 0 開頭的十進位數字（RFC 6901 §4）。
_ARRAY_INDEX = re.compile(r"0|[1-9][0-9]*")
_ESCAPE = re.compile(r"~(?![01])")

type Location = tuple[str | int, ...]
type Tokens = tuple[str, ...]


def check_references(document: JsonObject) -> None:
    """不能接受時拋出 InvalidSpecError。

    指向文件以外是 EXTERNAL_REF；P0 不支援的寫法是 UNSUPPORTED；指不到、循環等是 INVALID。
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
    for location, tokens in references:
        _follow(document, location, tokens)


def _check_object(
    document: JsonObject, value: JsonObject, location: Location
) -> list[tuple[Location, Tokens]]:
    for key, reason in FORBIDDEN_KEYS.items():
        if key in value:
            raise InvalidSpecError(
                SpecProblem.UNSUPPORTED, f"{pointer_text(location)}：不接受 {key}（{reason}）"
            )
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
    components = document.get("components")
    schemas = components.get("schemas") if isinstance(components, dict) else None
    for name, target in mapping.items():
        where = (*location, name)
        if isinstance(target, str) and not target.startswith("#"):
            if isinstance(schemas, dict) and target in schemas:
                continue
            raise InvalidSpecError(
                SpecProblem.EXTERNAL_REF,
                f"{pointer_text(where)}：discriminator 的 mapping 只接受 components.schemas 中的"
                "名稱，或同一份文件中的參照（#/…）",
            )
        _target(document, target, where, label="discriminator 的 mapping")


def _target(
    document: JsonObject, reference: JsonValue, location: Location, *, label: str
) -> Tokens:
    """檢查一個參照並回傳它的 JSON Pointer token；參照必須指到存在的節點。"""
    where = pointer_text(location)
    if not isinstance(reference, str):
        raise _invalid(f"{where}：{label} 必須是字串")
    if not reference.startswith("#"):
        raise InvalidSpecError(
            SpecProblem.EXTERNAL_REF, f"{where}：{label} 只接受同一份文件中的參照（#/…）"
        )
    if not reference.startswith("#/"):
        raise _unsupported(
            f"{where}：{label} 只接受 JSON Pointer 形式的參照（#/…），不可參照整份文件"
        )
    if "%" in reference or not all("!" <= character <= "~" for character in reference):
        raise _unsupported(
            f"{where}：{label} 只能使用 ASCII 可見字元，不可包含 percent-encoding 或空白"
        )
    tokens = tuple(_unescape(token, where) for token in reference[2:].split("/"))
    _resolve(document, tokens, where)
    return tokens


def _unescape(token: str, where: str) -> str:
    if _ESCAPE.search(token):
        raise _invalid(f"{where}：JSON Pointer 的 ~ 只能寫成 ~0 或 ~1")
    return token.replace("~1", "/").replace("~0", "~")


def _resolve(document: JsonObject, tokens: Tokens, where: str) -> JsonValue:
    node: JsonValue = document
    for token in tokens:
        if isinstance(node, dict) and token in node:
            node = node[token]
        elif isinstance(node, list) and _ARRAY_INDEX.fullmatch(token) and int(token) < len(node):
            node = node[int(token)]
        else:
            raise _invalid(f"{where}：參照指不到文件中的任何節點")
    return node


def _follow(document: JsonObject, location: Location, tokens: Tokens) -> None:
    """沿著「只有參照的物件」前進：回到走過的節點就是循環，工具解析時會無窮迴圈。

    參照鏈的長度另外計數（不看 visited 的大小），即使循環的判斷有錯也一定會結束。
    """
    visited = {tokens}
    hops = 1
    target = _resolve(document, tokens, pointer_text(location))
    while isinstance(target, dict) and isinstance(reference := target.get("$ref"), str):
        tokens = tuple(_unescape(token, "") for token in reference[2:].split("/"))
        if tokens in visited:
            raise _invalid(f"{pointer_text(location)}：參照形成循環（只由 $ref 組成）")
        if hops >= MAX_REF_CHAIN:
            raise _invalid(f"{pointer_text(location)}：參照鏈不可超過 {MAX_REF_CHAIN} 層")
        visited.add(tokens)
        hops += 1
        target = _resolve(document, tokens, pointer_text(location))


def _invalid(message: str) -> InvalidSpecError:
    return InvalidSpecError(SpecProblem.INVALID, message)


def _unsupported(message: str) -> InvalidSpecError:
    return InvalidSpecError(SpecProblem.UNSUPPORTED, message)
