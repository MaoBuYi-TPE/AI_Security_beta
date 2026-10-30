"""交給工具的規格（docs/DECISIONS.md §18.6）：只留下 scan 建立時判斷為 eligible 的 operation。

輸入是上傳時正規化過的文件（openapi.normalize_spec 的輸出，servers 已改綁到 target 的 origin
加 base path）。工具（ZAP 的 openapi job）會對文件中的每個 operation 送出請求，所以 grant 不允許的
method 或 path 不能留在文件中（guard 仍然會拒絕，這裡讓工具根本不送）。

- eligible 是 scan_operations 中 ineligible_reason 為 NULL 的 (method, 含 base path 的 path)。
- 保留 path 層級的 parameters；刪掉沒有 operation 的 path item，以及 x- 開頭的 path key。
- 重新檢查參照：operationRef 或 #/paths/… 指到被刪的 operation 時 fail closed。
- servers 必須恰好是 [{"url": origin + base_path}]：上傳時已改綁，不符代表資料損毀，不改寫。
- 輸出和 normalize_spec 相同的 compact JSON。
任何不符都拋 ToolDocumentError（訊息不含文件的內容）。
"""

import json
from collections.abc import Collection

from secscan.core.json_types import JsonObject, JsonValue
from secscan.specs.domain.documents import InvalidSpecError
from secscan.specs.domain.openapi import OPERATION_METHODS
from secscan.specs.domain.references import check_references
from secscan.targets.domain import Origin

_PATH_LEVEL_FIELDS = frozenset({"summary", "description", "parameters"})


class ToolDocumentError(Exception):
    """文件不是預期的正規化格式，或過濾之後不能交給工具（訊息不含文件的內容）。"""


def tool_document(
    document: bytes,
    *,
    eligible: Collection[tuple[str, str]],
    base_path: str,
    origin: Origin,
) -> bytes:
    parsed = _load(document)
    if parsed.get("servers") != [{"url": f"{origin}{base_path}"}]:
        raise ToolDocumentError("servers 不是 target 的 origin 加 base path")
    paths = parsed.get("paths")
    if not isinstance(paths, dict):
        raise ToolDocumentError("缺少 paths 物件")
    kept = _kept_paths(paths, frozenset(eligible), base_path)
    if not kept:
        raise ToolDocumentError("沒有任何 eligible 的 operation")
    filtered: JsonObject = {**parsed, "paths": kept}
    try:
        check_references(filtered)
    except InvalidSpecError:
        raise ToolDocumentError("參照指向被刪除的 operation 或不存在的位置") from None
    return json.dumps(
        filtered, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def _load(document: bytes) -> JsonObject:
    try:
        parsed = json.loads(document.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ToolDocumentError("文件不是 JSON") from None
    if not isinstance(parsed, dict):
        raise ToolDocumentError("文件必須是物件")
    return parsed


def _kept_paths(
    paths: JsonObject, eligible: frozenset[tuple[str, str]], base_path: str
) -> JsonObject:
    kept: JsonObject = {}
    for key, item in paths.items():
        if key.startswith("x-") or not isinstance(item, dict):
            continue
        operations = {
            method: item[method]
            for method in OPERATION_METHODS
            if method in item and (method.upper(), base_path + key) in eligible
        }
        if operations:
            kept[key] = {**_path_level(item), **operations}
    return kept


def _path_level(item: dict[str, JsonValue]) -> JsonObject:
    return {field: value for field, value in item.items() if field in _PATH_LEVEL_FIELDS}
