"""OpenAPI 3.0 的檢查、servers 改綁、operation inventory 與正規化文件。

規則見 docs/DECISIONS.md §11.3 到 §11.5。

只驗證平台依賴的部分（版本、頂層欄位、info、paths、operation、servers），其他欄位當成不透明的
JSON。會讓工具連到別處的功能（path 與 operation 層級的 servers、Link 的 server、callbacks、
oauth2 與 openIdConnect）一律拒絕；參照由 references 檢查。

servers 一律改綁成 target 的 origin 加 base path：原本的 host 丟掉，也不出現在訊息中。
"""

import hashlib
import json
import re
from collections.abc import Iterator
from urllib.parse import urlsplit

from secscan.core.json_types import JsonObject, JsonValue
from secscan.core.text import require_text
from secscan.grants.domain.matching import Route, parse_route
from secscan.grants.domain.scope import path_problem
from secscan.specs.domain.documents import (
    DEFAULT_LIMITS,
    DocumentLimits,
    InvalidSpecError,
    SpecFormat,
    SpecProblem,
    parse_document,
    pointer_text,
    printable,
)
from secscan.specs.domain.model import NormalizedSpec, SpecOperation
from secscan.specs.domain.references import COMPONENT_NAME, check_references
from secscan.targets.domain import Origin

MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_OPERATIONS = 1_000
OPERATION_ID_MAX_LENGTH = 200
# patch 的位數有上限：DB 的欄位是 16 個字元。
OPENAPI_VERSION = re.compile(r"3\.0\.(?:0|[1-9][0-9]{0,11})")
TOP_LEVEL_FIELDS = frozenset(
    {"openapi", "info", "servers", "paths", "components", "security", "tags", "externalDocs"}
)
# OAS 3.0 的 Path Item 中 operation 的順序；inventory 依 path 再依這個順序排列。
OPERATION_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
PATH_ITEM_FIELDS = frozenset({"summary", "description", "parameters", *OPERATION_METHODS})
UNSUPPORTED_SECURITY_SCHEMES = frozenset({"oauth2", "openIdConnect"})
# 名稱必須符合 COMPONENT_NAME 的區段（OAS 3.0 的 Components Object）。
COMPONENT_SECTIONS = (
    "schemas",
    "responses",
    "parameters",
    "examples",
    "requestBodies",
    "headers",
    "securitySchemes",
    "links",
    "callbacks",
)
_SERVER_SCHEMES = frozenset({"http", "https"})

type Location = tuple[str | int, ...]


def normalize_spec(
    content: bytes,
    spec_format: SpecFormat,
    *,
    origin: Origin,
    limits: DocumentLimits = DEFAULT_LIMITS,
    max_document_bytes: int = MAX_DOCUMENT_BYTES,
) -> NormalizedSpec:
    """解析、檢查並正規化；不能接受時拋出 InvalidSpecError。這裡不做任何 I/O。"""
    document = parse_document(content, spec_format, limits=limits)
    version = _openapi_version(document)
    _check_top_level(document)
    _check_info(document.get("info"))
    base_path = _base_path(document.get("servers"))
    check_references(document)
    _check_components(document.get("components"))
    operations = _operations(document.get("paths"), base_path)
    normalized = {**document, "servers": [{"url": f"{origin}{base_path}"}]}
    encoded = json.dumps(
        normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    if len(encoded) > max_document_bytes:
        raise InvalidSpecError(
            SpecProblem.TOO_LARGE, f"正規化後的文件不可超過 {max_document_bytes:,} bytes"
        )
    return NormalizedSpec(
        source_format=spec_format,
        source_size=len(content),
        source_sha256=hashlib.sha256(content).digest(),
        document=encoded,
        document_sha256=hashlib.sha256(encoded).digest(),
        openapi_version=version,
        base_path=base_path,
        operations=operations,
    )


def _invalid(message: str) -> InvalidSpecError:
    return InvalidSpecError(SpecProblem.INVALID, message)


def _unsupported(message: str) -> InvalidSpecError:
    return InvalidSpecError(SpecProblem.UNSUPPORTED, message)


def _at(location: Location, message: str) -> str:
    """位置加上原因；只在拋錯時呼叫，合法的文件不付組位置字串的成本。"""
    return f"{pointer_text(location)}：{message}"


# --- 版本與頂層 -------------------------------------------------------------------------------


def _openapi_version(document: JsonObject) -> str:
    if "openapi" not in document:
        if "swagger" in document:
            raise _unsupported("P0 只支援 OpenAPI 3.0.x（不支援 Swagger 2.0）")
        raise _invalid('缺少 openapi 欄位（例如 "3.0.3"）')
    version = document["openapi"]
    if not isinstance(version, str):
        raise _invalid('openapi 必須是字串（例如 "3.0.3"；YAML 中請加引號）')
    if OPENAPI_VERSION.fullmatch(version) is None:
        raise _unsupported("P0 只支援 OpenAPI 3.0.x（3.1 在 P1）")
    return version


def _check_top_level(document: JsonObject) -> None:
    for key in document:
        if key not in TOP_LEVEL_FIELDS and not key.startswith("x-"):
            raise _unsupported(
                f"不支援頂層欄位「{printable(key, limit=64)}」"
                "（只接受 OpenAPI 3.0 的欄位與 x- 擴充；webhooks 是 3.1 的功能）"
            )


def _check_info(info: JsonValue) -> None:
    if not isinstance(info, dict):
        raise _invalid("缺少 info 物件")
    for field in ("title", "version"):
        if not isinstance(info.get(field), str):
            raise _invalid(f"info.{field} 必須是字串（YAML 中的版本號請加引號）")


# --- servers ---------------------------------------------------------------------------------


def _base_path(servers: JsonValue) -> str:
    """所有 server 的 base path（必須相同）。

    沒有 servers 或是空陣列時為空字串（OAS 的預設是 /）。
    """
    if servers is None:
        return ""
    if not isinstance(servers, list):
        raise _invalid("servers 必須是陣列")
    paths = {_server_path(server, ("servers", index)) for index, server in enumerate(servers)}
    if len(paths) > 1:
        raise _unsupported(
            "所有 servers 的 base path 必須相同（servers 會一律改綁到 target 的 origin）"
        )
    return paths.pop() if paths else ""


def _server_path(server: JsonValue, location: Location) -> str:
    """server URL 的 path，去掉結尾的 /。只取 path，原本的 host 不保留也不回顯。"""
    url = server.get("url") if isinstance(server, dict) else None
    if not isinstance(url, str):
        raise _invalid(_at(location, "server 必須是含有 url 字串的物件"))
    if "{" in url or "}" in url:
        raise _unsupported(_at(location, "server 的 URL 不支援變數"))
    if not url or not all("!" <= character <= "~" for character in url):
        raise _invalid(_at(location, "server 的 URL 只能使用 ASCII 可見字元，不可有空白"))
    if "?" in url or "#" in url:
        raise _invalid(_at(location, "server 的 URL 不可有 query 或 fragment"))
    try:
        parts = urlsplit(url)
    except ValueError:
        # 例如不合法的 IPv6 括號；例外的訊息含有 host，不回顯。
        raise _invalid(_at(location, "server 的 URL 不合法")) from None
    absolute = parts.scheme in _SERVER_SCHEMES and bool(parts.netloc)
    path_only = not parts.scheme and not parts.netloc and url.startswith("/")
    if not (absolute or path_only):
        raise _invalid(_at(location, "server 的 URL 必須是 http(s)://主機/… 或以 / 開頭的 path"))
    if parts.path in ("", "/"):
        return ""
    problem = path_problem(parts.path)
    if problem is not None:
        raise _invalid(_at(location, problem))
    return parts.path.removesuffix("/")


# --- components ------------------------------------------------------------------------------


def _check_components(components: JsonValue) -> None:
    if components is None:
        return
    if not isinstance(components, dict):
        raise _invalid("components 必須是物件")
    if "callbacks" in components:
        raise _unsupported("#/components/callbacks：不支援 callbacks")
    _check_component_names(components)
    _check_links(components.get("links"), ("components", "links"))
    responses = components.get("responses")
    if isinstance(responses, dict):
        for name, response in responses.items():
            _check_response(response, ("components", "responses", name))
    schemes = components.get("securitySchemes")
    if isinstance(schemes, dict):
        for name, scheme in schemes.items():
            _check_security_scheme(scheme, ("components", "securitySchemes", name))


def _check_component_names(components: JsonObject) -> None:
    """名稱不能是 URL 或路徑（工具可能把名稱當成參照）；訊息只給第幾個，不回顯名稱。"""
    for section in COMPONENT_SECTIONS:
        entries = components.get(section)
        if not isinstance(entries, dict):
            continue
        for index, name in enumerate(entries, start=1):
            if COMPONENT_NAME.fullmatch(name) is None:
                raise _invalid(
                    _at(
                        ("components", section),
                        f"第 {index} 個名稱不符合 OAS 的規定（只能使用英文字母、數字與 . - _）",
                    )
                )


def _check_security_scheme(scheme: JsonValue, location: Location) -> None:
    if not isinstance(scheme, dict):
        return
    _check_entry_reference(scheme, "securitySchemes", location)
    kind = scheme.get("type")
    if kind in UNSUPPORTED_SECURITY_SCHEMES:
        raise _unsupported(
            _at(location, f"P0 不支援 {kind} 類型的 security scheme（含 token 或 discovery URL）")
        )


def _check_response(response: JsonValue, location: Location) -> None:
    if isinstance(response, dict):
        _check_entry_reference(response, "responses", location)
        _check_links(response.get("links"), (*location, "links"))


def _check_links(links: JsonValue, location: Location) -> None:
    """Link 的 server 會讓工具連到別處。"""
    if not isinstance(links, dict):
        return
    for name, link in links.items():
        if not isinstance(link, dict):
            continue
        _check_entry_reference(link, "links", (*location, name))
        if "server" in link:
            raise _unsupported(_at((*location, name), "不支援 Link 的 server"))


def _check_entry_reference(entry: JsonObject, section: str, location: Location) -> None:
    """這些位置的 $ref 只能指向 components 中對應的區段：那裡的每一項都會檢查，轉一手也繞不過。

    參照的寫法與能否解析已由 references 檢查；同一個物件中 $ref 以外的欄位照樣檢查。
    """
    if "$ref" not in entry:
        return
    reference = entry["$ref"]
    prefix = f"#/components/{section}/"
    if not (
        isinstance(reference, str)
        and reference.startswith(prefix)
        and "/" not in reference.removeprefix(prefix)
    ):
        raise _unsupported(_at(location, f"這裡的 $ref 只能指向 #/components/{section}/<名稱>"))


# --- paths 與 operation ---------------------------------------------------------------------


def _operations(paths: JsonValue, base_path: str) -> tuple[SpecOperation, ...]:
    if not isinstance(paths, dict):
        raise _invalid("缺少 paths 物件")
    routes: dict[Route, str] = {}
    operation_ids: set[str] = set()
    operations: list[SpecOperation] = []
    for key, item in paths.items():
        if key.startswith("x-"):
            continue
        full_path, route = _route(key, base_path, routes)
        routes[route] = key
        for method, operation in _path_item(item, ("paths", key)):
            location = ("paths", key, method)
            operation_id = _check_operation(operation, location, operation_ids)
            operations.append(SpecOperation(method.upper(), full_path, operation_id))
    if len(operations) > MAX_OPERATIONS:
        raise _invalid(f"operation 不可超過 {MAX_OPERATIONS:,} 個")
    order = {method.upper(): index for index, method in enumerate(OPERATION_METHODS)}
    return tuple(
        sorted(operations, key=lambda operation: (operation.path, order[operation.method]))
    )


def _route(key: str, base_path: str, routes: dict[Route, str]) -> tuple[str, Route]:
    location = ("paths", key)
    if not key.startswith("/"):
        raise _invalid(_at(location, "path 必須以 / 開頭"))
    full_path = base_path + key
    problem = path_problem(full_path)
    if problem is not None:
        raise _invalid(_at(location, problem))
    route = parse_route(full_path)
    if route in routes:
        other = pointer_text(("paths", routes[route]))
        raise _invalid(f"{pointer_text(location)} 與 {other} 只差在佔位的名稱，是同一個 route")
    return full_path, route


def _path_item(item: JsonValue, location: Location) -> Iterator[tuple[str, JsonObject]]:
    if not isinstance(item, dict):
        raise _invalid(_at(location, "path item 必須是物件"))
    for field in item:
        if field == "$ref":
            raise _unsupported(_at(location, "不支援 path item 的 $ref"))
        if field == "servers":
            raise _unsupported(_at(location, "不支援 path 層級的 servers（只能寫在最外層）"))
        if field not in PATH_ITEM_FIELDS and not field.startswith("x-"):
            raise _invalid(_at(location, f"path item 不認得欄位「{printable(field, limit=64)}」"))
    for method in OPERATION_METHODS:
        if method in item:
            operation = item[method]
            if not isinstance(operation, dict):
                raise _invalid(_at((*location, method), "operation 必須是物件"))
            yield method, operation


def _check_operation(operation: JsonObject, location: Location, seen: set[str]) -> str | None:
    """operation 層級的規則；回傳 operationId（沒有時為 None）。"""
    if "servers" in operation:
        raise _unsupported(_at(location, "不支援 operation 層級的 servers（只能寫在最外層）"))
    if "callbacks" in operation:
        raise _unsupported(_at(location, "不支援 callbacks"))
    responses = operation.get("responses")
    if isinstance(responses, dict):
        for code, response in responses.items():
            _check_response(response, (*location, "responses", code))
    if "operationId" not in operation:
        return None
    operation_id = operation["operationId"]
    if not isinstance(operation_id, str):
        raise _invalid(_at(location, "operationId 必須是字串"))
    try:
        require_text(operation_id, field="operationId", max_length=OPERATION_ID_MAX_LENGTH)
    except ValueError as exc:
        raise _invalid(_at(location, str(exc))) from None
    if operation_id in seen:
        raise _invalid(_at(location, "operationId 與其他 operation 重複"))
    seen.add(operation_id)
    return operation_id
