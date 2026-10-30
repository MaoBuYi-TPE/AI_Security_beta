"""交給工具的規格（docs/DECISIONS.md §18.6）：只留下 scan 建立時判斷為 eligible 的 operation。

輸入是上傳時正規化過的文件（servers 已改綁到 target 的 origin 加 base path）；這裡不做 I/O。
"""

import json
from pathlib import Path

import pytest

from secscan.core.json_types import JsonObject, JsonValue
from secscan.specs.domain.documents import SpecFormat
from secscan.specs.domain.openapi import normalize_spec
from secscan.specs.domain.tool_document import ToolDocumentError, tool_document
from secscan.targets.domain import parse_origin

ORIGIN = parse_origin("http://lab-api:8080")
FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "openapi" / "vampi-openapi3.yml"


def _document(paths: JsonObject, *, base_path: str = "/api", **extra: object) -> bytes:
    document = {
        "openapi": "3.0.3",
        "info": {"title": "lab", "version": "1"},
        "servers": [{"url": f"{ORIGIN}{base_path}"}],
        "paths": paths,
        **extra,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def _ok(description: str = "ok") -> JsonObject:
    return {"responses": {"200": {"description": description}}}


ID_PARAMETERS: list[JsonValue] = [
    {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
]
ITEMS: JsonObject = {
    "/items": {"get": _ok(), "post": _ok()},
    "/items/{id}": {
        "parameters": ID_PARAMETERS,
        "get": _ok(),
        "delete": _ok(),
    },
    "/admin": {"get": _ok()},
    "x-internal": {"note": "not a path"},
}


def _filtered(
    document: bytes, eligible: set[tuple[str, str]], base_path: str = "/api"
) -> JsonObject:
    output = tool_document(document, eligible=eligible, base_path=base_path, origin=ORIGIN)
    result = json.loads(output)
    assert isinstance(result, dict)
    return result


def test_only_eligible_operations_remain() -> None:
    eligible = {("GET", "/api/items"), ("GET", "/api/items/{id}")}

    paths = _filtered(_document(ITEMS), eligible)["paths"]

    assert paths == {
        "/items": {"get": _ok()},
        "/items/{id}": {"parameters": ID_PARAMETERS, "get": _ok()},
    }


def test_path_items_without_operations_and_extensions_are_dropped() -> None:
    paths = _filtered(_document(ITEMS), {("POST", "/api/items")})["paths"]

    assert paths == {"/items": {"post": _ok()}}


def test_the_rest_of_the_document_is_kept_and_servers_stay_bound() -> None:
    document = _document(ITEMS, components={"schemas": {"Item": {"type": "object"}}})

    result = _filtered(document, {("GET", "/api/items")})

    assert result["servers"] == [{"url": "http://lab-api:8080/api"}]
    assert result["components"] == {"schemas": {"Item": {"type": "object"}}}
    assert result["info"] == {"title": "lab", "version": "1"}


def test_the_output_is_compact_canonical_json_and_not_larger() -> None:
    document = _document(ITEMS)

    output = tool_document(
        document, eligible={("GET", "/api/items")}, base_path="/api", origin=ORIGIN
    )

    parsed = json.loads(output)
    assert (
        output
        == json.dumps(
            parsed, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    )
    assert len(output) <= len(document)


def test_methods_are_matched_by_the_full_path_including_the_base_path() -> None:
    # 只有 path key（不含 base path）相同不算：eligible 記的是完整的 path。
    with pytest.raises(ToolDocumentError):
        tool_document(
            _document(ITEMS), eligible={("GET", "/items")}, base_path="/api", origin=ORIGIN
        )


def test_no_eligible_operation_is_an_error() -> None:
    with pytest.raises(ToolDocumentError):
        tool_document(_document(ITEMS), eligible=set(), base_path="/api", origin=ORIGIN)


@pytest.mark.parametrize(
    "servers",
    [
        [{"url": "http://elsewhere:9999/api"}],
        [{"url": "http://lab-api:8080/other"}],
        [{"url": "http://lab-api:8080/api"}, {"url": "http://lab-api:8080/api"}],
        "http://lab-api:8080/api",
        None,
    ],
)
def test_servers_must_be_exactly_the_bound_origin(servers: object) -> None:
    document = json.loads(_document(ITEMS))
    if servers is None:
        del document["servers"]
    else:
        document["servers"] = servers

    with pytest.raises(ToolDocumentError):
        tool_document(
            json.dumps(document).encode(),
            eligible={("GET", "/api/items")},
            base_path="/api",
            origin=ORIGIN,
        )


def test_a_reference_to_a_removed_operation_fails_closed() -> None:
    link: JsonObject = {"operationRef": "#/paths/~1items~1{id}/delete"}
    paths: JsonObject = {
        "/items": {"get": {"responses": {"200": {"description": "ok", "links": {"x": link}}}}},
        "/items/{id}": {"delete": _ok()},
    }

    with pytest.raises(ToolDocumentError):
        tool_document(
            _document(paths), eligible={("GET", "/api/items")}, base_path="/api", origin=ORIGIN
        )


@pytest.mark.parametrize(
    "content", [b"not json", b"[]", b'{"paths": []}', b"1" * 5_000, b"[" * 100_000, b"\xff"]
)
def test_a_document_that_is_not_the_normalized_shape_is_an_error(content: bytes) -> None:
    with pytest.raises(ToolDocumentError):
        tool_document(content, eligible={("GET", "/api/items")}, base_path="/api", origin=ORIGIN)


def test_the_vampi_spec_keeps_only_the_get_operations() -> None:
    vampi = parse_origin("http://vampi-vuln:5000")
    normalized = normalize_spec(FIXTURE.read_bytes(), SpecFormat.YAML, origin=vampi)
    eligible = {(op.method, op.path) for op in normalized.operations if op.method == "GET"}

    output = tool_document(
        normalized.document, eligible=eligible, base_path=normalized.base_path, origin=vampi
    )

    kept = {
        (method.upper(), normalized.base_path + key)
        for key, item in json.loads(output)["paths"].items()
        for method in item
        if method != "parameters"
    }
    assert kept == eligible
    assert len(output) < len(normalized.document)


def test_paths_must_be_an_object() -> None:
    document = json.loads(_document(ITEMS))
    document["paths"] = []

    with pytest.raises(ToolDocumentError, match="paths"):
        tool_document(
            json.dumps(document).encode(),
            eligible={("GET", "/api/items")},
            base_path="/api",
            origin=ORIGIN,
        )
