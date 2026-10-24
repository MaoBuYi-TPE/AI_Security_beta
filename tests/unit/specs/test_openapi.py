"""OpenAPI 3.0 的檢查、servers 改綁、operation inventory 與正規化文件。

規則見 docs/DECISIONS.md §11.3 到 §11.5。

以 VAmPI 的真實規格（tests/fixtures/openapi/，T03 的輸入，sha256 記在 manifest）當基準；
其他情境以最小的文件逐一測試。全部是純函式，不做任何 I/O。
"""

import builtins
import hashlib
import json
import socket
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from secscan.core.json_types import JsonObject
from secscan.specs.domain.documents import InvalidSpecError, SpecFormat, SpecProblem, parse_document
from secscan.specs.domain.model import SpecOperation
from secscan.specs.domain.openapi import (
    MAX_DOCUMENT_BYTES,
    MAX_OPERATIONS,
    OPERATION_ID_MAX_LENGTH,
    normalize_spec,
)
from secscan.targets.domain import parse_origin

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "openapi" / "vampi-openapi3.yml"
# tests/fixtures/manifest.json 的 openapi_fixtures：範例 JWT 已遮罩，其他位元組與 T03 的輸入相同。
VAMPI_SHA256 = "039f567e37521f960c8bda26b6b38149303b961f3cb5e7bb3f6c1b99d265ab92"
VAMPI = parse_origin("http://vampi-vuln:5000")
INVALID, UNSUPPORTED, EXTERNAL, TOO_LARGE = (
    SpecProblem.INVALID,
    SpecProblem.UNSUPPORTED,
    SpecProblem.EXTERNAL_REF,
    SpecProblem.TOO_LARGE,
)
CANARY_HOST = "canary-host-0101.example"
CANARY_PASSWORD = "canary-pass-0102"

VAMPI_OPERATIONS = (
    ("GET", "/", "api_views.main.basic"),
    ("GET", "/books/v1", "api_views.books.get_all_books"),
    ("POST", "/books/v1", "api_views.books.add_new_book"),
    ("GET", "/books/v1/{book_title}", "api_views.books.get_by_title"),
    ("GET", "/createdb", "api_views.main.populate_db"),
    ("GET", "/me", "api_views.users.me"),
    ("GET", "/users/v1", "api_views.users.get_all_users"),
    ("GET", "/users/v1/_debug", "api_views.users.debug"),
    ("POST", "/users/v1/login", "api_views.users.login_user"),
    ("POST", "/users/v1/register", "api_views.users.register_user"),
    ("GET", "/users/v1/{username}", "api_views.users.get_by_username"),
    ("DELETE", "/users/v1/{username}", "api_views.users.delete_user"),
    ("PUT", "/users/v1/{username}/email", "api_views.users.update_email"),
    ("PUT", "/users/v1/{username}/password", "api_views.users.update_password"),
)


def _vampi() -> bytes:
    return FIXTURE.read_bytes()


def _spec(**fields: Any) -> JsonObject:
    document: JsonObject = {
        "openapi": "3.0.3",
        "info": {"title": "t", "version": "1"},
        "paths": {"/items/{id}": {"get": {"operationId": "getItem", "responses": {}}}},
    }
    for key, value in fields.items():
        if value is None:
            document.pop(key, None)
        else:
            document[key] = value
    return document


def _normalize(document: JsonObject, *, origin: str = "http://vampi-vuln:5000") -> Any:
    content = json.dumps(document).encode()
    return normalize_spec(content, SpecFormat.JSON, origin=parse_origin(origin))


def _rejected(call: Callable[[], object]) -> InvalidSpecError:
    with pytest.raises(InvalidSpecError) as raised:
        call()
    return raised.value


def _document_of(result: Any) -> Any:
    return json.loads(result.document)


# --- VAmPI ------------------------------------------------------------------------------------


def test_vampi_spec_is_normalized() -> None:
    content = _vampi()

    result = normalize_spec(content, SpecFormat.YAML, origin=VAMPI)

    assert result.source_format is SpecFormat.YAML
    assert result.source_size == len(content) == 19631
    assert result.source_sha256.hex() == VAMPI_SHA256
    assert result.openapi_version == "3.0.1"
    assert result.base_path == ""
    assert result.operations == tuple(
        SpecOperation(method=method, path=path, operation_id=operation_id)
        for method, path, operation_id in VAMPI_OPERATIONS
    )
    assert result.document_sha256 == hashlib.sha256(result.document).digest()
    document = _document_of(result)
    assert document["servers"] == [{"url": "http://vampi-vuln:5000"}]
    assert b"localhost" not in result.document
    assert document["paths"].keys() == parse_document(content, SpecFormat.YAML)["paths"].keys()  # type: ignore[union-attr]


def test_document_is_canonical_json() -> None:
    result = normalize_spec(_vampi(), SpecFormat.YAML, origin=VAMPI)

    text = result.document.decode()
    assert text == json.dumps(
        json.loads(text), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def test_same_content_as_json_or_yaml_gives_the_same_document() -> None:
    from_yaml = normalize_spec(_vampi(), SpecFormat.YAML, origin=VAMPI)
    parsed = parse_document(_vampi(), SpecFormat.YAML)
    reordered = dict(reversed(list(parsed.items())))
    as_json = json.dumps(reordered, indent=2).encode()

    from_json = normalize_spec(as_json, SpecFormat.JSON, origin=VAMPI)

    assert from_json.document == from_yaml.document
    assert from_json.document_sha256 == from_yaml.document_sha256
    assert from_json.source_sha256 != from_yaml.source_sha256
    assert from_json.source_format is SpecFormat.JSON


def test_spec_parsing_never_touches_the_network_or_files(monkeypatch: pytest.MonkeyPatch) -> None:
    """平台本身不做任何 I/O：外部參照、servers 指向哪裡，都只會被檢查或丟掉。"""

    content = _vampi()

    def blocked(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("規格的解析不可以連網或開檔")

    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(urllib.request, "urlopen", blocked)
    monkeypatch.setattr(builtins, "open", blocked)
    hostile = [
        _spec(servers=[{"url": f"http://{CANARY_HOST}/api"}]),
        _spec(components={"schemas": {"A": {"$ref": f"http://{CANARY_HOST}/a.yaml"}}}),
        _spec(components={"schemas": {"A": {"$ref": "file:///etc/passwd"}}}),
        _spec(components={"examples": {"e": {"externalValue": f"http://{CANARY_HOST}/e"}}}),
    ]

    normalize_spec(content, SpecFormat.YAML, origin=VAMPI)
    for document in hostile:
        try:
            _normalize(document)
        except InvalidSpecError:
            continue


# --- 版本與頂層 -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fields", "problem"),
    [
        ({"openapi": None, "swagger": "2.0"}, UNSUPPORTED),
        ({"openapi": None}, INVALID),
        ({"openapi": "3.1.0"}, UNSUPPORTED),
        ({"openapi": "2.0"}, UNSUPPORTED),
        ({"openapi": "3.0"}, UNSUPPORTED),
        ({"openapi": "3.0.04"}, UNSUPPORTED),
        ({"openapi": 3.0}, INVALID),
        ({"webhooks": {}}, UNSUPPORTED),
        ({"jsonSchemaDialect": "x"}, UNSUPPORTED),
        ({"unknown": 1}, UNSUPPORTED),
        ({"info": None}, INVALID),
        ({"info": "t"}, INVALID),
        ({"info": {"title": "t"}}, INVALID),
        ({"info": {"title": 1, "version": "1"}}, INVALID),
        ({"info": {"title": "t", "version": 1.0}}, INVALID),
        ({"paths": None}, INVALID),
        ({"paths": []}, INVALID),
        ({"components": []}, INVALID),
    ],
)
def test_version_and_top_level_rules(fields: dict[str, Any], problem: SpecProblem) -> None:
    assert _rejected(lambda: _normalize(_spec(**fields))).problem is problem


@pytest.mark.parametrize("version", ["3.0.0", "3.0.3", "3.0.4", "3.0.10"])
def test_every_3_0_patch_version_is_accepted(version: str) -> None:
    assert _normalize(_spec(openapi=version)).openapi_version == version


def test_extensions_and_known_fields_are_accepted() -> None:
    result = _normalize(
        _spec(
            **{
                "x-anything": {"a": 1},
                "tags": [{"name": "t"}],
                "security": [],
                "externalDocs": {"url": "https://example.com/docs"},
                "components": {"schemas": {}},
            }
        )
    )

    assert result.operations == (SpecOperation("GET", "/items/{id}", "getItem"),)


def test_empty_paths_give_an_empty_inventory() -> None:
    assert _normalize(_spec(paths={})).operations == ()


# --- paths 與 operation ---------------------------------------------------------------------


def _paths(paths: dict[str, Any]) -> JsonObject:
    return _spec(paths=paths)


def test_inventory_lists_every_method_in_a_stable_order() -> None:
    methods = ("trace", "patch", "head", "options", "delete", "post", "put", "get")
    item: dict[str, Any] = {method: {} for method in methods}
    result = _normalize(_paths({"/b": item, "/a": {"get": {}}, "x-meta": {"get": {}}}))

    assert [(operation.method, operation.path) for operation in result.operations] == [
        ("GET", "/a"),
        *(
            (method, "/b")
            for method in ("GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE")
        ),
    ]
    assert all(operation.operation_id is None for operation in result.operations)


def test_trailing_slash_routes_are_distinct() -> None:
    result = _normalize(_paths({"/users": {"get": {}}, "/users/": {"get": {}}}))

    assert [operation.path for operation in result.operations] == ["/users", "/users/"]


@pytest.mark.parametrize(
    ("paths", "problem"),
    [
        ({"users": {"get": {}}}, INVALID),
        ({"/files/{name}.json": {"get": {}}}, INVALID),
        ({"/a/../b": {"get": {}}}, INVALID),
        ({"/a%2fb": {"get": {}}}, INVALID),
        ({"/a;b": {"get": {}}}, INVALID),
        ({"/users/{id}": {"get": {}}, "/users/{name}": {"put": {}}}, INVALID),
        ({"/a": "x"}, INVALID),
        ({"/a": {"get": "x"}}, INVALID),
        ({"/a": {"query": {}}}, INVALID),
        ({"/a": {"$ref": "#/paths/~1b"}, "/b": {"get": {}}}, UNSUPPORTED),
        ({"/a": {"servers": [{"url": "/x"}], "get": {}}}, UNSUPPORTED),
        ({"/a": {"get": {"servers": [{"url": "/x"}]}}}, UNSUPPORTED),
        ({"/a": {"get": {"callbacks": {"c": {}}}}}, UNSUPPORTED),
    ],
    ids=[
        "no-leading-slash",
        "partial-placeholder",
        "dot-segment",
        "percent-encoding",
        "semicolon",
        "same-route",
        "path-item-not-object",
        "operation-not-object",
        "unknown-path-item-field",
        "path-item-ref",
        "path-servers",
        "operation-servers",
        "callbacks",
    ],
)
def test_path_and_operation_rules(paths: dict[str, Any], problem: SpecProblem) -> None:
    assert _rejected(lambda: _normalize(_paths(paths))).problem is problem


def test_path_errors_point_at_the_path() -> None:
    error = _rejected(lambda: _normalize(_paths({"/ok": {"get": {}}, "/a%2fb": {"get": {}}})))

    assert "#/paths/~1a%2fb" in error.message


def test_full_path_length_includes_the_base_path() -> None:
    base = "/" + "b" * 100
    path = "/" + "p" * (512 - len(base) - 1)
    assert _normalize(_spec(servers=[{"url": base}], paths={path: {"get": {}}})).operations

    too_long = path + "p"
    error = _rejected(
        lambda: _normalize(_spec(servers=[{"url": base}], paths={too_long: {"get": {}}}))
    )
    assert error.problem is INVALID


def test_operation_count_is_bounded() -> None:
    def paths(count: int) -> dict[str, Any]:
        return {f"/p{index}": {"get": {}} for index in range(count)}

    assert len(_normalize(_paths(paths(MAX_OPERATIONS))).operations) == MAX_OPERATIONS
    assert _rejected(lambda: _normalize(_paths(paths(MAX_OPERATIONS + 1)))).problem is INVALID


@pytest.mark.parametrize(
    "operation_id",
    ["", "   ", None, 7, "a\nb", "a‮b", "x" * (OPERATION_ID_MAX_LENGTH + 1)],
    ids=["empty", "blank", "null", "number", "newline", "bidi", "too-long"],
)
def test_operation_id_rules(operation_id: Any) -> None:
    paths = {"/a": {"get": {"operationId": operation_id}}}

    assert _rejected(lambda: _normalize(_paths(paths))).problem is INVALID


def test_operation_ids_must_be_unique() -> None:
    longest = "x" * OPERATION_ID_MAX_LENGTH
    assert _normalize(_paths({"/a": {"get": {"operationId": longest}}})).operations

    duplicate = {"/a": {"get": {"operationId": "op"}}, "/b": {"post": {"operationId": "op"}}}
    assert _rejected(lambda: _normalize(_paths(duplicate))).problem is INVALID


# --- servers -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("servers", "base_path"),
    [
        (None, ""),
        ([], ""),
        ([{"url": "http://localhost:5000"}], ""),
        ([{"url": "http://localhost:5000/"}], ""),
        ([{"url": "/"}], ""),
        ([{"url": "http://example.com/api/v1/"}], "/api/v1"),
        ([{"url": "/b2b/v2"}], "/b2b/v2"),
        ([{"url": "HTTPS://Other:8443/api"}], "/api"),
        ([{"url": f"http://user:{CANARY_PASSWORD}@{CANARY_HOST}/api"}], "/api"),
        ([{"url": "http://10.0.0.1/api"}, {"url": "https://staging/api/"}], "/api"),
        ([{"url": "/api", "description": "d", "variables": {}}], "/api"),
    ],
    ids=[
        "absent",
        "empty",
        "host-only",
        "host-slash",
        "root",
        "absolute-with-path",
        "relative",
        "https-upper",
        "userinfo",
        "same-base-path",
        "extra-fields",
    ],
)
def test_servers_are_rebound_to_the_target_origin(servers: Any, base_path: str) -> None:
    result = _normalize(_spec(servers=servers))

    assert result.base_path == base_path
    assert _document_of(result)["servers"] == [{"url": f"http://vampi-vuln:5000{base_path}"}]
    for original in (CANARY_HOST, CANARY_PASSWORD, "localhost", "staging", "10.0.0.1", "Other"):
        assert original.encode() not in result.document


@pytest.mark.parametrize("url", ["api/v1", f"ftp://{CANARY_HOST}/x", "http:/api"])
def test_server_url_errors_explain_the_accepted_forms(url: str) -> None:
    error = _rejected(lambda: _normalize(_spec(servers=[{"url": url}])))

    assert "http(s)://主機/… 或以 / 開頭的 path" in error.message


def test_base_path_is_part_of_every_operation_path() -> None:
    result = _normalize(
        _spec(servers=[{"url": "/b2b/v2"}], paths={"/orders": {"post": {}}, "/": {"get": {}}}),
        origin="http://juice-shop:3000",
    )

    assert [operation.path for operation in result.operations] == ["/b2b/v2/", "/b2b/v2/orders"]
    assert _document_of(result)["servers"] == [{"url": "http://juice-shop:3000/b2b/v2"}]


@pytest.mark.parametrize(
    ("servers", "problem"),
    [
        ([{"url": "/a"}, {"url": "/b"}], UNSUPPORTED),
        ([{"url": "{scheme}://host/api"}], UNSUPPORTED),
        ([{"url": "http://host/{version}"}], UNSUPPORTED),
        ([{"url": "api/v1"}], INVALID),
        ([{"url": f"//{CANARY_HOST}/api"}], INVALID),
        ([{"url": f"ftp://{CANARY_HOST}/x"}], INVALID),
        ([{"url": "http:/api"}], INVALID),
        ([{"url": "javascript:alert(1)"}], INVALID),
        ([{"url": f"localhost:{CANARY_PASSWORD}"}], INVALID),
        ([{"url": "/api?x=1"}], INVALID),
        ([{"url": "/api#x"}], INVALID),
        ([{"url": "/a b"}], INVALID),
        ([{"url": " /api"}], INVALID),
        ([{"url": ""}], INVALID),
        ([{"url": "/café"}], INVALID),
        ([{"url": "/a/%2e%2e"}], INVALID),
        ([{"url": "/a//b"}], INVALID),
        ({"url": "/api"}, INVALID),
        (["/api"], INVALID),
        ([{"url": 1}], INVALID),
        ([{}], INVALID),
    ],
    ids=[
        "different-base-paths",
        "variable-scheme",
        "variable-path",
        "relative-without-slash",
        "network-path",
        "ftp",
        "no-host",
        "javascript",
        "host-without-scheme",
        "query",
        "fragment",
        "space",
        "leading-space",
        "empty",
        "non-ascii",
        "encoded-dots",
        "empty-segment",
        "not-a-list",
        "entry-not-object",
        "url-not-string",
        "missing-url",
    ],
)
def test_server_rules(servers: Any, problem: SpecProblem) -> None:
    error = _rejected(lambda: _normalize(_spec(servers=servers)))

    assert error.problem is problem
    assert CANARY_HOST not in error.message
    assert CANARY_PASSWORD not in error.message


# --- 其他會讓工具連到別處的功能 ----------------------------------------------------------------


@pytest.mark.parametrize(
    "components",
    [
        {"callbacks": {"c": {}}},
        {"links": {"l": {"operationId": "getItem", "server": {"url": f"http://{CANARY_HOST}"}}}},
        {"responses": {"r": {"description": "d", "links": {"l": {"server": {"url": "/x"}}}}}},
        {"securitySchemes": {"o": {"type": "oauth2", "flows": {}}}},
        {"securitySchemes": {"o": {"type": "openIdConnect", "openIdConnectUrl": "http://x/"}}},
    ],
    ids=["callbacks", "link-server", "response-link-server", "oauth2", "openid-connect"],
)
def test_components_that_reach_other_places_are_unsupported(components: JsonObject) -> None:
    error = _rejected(lambda: _normalize(_spec(components=components)))

    assert error.problem is UNSUPPORTED
    assert CANARY_HOST not in error.message


def test_link_servers_inside_operations_are_unsupported() -> None:
    responses = {"200": {"description": "d", "links": {"l": {"server": {"url": "/x"}}}}}
    paths = {"/a": {"get": {"responses": responses}}}

    assert _rejected(lambda: _normalize(_paths(paths))).problem is UNSUPPORTED


def test_links_and_schemes_without_external_addresses_are_accepted() -> None:
    components: JsonObject = {
        "links": {"self": {"operationId": "getItem"}, "ref": {"$ref": "#/components/links/self"}},
        "responses": {
            "ok": {"description": "d", "links": {"self": {"$ref": "#/components/links/self"}}},
            "plain": {"description": "d"},
            "alias": {"$ref": "#/components/responses/plain"},
        },
        "securitySchemes": {
            "bearer": {"type": "http", "scheme": "bearer"},
            "key": {"type": "apiKey", "in": "header", "name": "X-Key"},
            "alias": {"$ref": "#/components/securitySchemes/bearer"},
        },
    }
    paths = {
        "/items/{id}": {
            "get": {
                "operationId": "getItem",
                "responses": {"200": {"$ref": "#/components/responses/ok"}, "x-note": "n"},
            }
        }
    }

    assert _normalize(_spec(components=components, paths=paths)).operations


def test_external_references_are_reported_through_normalization() -> None:
    document = _spec(components={"schemas": {"A": {"$ref": f"http://{CANARY_HOST}/a.yaml"}}})

    error = _rejected(lambda: _normalize(document))

    assert error.problem is EXTERNAL
    assert CANARY_HOST not in error.message


# --- 大小 -------------------------------------------------------------------------------------


def test_document_size_limit_applies_after_normalization() -> None:
    assert MAX_DOCUMENT_BYTES == 2 * 1024 * 1024
    content = json.dumps(_spec()).encode()
    size = len(normalize_spec(content, SpecFormat.JSON, origin=VAMPI).document)

    normalize_spec(content, SpecFormat.JSON, origin=VAMPI, max_document_bytes=size)
    error = _rejected(
        lambda: normalize_spec(content, SpecFormat.JSON, origin=VAMPI, max_document_bytes=size - 1)
    )
    assert error.problem is TOO_LARGE
