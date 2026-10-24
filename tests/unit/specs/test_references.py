"""文件中的參照（docs/DECISIONS.md §11.4）；純函式。

`$ref`、`operationRef` 只接受指得到節點的內部 JSON Pointer；discriminator 的 mapping 只接受
schema 名稱或內部參照；externalValue 與 JSON Schema 的識別字一律拒絕。「任何位置」包含 example
與 x- 擴充。錯誤訊息指出位置，但不含參照的值（可能是帶帳密的 URL）。
"""

from collections.abc import Callable
from typing import Any

import pytest

from secscan.core.json_types import JsonObject, JsonValue
from secscan.specs.domain.documents import InvalidSpecError, SpecProblem
from secscan.specs.domain.references import MAX_REF_CHAIN, check_references

INVALID, UNSUPPORTED, EXTERNAL = (
    SpecProblem.INVALID,
    SpecProblem.UNSUPPORTED,
    SpecProblem.EXTERNAL_REF,
)
SECRET_URL = "http://user:canary-pass-0099@evil.example/x.yaml"


def _document(**extra: JsonValue) -> JsonObject:
    return {
        "openapi": "3.0.3",
        "paths": {
            "/users/{id}": {
                "get": {
                    "parameters": [{"$ref": "#/components/parameters/Id"}],
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/User"}
                                }
                            },
                            "links": {"self": {"operationRef": "#/paths/~1users~1{id}/get"}},
                        }
                    },
                }
            }
        },
        "components": {
            "parameters": {"Id": {"name": "id", "in": "path", "required": True}},
            "schemas": {
                "User": {
                    "type": "object",
                    # schema 的遞迴（屬性引用自己）不是只由參照組成的循環。
                    "properties": {"friend": {"$ref": "#/components/schemas/User"}},
                },
                "Pet": {
                    "oneOf": [{"$ref": "#/components/schemas/User"}],
                    "discriminator": {
                        "propertyName": "kind",
                        "mapping": {"user": "#/components/schemas/User", "named": "User"},
                    },
                },
                "Tags": {"type": "array", "items": {"$ref": "#/components/schemas/Pet/oneOf/0"}},
            },
        },
        **extra,
    }


def _bare(components: JsonObject) -> JsonObject:
    """只有 components 的文件（替換 components 時，其他地方不會有懸空的參照）。"""
    return {"openapi": "3.0.3", "paths": {}, "components": components}


def _with_ref(value: JsonValue, *, key: str = "$ref") -> JsonObject:
    document = _document()
    document["x-extra"] = {"nested": [{key: value}]}
    return document


def _rejected(call: Callable[[], object]) -> InvalidSpecError:
    with pytest.raises(InvalidSpecError) as raised:
        call()
    return raised.value


def test_internal_references_are_accepted() -> None:
    check_references(_document())


@pytest.mark.parametrize(
    "value",
    [
        SECRET_URL,
        "https://example.com/schemas.json#/User",
        "file:///etc/passwd",
        "./other.yaml",
        "other.yaml#/components/schemas/User",
        "/absolute/path.yaml",
        "//evil.example/x",
        "urn:example:schema",
        "",
    ],
    ids=[
        *("http-userinfo", "https", "file", "relative", "relative-fragment", "absolute"),
        *("network-path", "urn", "empty"),
    ],
)
@pytest.mark.parametrize("key", ["$ref", "operationRef"])
def test_external_references_are_forbidden(value: str, key: str) -> None:
    error = _rejected(lambda: check_references(_with_ref(value, key=key)))

    assert error.problem is EXTERNAL
    assert "#/x-extra/nested/0" in error.message
    assert "canary-pass" not in error.message
    assert "evil" not in error.message


@pytest.mark.parametrize(
    ("value", "problem"),
    [
        ("#", UNSUPPORTED),
        ("#User", UNSUPPORTED),
        ("#/components/schemas/My%20User", UNSUPPORTED),
        ("#/components/schemas/Us er", UNSUPPORTED),
        ("#/components/schemas/Usér", UNSUPPORTED),
        ("#/components/schemas/Missing", INVALID),
        ("#/components/schemas/User/properties/friend/$ref/x", INVALID),
        ("#/paths/~1users~1{id}/get/parameters/1", INVALID),
        ("#/paths/~1users~1{id}/get/parameters/00", INVALID),
        ("#/paths/~1users~1{id}/get/parameters/-", INVALID),
        ("#/components/schemas/~2", INVALID),
        ("#/components/schemas/a~", INVALID),
        (["#/components/schemas/User"], INVALID),
        ({"$ref": "#/components/schemas/User"}, INVALID),
    ],
    ids=[
        "whole-document",
        "anchor-form",
        "percent-encoding",
        "space",
        "non-ascii",
        "dangling",
        "into-a-string",
        "index-out-of-range",
        "index-leading-zero",
        "index-dash",
        "bad-escape",
        "trailing-tilde",
        "not-a-string-list",
        "not-a-string-object",
    ],
)
def test_internal_reference_rules(value: JsonValue, problem: SpecProblem) -> None:
    assert _rejected(lambda: check_references(_with_ref(value))).problem is problem


def test_invalid_escapes_are_rejected_even_if_a_key_matches_literally() -> None:
    """`~2` 不是合法的跳脫：即使文件中剛好有 key `a~2`，也不可以照字面去比對。"""
    document = _bare({"schemas": {"a~2": {"type": "string"}}})
    document["x-use"] = {"$ref": "#/components/schemas/a~2"}

    error = _rejected(lambda: check_references(document))

    assert error.problem is INVALID
    assert "~0 或 ~1" in error.message


def test_json_pointer_escapes_are_decoded() -> None:
    document = _document()
    document["x-keys"] = {"a/b": {"c~d": 1}}
    document["x-use"] = {"$ref": "#/x-keys/a~1b/c~0d"}

    check_references(document)


@pytest.mark.parametrize(
    "chain",
    [
        {"A": {"$ref": "#/components/schemas/A"}},
        {"A": {"$ref": "#/components/schemas/B"}, "B": {"$ref": "#/components/schemas/A"}},
        {
            "A": {"$ref": "#/components/schemas/B"},
            "B": {"$ref": "#/components/schemas/C"},
            "C": {"$ref": "#/components/schemas/B"},
        },
    ],
    ids=["self", "two", "tail-loop"],
)
def test_reference_only_cycles_are_rejected(chain: JsonObject) -> None:
    error = _rejected(lambda: check_references(_bare({"schemas": chain})))

    assert error.problem is INVALID
    assert "循環" in error.message


def test_reference_chains_are_bounded() -> None:
    def chain(length: int) -> JsonObject:
        schemas: JsonObject = {
            f"S{index}": {"$ref": f"#/components/schemas/S{index + 1}"} for index in range(length)
        }
        schemas[f"S{length}"] = {"type": "string"}
        return _bare({"schemas": schemas})

    check_references(chain(MAX_REF_CHAIN))
    error = _rejected(lambda: check_references(chain(MAX_REF_CHAIN + 1)))
    assert error.problem is INVALID


@pytest.mark.parametrize(
    ("mapping_value", "problem"),
    [
        ("Dog.json", EXTERNAL),
        ("https://example.com/dog.json", EXTERNAL),
        ("#/components/schemas/Missing", INVALID),
        ("#Dog", UNSUPPORTED),
        (3, INVALID),
    ],
)
def test_discriminator_mapping_values(mapping_value: JsonValue, problem: SpecProblem) -> None:
    document: Any = _document()
    document["components"]["schemas"]["Pet"]["discriminator"]["mapping"]["bad"] = mapping_value

    assert _rejected(lambda: check_references(document)).problem is problem


def test_discriminator_names_need_a_schemas_object() -> None:
    pet: JsonObject = {"discriminator": {"mapping": {"a": "Pet"}}}
    check_references(_bare({"schemas": {"Pet": pet}}))

    without_schemas = _bare({"x-schemas": {"Pet": pet}})
    assert _rejected(lambda: check_references(without_schemas)).problem is EXTERNAL


@pytest.mark.parametrize(
    "key",
    [
        "externalValue",
        "$id",
        "$schema",
        "$anchor",
        "$dynamicRef",
        "$dynamicAnchor",
        "$recursiveRef",
        "$recursiveAnchor",
    ],
)
def test_keywords_that_reach_outside_are_rejected_anywhere(key: str) -> None:
    error = _rejected(lambda: check_references(_with_ref(SECRET_URL, key=key)))

    assert error.problem is UNSUPPORTED
    assert "#/x-extra/nested/0" in error.message
    assert "canary-pass" not in error.message


def test_references_inside_examples_are_still_references() -> None:
    """寧可誤拒：example 中剛好有 $ref 的 key，也當成參照檢查。"""
    document: Any = _document()
    document["components"]["examples"] = {"e": {"value": {"$ref": SECRET_URL}}}

    assert _rejected(lambda: check_references(document)).problem is EXTERNAL
