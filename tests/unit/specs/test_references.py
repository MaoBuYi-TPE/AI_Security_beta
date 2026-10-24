"""文件中的參照（docs/DECISIONS.md §11.4）；純函式。

`$ref`、`operationRef` 只接受指得到節點的內部 JSON Pointer；discriminator 的 mapping 只接受
`#/components/schemas/<名稱>`；externalValue 與 JSON Schema 的識別字一律拒絕。
「任何位置」包含 example 與 x- 擴充。錯誤訊息指出位置，但不含參照的值（可能是帶帳密的 URL）。
"""

from collections.abc import Callable
from typing import Any

import pytest

from secscan.core.json_types import JsonObject, JsonValue
from secscan.specs.domain import references
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
                        "mapping": {"user": "#/components/schemas/User"},
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
        ("Dog.json", UNSUPPORTED),
        ("../dog.json", EXTERNAL),
        ("https://example.com/dog.json", EXTERNAL),
        ("User", UNSUPPORTED),
        ("#/components/schemas/Missing", INVALID),
        ("#/components/parameters/Id", UNSUPPORTED),
        ("#/components/schemas/User/properties/friend", UNSUPPORTED),
        ("#/x-elsewhere", UNSUPPORTED),
        ("#Dog", UNSUPPORTED),
        (3, INVALID),
    ],
)
def test_discriminator_mapping_values(mapping_value: JsonValue, problem: SpecProblem) -> None:
    document: Any = _document()
    document["components"]["schemas"]["Pet"]["discriminator"]["mapping"]["bad"] = mapping_value

    assert _rejected(lambda: check_references(document)).problem is problem


def test_discriminator_mapping_names_are_not_accepted() -> None:
    """審查發現：schema 的名稱本身可以是 URL，工具可能把 mapping 的名稱當成 URI reference。

    所以只接受 `#/components/schemas/<名稱>`，即使同名的 schema 存在。
    """
    pet: JsonObject = {"discriminator": {"mapping": {"a": "Pet"}}}
    named = _bare({"schemas": {"Pet": pet}})

    assert _rejected(lambda: check_references(named)).problem is UNSUPPORTED
    pet["discriminator"] = {"mapping": {"a": "#/components/schemas/Pet"}}
    check_references(named)


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


# --- 審查後補上：成本有上限、不會變成其他例外 ---------------------------------------------------


def test_valid_documents_never_render_positions(monkeypatch: pytest.MonkeyPatch) -> None:
    """位置字串只在要拋錯時才組：合法的文件不付這個成本（審查發現的 CPU 放大）。"""

    def must_not_render(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("合法的文件不應計算位置字串")

    monkeypatch.setattr(references, "pointer_text", must_not_render)
    document = _document()
    document["x-" + "k" * 10_000] = [{"$ref": "#/components/schemas/Pet"}] * 500

    check_references(document)


def test_shared_reference_chains_are_walked_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """很多參照指向同一條參照鏈時，已確認的鏈不再重走（審查發現的 CPU 放大）。"""
    schemas: JsonObject = {
        f"S{index}": {"$ref": f"#/components/schemas/S{index + 1}"}
        for index in range(MAX_REF_CHAIN - 1)
    }
    schemas[f"S{MAX_REF_CHAIN - 1}"] = {"type": "string"}
    document = _bare({"schemas": schemas})
    document["x-uses"] = [{"$ref": "#/components/schemas/S0"}] * 2_000
    calls = 0
    original = references._resolve

    def counting(*args: Any, **kwargs: Any) -> JsonValue:
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(references, "_resolve", counting)

    check_references(document)

    assert calls < 3 * (2_000 + MAX_REF_CHAIN)


def test_huge_array_indexes_are_invalid_not_a_crash() -> None:
    """int() 對超過 4,300 位的字串拋出 ValueError，不能變成 500。"""
    document = _document()
    document["x-use"] = {"$ref": "#/paths/~1users~1{id}/get/parameters/" + "1" * 5_000}

    assert _rejected(lambda: check_references(document)).problem is INVALID


def test_settled_chains_still_count_toward_the_limit() -> None:
    """接上已確認的鏈時，長度要加上那條鏈剩下的部分（快取不能讓長鏈逃過上限）。

    x-use 放在最前面：走訪時它最後才處理，那時整條鏈都已經確認過了。
    """
    schemas: JsonObject = {
        f"S{index}": {"$ref": f"#/components/schemas/S{index + 1}"}
        for index in range(MAX_REF_CHAIN)
    }
    schemas[f"S{MAX_REF_CHAIN}"] = {"type": "string"}
    document: JsonObject = {
        "x-use": {"$ref": "#/components/schemas/S0"},
        **_bare({"schemas": schemas}),
    }

    error = _rejected(lambda: check_references(document))

    assert error.problem is INVALID
    assert "參照鏈" in error.message


def test_long_chains_stop_walking_at_the_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """還沒確認過的長鏈走到上限就停，不走完整條（循環的判斷有錯時也一定會結束）。

    名稱倒著放：走訪時 S0 最先處理，那時整條鏈都還沒確認。
    """
    length = 5_000
    schemas: JsonObject = {
        f"S{index}": {"$ref": f"#/components/schemas/S{index + 1}"}
        for index in reversed(range(length))
    }
    schemas[f"S{length}"] = {"type": "string"}
    calls = 0
    original = references._resolve

    def counting(*args: Any, **kwargs: Any) -> JsonValue:
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(references, "_resolve", counting)

    error = _rejected(lambda: check_references(_bare({"schemas": schemas})))

    assert "參照鏈" in error.message
    # 走訪時每個參照解析一次，之後只多走上限那麼多步。
    assert calls <= length + MAX_REF_CHAIN
