"""preflight 的定義（docs/DECISIONS.md §12.5）：GET、沒有佔位的 path、2xx、至少一項 JSON 比對。

T08 只定義與驗證，T12 才實際執行。錯誤訊息不回顯輸入（期望值可能是帳號或 email）。
"""

from types import MappingProxyType
from typing import cast

import pytest
from hypothesis import given
from hypothesis import strategies as st

from secscan.auth_profiles.domain.errors import InvalidAuthProfileError
from secscan.auth_profiles.domain.preflight import (
    EXPECTED_TEXT_MAX_LENGTH,
    MAX_EXPECTED_ITEMS,
    MAX_SAFE_INTEGER,
    POINTER_MAX_LENGTH,
    ExpectedValue,
    Preflight,
    parse_pointer,
)
from secscan.grants.domain.scope import PATH_MAX_LENGTH

CANARY = "canary7f3a"
VAMPI_ME = {"/data/username": "name1", "/status": "success"}


def _preflight(**overrides: object) -> Preflight:
    params: dict[str, object] = {
        "method": "GET",
        "path": "/me",
        "expected_status": 200,
        "expected_json": VAMPI_ME,
    }
    params.update(overrides)
    return Preflight(**params)  # type: ignore[arg-type]


def _rejected(**overrides: object) -> str:
    with pytest.raises(InvalidAuthProfileError) as raised:
        _preflight(**overrides)
    message = str(raised.value)
    assert message.startswith("preflight")
    assert CANARY not in message
    return message


def test_vampi_me_is_a_valid_preflight() -> None:
    preflight = _preflight()

    assert (preflight.method, preflight.path, preflight.expected_status) == ("GET", "/me", 200)
    assert dict(preflight.expected_json) == VAMPI_ME


# --- method ---------------------------------------------------------------------------------


@pytest.mark.parametrize("method", ["get", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE", ""])
def test_only_get_is_accepted(method: str) -> None:
    assert "GET" in _rejected(method=method)


# --- path -----------------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/", "/me", "/users/v1/name1", "/a/b/", "/books/v1/bookTitle77"])
def test_concrete_paths_are_accepted(path: str) -> None:
    assert _preflight(path=path).path == path


@pytest.mark.parametrize(
    "path",
    [
        "",
        "me",
        f"/{CANARY}//b",
        f"/{CANARY}/../b",
        f"/{CANARY}?x=1",
        f"/{CANARY}#f",
        f"/{CANARY}%20b",
        f"/{CANARY};b",
        f"/{CANARY} b",
        f"/{CANARY}é",
        "/" + "a" * PATH_MAX_LENGTH,
    ],
)
def test_paths_follow_the_grant_syntax(path: str) -> None:
    assert "path" in _rejected(path=path)


@pytest.mark.parametrize("path", ["/users/{id}", "/a/{b}/c", f"/{CANARY}/{{name}}"])
def test_placeholders_are_rejected(path: str) -> None:
    """preflight 是實際送出的請求，path 要寫實際的值。"""
    assert "佔位" in _rejected(path=path)


# --- expected_status ------------------------------------------------------------------------


@pytest.mark.parametrize("status", [200, 201, 204, 299])
def test_expected_status_is_2xx(status: int) -> None:
    assert _preflight(expected_status=status).expected_status == status


@pytest.mark.parametrize("status", [199, 300, 302, 401, 404, 500, True, "200", 200.0])
def test_other_expected_statuses_are_rejected(status: object) -> None:
    assert "expected_status" in _rejected(expected_status=status)


# --- expected_json：數量 --------------------------------------------------------------------


def test_status_alone_is_not_enough() -> None:
    """只看狀態碼分不出登入頁：至少要比對一項內容。"""
    assert "登入頁" in _rejected(expected_json={})


def test_at_most_sixteen_checks() -> None:
    allowed = {f"/k{index}": index for index in range(MAX_EXPECTED_ITEMS)}

    assert len(_preflight(expected_json=allowed).expected_json) == MAX_EXPECTED_ITEMS
    too_many = {f"/k{index}": index for index in range(MAX_EXPECTED_ITEMS + 1)}
    assert "expected_json" in _rejected(expected_json=too_many)


def test_expected_json_must_be_an_object() -> None:
    assert "expected_json" in _rejected(expected_json=[("/a", 1)])


# --- expected_json：pointer -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("pointer", "tokens"),
    [
        ("/", ("",)),
        ("/a", ("a",)),
        ("/data/username", ("data", "username")),
        ("/items/0/name", ("items", "0", "name")),
        ("/a~1b", ("a/b",)),
        ("/a~0b", ("a~b",)),
        ("/~01", ("~1",)),
        ("/使用者", ("使用者",)),
    ],
)
def test_pointers_follow_rfc_6901(pointer: str, tokens: tuple[str, ...]) -> None:
    assert parse_pointer(pointer) == tokens
    assert _preflight(expected_json={pointer: 1}).expected_json == {pointer: 1}


@pytest.mark.parametrize(
    "pointer",
    [
        "",
        CANARY,
        f"#/{CANARY}",
        f"/{CANARY}~",
        f"/{CANARY}~2",
        f"/{CANARY}\n",
        f"/{CANARY}\u200b",
        "/" + "a" * POINTER_MAX_LENGTH,
    ],
)
def test_invalid_pointers_are_rejected_by_position(pointer: str) -> None:
    message = _rejected(expected_json={"/ok": 1, pointer: 2})

    assert "第 2 項" in message


@pytest.mark.parametrize("pointer", ["", CANARY, f"/{CANARY}~2"])
def test_parse_pointer_rejects_invalid_pointers_without_echoing(pointer: str) -> None:
    with pytest.raises(InvalidAuthProfileError) as raised:
        parse_pointer(pointer)

    assert CANARY not in str(raised.value)


def _encode(tokens: list[str]) -> str:
    return "".join("/" + token.replace("~", "~0").replace("/", "~1") for token in tokens)


@given(
    tokens=st.lists(
        st.text(st.characters(exclude_categories=("Cc", "Cf", "Cs")), max_size=8),
        min_size=1,
        max_size=6,
    )
)
def test_encoded_pointers_parse_back_to_the_same_tokens(tokens: list[str]) -> None:
    pointer = _encode(tokens)
    if len(pointer) > POINTER_MAX_LENGTH:
        return

    assert parse_pointer(pointer) == tuple(tokens)


# --- expected_json：值 ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "",
        "name1",
        "x" * EXPECTED_TEXT_MAX_LENGTH,
        0,
        -1,
        MAX_SAFE_INTEGER,
        -MAX_SAFE_INTEGER,
        True,
        False,
        None,
    ],
)
def test_expected_values_are_simple_json_scalars(value: ExpectedValue) -> None:
    assert _preflight(expected_json={"/a": value}).expected_json == {"/a": value}


@pytest.mark.parametrize(
    "value",
    [
        1.0,
        1.5,
        float("nan"),
        MAX_SAFE_INTEGER + 1,
        -MAX_SAFE_INTEGER - 1,
        "x" * (EXPECTED_TEXT_MAX_LENGTH + 1),
        f"{CANARY}\n",
        f"{CANARY}\u202e",
        [CANARY],
        {"a": CANARY},
    ],
)
def test_other_expected_values_are_rejected_by_position(value: object) -> None:
    message = _rejected(expected_json={"/ok": 1, "/b": value})

    assert "第 2 項" in message


# --- 比較與不可變 ---------------------------------------------------------------------------


def test_booleans_are_not_integers() -> None:
    """Python 中 True == 1；比較時型別也要相同，否則把 1 改成 true 會被當成「沒有變更」。"""
    assert _preflight(expected_json={"/a": True}) != _preflight(expected_json={"/a": 1})
    assert _preflight(expected_json={"/a": False}) != _preflight(expected_json={"/a": 0})


def test_comparison_ignores_the_order_of_checks() -> None:
    first = _preflight(expected_json={"/a": 1, "/b": "x"})
    second = _preflight(expected_json={"/b": "x", "/a": 1})

    assert first == second
    assert hash(first) == hash(second)


def test_every_field_takes_part_in_the_comparison() -> None:
    base = _preflight()

    assert base == _preflight()
    assert base != _preflight(path="/users/v1/name1")
    assert base != _preflight(expected_status=201)
    assert base != _preflight(expected_json={"/status": "success"})
    assert base != "not a preflight"


def test_expected_json_cannot_be_changed_after_creation() -> None:
    checks = dict(VAMPI_ME)
    preflight = _preflight(expected_json=checks)
    checks["/status"] = "changed"

    assert preflight.expected_json["/status"] == "success"
    assert isinstance(preflight.expected_json, MappingProxyType)
    with pytest.raises(TypeError):
        cast(dict[str, ExpectedValue], preflight.expected_json)["/status"] = "x"
