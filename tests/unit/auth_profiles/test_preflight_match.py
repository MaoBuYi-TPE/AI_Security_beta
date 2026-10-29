"""preflight 的比對（docs/DECISIONS.md §12.5；T08 只定義，T12 照著實作）。

- 狀態碼相同，而且 expected_json 的每一項都嚴格相等（型別也要相同：true 不等於 1）。
- JSON Pointer 依 RFC 6901 解析，含陣列索引；指不到就不符合。索引有前導 0（01）或是 -，算指不到。
- 回應必須是 JSON（呼叫端解析好的值；不是 JSON 時傳入 NOT_JSON）。
"""

from typing import Any

import pytest

from secscan.auth_profiles.domain.preflight import NOT_JSON, Preflight, matches


def _preflight(**expected: Any) -> Preflight:
    return Preflight(
        method="GET", path="/me", expected_status=200, expected_json=expected or {"/ok": True}
    )


BODY = {
    "ok": True,
    "count": 1,
    "user": {"name": "alice", "roles": ["admin", "user"], "a/b": "slash", "m~n": "tilde"},
    "nothing": None,
}


@pytest.mark.parametrize(
    "expected",
    [
        {"/ok": True},
        {"/count": 1},
        {"/user/name": "alice", "/user/roles/0": "admin", "/user/roles/1": "user"},
        {"/user/a~1b": "slash", "/user/m~0n": "tilde"},
        {"/nothing": None},
    ],
)
def test_every_expected_item_must_be_strictly_equal(expected: dict[str, Any]) -> None:
    assert matches(Preflight("GET", "/me", 200, expected), 200, BODY)


@pytest.mark.parametrize(
    "expected",
    [
        {"/ok": 1},  # true 不等於 1
        {"/count": True},  # 1 不等於 true
        {"/count": "1"},
        {"/nothing": False},
        {"/user/name": "Alice"},
        {"/user/roles/01": "user"},  # 前導 0：指不到
        {"/user/roles/-": "user"},  # 最後一個之後：指不到
        {"/user/roles/2": "user"},
        {"/user/roles/x": "user"},
        {"/missing": None},  # 指不到不等於 null
        {"/user/name/0": "a"},  # 字串不能再往下
        {"/ok": True, "/count": 2},  # 全部都要符合
    ],
)
def test_anything_else_does_not_match(expected: dict[str, Any]) -> None:
    assert not matches(Preflight("GET", "/me", 200, expected), 200, BODY)


def test_the_status_must_be_the_expected_one() -> None:
    assert not matches(_preflight(), 201, BODY)


def test_the_response_must_be_json() -> None:
    assert not matches(_preflight(), 200, NOT_JSON)


def test_a_root_that_is_not_an_object_does_not_match() -> None:
    assert not matches(_preflight(), 200, ["ok"])
    assert not matches(_preflight(), 200, "ok")


def test_the_empty_token_is_a_key() -> None:
    assert matches(Preflight("GET", "/me", 200, {"/": "empty"}), 200, {"": "empty"})
