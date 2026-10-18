"""遮罩：寫進 audit、log 或一般 API 的資料不得含秘密，而且大小有上限（CLAUDE.md §9）。"""

import random
import time
from types import MappingProxyType

import pytest

from secscan.core.json_types import JsonObject, JsonValue
from secscan.security import redaction
from secscan.security.redaction import (
    MAX_DEPTH,
    MAX_ITEMS,
    MAX_STRING_LENGTH,
    REDACTED,
    TRUNCATED,
    is_sensitive_key,
    redact_json,
    redact_object,
)

SAMPLE_PREFIX = "0123456789abcdef"
PLATFORM_KEY = f"secscan_{SAMPLE_PREFIX}_{'c' * 64}"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJsYWIifQ.c2lnbmF0dXJl"
FUZZ_SEED = 20261019
FUZZ_CASES = 20_000
# 舊的 JWT 樣式遇到這種輸入是 O(n²)：48 KB 要 3 秒。
PATHOLOGICAL_JWT = "eyJ" * 40_000
LINEAR_TIME_BUDGET_SECONDS = 1.0
# 只是私鑰檔的開頭字樣（假資料）；拆開寫，避免被 pre-commit 的 detect-private-key 當成真的私鑰。
PEM_HEADER = "-----BEGIN " + "PRIVATE KEY-----"
# 全形的 PASSWORD（U+FF30…）；以程式產生，原始碼中不放容易誤認的字元。
FULLWIDTH_PASSWORD = "".join(chr(ord(letter) + 0xFEE0) for letter in "PASSWORD")


@pytest.mark.parametrize(
    "key",
    [
        "Authorization",
        "proxy-authorization",
        "Cookie",
        "Set-Cookie",
        "password",
        "db_passwd",
        "passphrase",
        "client_secret",
        "access_token",
        "refresh-token",
        "X-API-Key",
        "apiKey",
        "key_hash",
        "keyHash",
        "credentials",
        "private_key",
        "privateKey",
        "session_id",
        "key",
        "KEY",
        # 全形字元先經 NFKC 正規化。
        FULLWIDTH_PASSWORD,
        "auth",
        "X-Auth",
        "pass",
        "jwt",
        "bearer",
        "access_key",
        "accessKey",
        "connection_string",
        "signature",
        "dsn",
    ],
)
def test_sensitive_key_names(key: str) -> None:
    assert is_sensitive_key(key)


@pytest.mark.parametrize(
    "key",
    [
        "name",
        "role",
        "prefix",
        "expires_at",
        "keyboard",
        "monkey",
        "passenger",
        "source",
        "author",
    ],
)
def test_ordinary_key_names(key: str) -> None:
    assert not is_sensitive_key(key)


def test_sensitive_values_are_replaced_at_every_depth() -> None:
    redacted = redact_object(
        {
            "Authorization": "Bearer abc",
            "nested": {"Set-Cookie": "sid=1", "items": [{"password": "p"}, {"apiKey": 7}]},
            "private_key": {"pem": PEM_HEADER},
            "refresh_token": None,
        }
    )

    assert redacted == {
        "Authorization": REDACTED,
        "nested": {"Set-Cookie": REDACTED, "items": [{"password": REDACTED}, {"apiKey": REDACTED}]},
        "private_key": REDACTED,
        "refresh_token": REDACTED,
    }


def test_ordinary_data_is_kept_as_is() -> None:
    data: JsonObject = {
        "name": "API 教學靶場",
        "role": "viewer",
        "prefix": SAMPLE_PREFIX,
        "count": 2,
        "ratio": 0.5,
        "enabled": True,
        "missing": None,
        "fields": ["name", "role"],
    }

    assert redact_object(data) == data


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"key is {PLATFORM_KEY} ok", f"key is {REDACTED} ok"),
        ("header Bearer abc.DEF-123_~+/== end", f"header {REDACTED} end"),
        ("bearer   lower.case", REDACTED),
        ("Basic dXNlcjpwYXNz", REDACTED),
        (f"token {JWT}", f"token {REDACTED}"),
    ],
)
def test_secret_looking_text_is_masked_inside_values(text: str, expected: str) -> None:
    assert redact_json(text) == expected
    assert redact_json([text]) == [expected]


def test_secret_looking_dict_keys_are_masked() -> None:
    assert redact_object({PLATFORM_KEY: 1}) == {REDACTED: 1}


def test_masking_repeats_until_nothing_changes() -> None:
    """遮掉一段之後，前後文字才可能成為新的比對（例如 key 緊接 bearer）。

    只遮一輪時，第二次套用的結果會不同，audit 的 domain 檢查就會拒絕寫入（API 回 500）。
    """
    once = redact_json(f"{PLATFORM_KEY}bearer x")

    assert once == f"{REDACTED}{REDACTED}"
    assert redact_json(once) == once


def test_endless_masking_falls_back_to_hiding_the_whole_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """遮罩輪數有上限；到了上限結果仍在變，就把整段當成秘密（fail closed）。"""
    monkeypatch.setattr(redaction, "MAX_MASK_PASSES", 1)

    assert redact_json(f"visible {PLATFORM_KEY}bearer x") == REDACTED


def test_redaction_is_idempotent_for_random_fragment_mixes() -> None:
    """固定 seed 的隨機片段組合：遮罩一次與兩次的結果相同（audit 的 domain 檢查依賴這一點）。"""
    fragments = [
        PLATFORM_KEY,
        JWT,
        "secscan_",
        SAMPLE_PREFIX,
        "bearer",
        "Basic",
        "eyJ",
        " ",
        "\t",
        "x",
        "abc",
        ".",
        "=",
        "_",
        "-",
        "/",
        REDACTED,
        "…",
    ]
    rng = random.Random(FUZZ_SEED)  # noqa: S311 - 固定 seed 的測試資料，不是密碼學用途

    for _ in range(FUZZ_CASES):
        text = "".join(rng.choice(fragments) for _ in range(rng.randint(1, 12)))
        once = redact_object({"name": text, "items": [text]})
        assert redact_object(once) == once, text


def test_jwt_pattern_runs_in_linear_time() -> None:
    """外部輸入（例如靶機回應）可以刻意構造；遮罩不能因此卡住。"""
    started = time.perf_counter()

    redact_json(PATHOLOGICAL_JWT)

    assert time.perf_counter() - started < LINEAR_TIME_BUDGET_SECONDS


@pytest.mark.parametrize("separator", [" ", "=", ":", '"', "\n"])
def test_jwt_after_a_separator_is_masked(separator: str) -> None:
    assert redact_json(f"token{separator}{JWT}") == f"token{separator}{REDACTED}"


def test_tuples_are_masked_like_lists() -> None:
    """tuple 不是 JSON 型別，但 json.dumps 會接受；不能因此繞過遮罩。"""
    headers = ("Authorization", "Bearer abc.def", PLATFORM_KEY)

    assert redact_object({"headers": headers}) == {"headers": ["Authorization", REDACTED, REDACTED]}  # type: ignore[dict-item]


def test_long_strings_are_truncated_after_masking() -> None:
    """先遮罩再截斷：key 剛好跨過截斷位置時，也不會留下一段 key。"""
    straddling = "a" * (MAX_STRING_LENGTH - 20) + PLATFORM_KEY
    long_text = "x" * (MAX_STRING_LENGTH + 44)

    masked = redact_json(straddling)
    truncated = redact_json(long_text)

    assert masked == "a" * (MAX_STRING_LENGTH - 20) + REDACTED
    assert truncated == "x" * MAX_STRING_LENGTH + "…"
    assert isinstance(masked, str)
    assert SAMPLE_PREFIX not in masked


def test_lists_and_objects_keep_at_most_max_items() -> None:
    redacted_list = redact_json(list(range(MAX_ITEMS + 10)))
    redacted_object = redact_object({f"field{n}": n for n in range(MAX_ITEMS + 10)})

    assert redacted_list == [*range(MAX_ITEMS), TRUNCATED]
    assert len(redacted_object) == MAX_ITEMS + 1
    assert redacted_object[TRUNCATED] == TRUNCATED
    assert f"field{MAX_ITEMS}" not in redacted_object


def test_containers_deeper_than_max_depth_are_truncated() -> None:
    """最外層是第 0 層；第 MAX_DEPTH 層的容器換成 TRUNCATED，上一層的內容都保留。"""
    deep: JsonValue = {"leaf": 1}
    for level in range(MAX_DEPTH + 1):
        deep = {f"level{level}": deep}
    expected: JsonValue = TRUNCATED
    for level in range(1, MAX_DEPTH + 1):
        expected = {f"level{level}": expected}

    assert redact_json(deep) == expected


def test_scalars_inside_the_deepest_allowed_container_are_kept() -> None:
    within: JsonValue = 1
    for level in range(MAX_DEPTH):
        within = {f"level{level}": within}

    assert redact_json(within) == within


@pytest.mark.parametrize(
    "data",
    [
        {"Authorization": "Bearer abc", "name": "lab"},
        {"long": "x" * (MAX_STRING_LENGTH * 2), "items": list(range(MAX_ITEMS * 2))},
        {f"field{n}": {"cookie": n} for n in range(MAX_ITEMS + 5)},
        {"note": f"{PLATFORM_KEY} and {JWT}"},
    ],
)
def test_redaction_is_idempotent(data: JsonObject) -> None:
    once = redact_object(data)

    assert redact_object(once) == once


def test_input_is_not_modified_and_mappings_are_accepted() -> None:
    original: JsonObject = {"password": "p", "items": ["Bearer abc"]}
    frozen = MappingProxyType(original)

    redact_object(frozen)

    assert original == {"password": "p", "items": ["Bearer abc"]}
