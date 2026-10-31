"""工具輸出的遮罩（docs/DECISIONS.md §19.5）：URL 的帳密與 query、文字中的認證值與 key=value。

結構不截斷（截斷由呼叫端在遮罩之後進行）；寧可多遮。
"""

import time

import pytest
from hypothesis import given
from hypothesis import strategies as st

from secscan.security.redaction import (
    MAX_VALUES,
    REDACTED,
    redact_text,
    redact_url,
    sensitive_query_values,
)

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJsYWIifQ.c2lnbmF0dXJl"
LINEAR_TIME_BUDGET_SECONDS = 1.0


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://lab:3000/shop?item=1", "http://lab:3000/shop?item=1"),
        ("http://lab:3000/a?token=abc&item=2", f"http://lab:3000/a?token={REDACTED}&item=2"),
        (
            "http://lab:3000/a?api_key=x&Session-Id=y",
            f"http://lab:3000/a?api_key={REDACTED}&Session-Id={REDACTED}",
        ),
        ("http://lab:3000/a?%74oken=abc", f"http://lab:3000/a?%74oken={REDACTED}"),
        ("http://user:pw@lab:3000/", f"http://{REDACTED}@lab:3000/"),
        ("http://lab:3000/a#access_token=abc", f"http://lab:3000/a#access_token={REDACTED}"),
        ("http://lab:3000/a?flag&password", "http://lab:3000/a?flag&password"),
        (f"http://lab:3000/u/{JWT}", f"http://lab:3000/u/{REDACTED}"),
        ("http://lab:3000/a?q=Bearer abc", f"http://lab:3000/a?q={REDACTED}"),
    ],
)
def test_redact_url(url: str, expected: str) -> None:
    assert redact_url(url) == expected


def test_redact_url_survives_urls_that_do_not_parse() -> None:
    """urlsplit 拒絕的輸入（不合法的 IPv6 括號）仍以文字的規則遮罩。"""
    assert redact_url("http://[::1/a?token=abc") == f"http://[::1/a?token={REDACTED}"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("nothing here", "nothing here"),
        ("Authorization: Bearer abc.def", f"Authorization: {REDACTED}"),
        ("X-Api-Key: k-123\nAccept: */*", f"X-Api-Key: {REDACTED}\nAccept: */*"),
        ("Set-Cookie: session=abc123; Path=/", f"Set-Cookie: session={REDACTED}; Path=/"),
        ('{"token": "abc", "name": "x"}', f'{{"token": "{REDACTED}", "name": "x"}}'),
        ('{"password":"p w"}', f'{{"password":"{REDACTED}"}}'),
        ("user=bob&password=hunter2", f"user=bob&password={REDACTED}"),
        (f"value {JWT} end", f"value {REDACTED} end"),
        ("keyboard=1 monkey: 2", "keyboard=1 monkey: 2"),
    ],
)
def test_redact_text(text: str, expected: str) -> None:
    assert redact_text(text) == expected


def test_redact_text_masks_the_given_values() -> None:
    """URL 中敏感參數的值也在 evidence 中遮掉（例如 10024 的 evidence 就是那個值）。"""
    assert redact_text("found s3cr3t-value twice: s3cr3t-value", values=("s3cr3t-value",)) == (
        f"found {REDACTED} twice: {REDACTED}"
    )


def test_redact_text_ignores_values_too_short_to_be_secrets() -> None:
    assert redact_text("a 1 b", values=("1", "")) == "a 1 b"


def test_too_many_values_mask_the_whole_text() -> None:
    """值來自目標控制的 URL：數量有上限，超過就整段遮掉（fail closed），不組出巨大的比對。"""
    values = tuple(f"value-{index}" for index in range(MAX_VALUES + 1))

    assert redact_text("nothing to see", values=values) == REDACTED
    assert redact_text("value-1 here", values=values[:MAX_VALUES]) == f"{REDACTED} here"


def test_many_values_stay_linear() -> None:
    values = tuple(f"value-{index}" for index in range(MAX_VALUES))
    text = "x" * 4096
    url = "http://lab/?" + "&".join(f"token=aaaa{index}" for index in range(100_000))

    started = time.perf_counter()
    for _ in range(100):
        redact_text(text, values=values)
    sensitive_query_values(url)

    assert time.perf_counter() - started < LINEAR_TIME_BUDGET_SECONDS


def test_a_value_cannot_match_inside_the_mask() -> None:
    """值是目標控制的：一次替換，遮罩字串本身不再被比對，重複套用結果不變（審查發現）。"""
    masked = redact_text("x abcd1234 y", values=("abcd1234", "REDA"))

    assert masked == f"x {REDACTED} y"
    assert redact_text(masked) == masked


def test_redaction_does_not_truncate() -> None:
    long = "x" * 10_000
    assert redact_text(long) == long
    assert redact_url(f"http://lab/{long}") == f"http://lab/{long}"


@given(st.text(max_size=300))
def test_redaction_is_idempotent(text: str) -> None:
    once = redact_text(text)
    assert redact_text(once) == once


@pytest.mark.parametrize(
    "text",
    ["a=" * 50_000, "token=" * 30_000, '"token":' * 30_000, "X-Key:" * 30_000, "=" * 100_000],
)
def test_redaction_is_linear(text: str) -> None:
    started = time.perf_counter()
    redact_text(text)
    redact_url(f"http://lab/?{text}")
    assert time.perf_counter() - started < LINEAR_TIME_BUDGET_SECONDS
