"""以已知的 secret 做位元組層級的遮罩（docs/DECISIONS.md §19.5）。

工具可能以任何一種編碼寫出 secret：每種形式都要遮掉；串流處理時不論怎麼切塊，結果都相同。
"""

import json
import time
from html import escape
from urllib.parse import quote, quote_plus

import pytest
from hypothesis import given
from hypothesis import strategies as st

from secscan.security.secret_masking import (
    PROXY_TOKEN_MARK,
    TARGET_SECRET_MARK,
    SecretMasker,
    secret_variants,
)

SECRET = 'to"k/e&n+=<x> 1'
MARK = TARGET_SECRET_MARK.encode()
LINEAR_TIME_BUDGET_SECONDS = 2.0


def _masker(*values: str) -> SecretMasker:
    return SecretMasker.of({TARGET_SECRET_MARK: values})


def _whole(masker: SecretMasker, data: bytes) -> tuple[bytes, int]:
    masked, rest, count = masker.mask_chunk(data, final=True)
    assert rest == b""
    return masked, count


def _chunked(masker: SecretMasker, data: bytes, sizes: list[int]) -> tuple[bytes, int]:
    output, pending, total, offset = [], b"", 0, 0
    for size in sizes:
        masked, pending, count = masker.mask_chunk(
            pending + data[offset : offset + size], final=False
        )
        output.append(masked)
        total += count
        offset += size
    masked, rest, count = masker.mask_chunk(pending + data[offset:], final=True)
    assert rest == b""
    return b"".join([*output, masked]), total + count


@pytest.mark.parametrize(
    "form",
    [
        SECRET,
        json.dumps(SECRET)[1:-1],
        json.dumps(SECRET)[1:-1].replace("/", "\\/"),
        escape(SECRET),
        escape(SECRET, quote=False),
        quote(SECRET, safe=""),
        quote(SECRET, safe="").lower(),
        quote(SECRET, safe="/"),
        quote_plus(SECRET),
        json.dumps(escape(SECRET))[1:-1],
    ],
)
def test_every_form_of_the_secret_is_masked(form: str) -> None:
    masked, count = _whole(_masker(SECRET), f"before {form} after".encode())

    assert masked == b"before " + MARK + b" after"
    assert count == 1


def test_the_variants_include_the_value_itself() -> None:
    assert SECRET.encode() in secret_variants(SECRET)


def test_a_longer_value_wins_over_its_prefix() -> None:
    """secret 與它加上前綴的 header 值同時列出：不留下片段。"""
    masked, count = _whole(_masker("abcdef", "abcdefgh"), b"x abcdefgh y abcdef z")

    assert masked == b"x " + MARK + b" y " + MARK + b" z"
    assert count == 2


def test_each_kind_of_value_has_its_own_mark() -> None:
    masker = SecretMasker.of(
        {TARGET_SECRET_MARK: ("target-value",), PROXY_TOKEN_MARK: ("proxy-value",)}
    )

    masked, count = _whole(masker, b"target-value proxy-value")

    assert masked == f"{TARGET_SECRET_MARK} {PROXY_TOKEN_MARK}".encode()
    assert count == 2


def test_the_marks_cannot_break_a_json_string() -> None:
    for mark in (TARGET_SECRET_MARK, PROXY_TOKEN_MARK):
        assert json.loads(json.dumps({"k": mark}, ensure_ascii=True)) == {"k": mark}
        assert '"' not in mark
        assert "\\" not in mark


def test_a_masker_needs_at_least_one_value() -> None:
    """沒有值可以遮罩是呼叫端的錯誤（zap 一定有 proxy token）：不靜默略過。"""
    with pytest.raises(ValueError, match="遮罩"):
        SecretMasker.of({TARGET_SECRET_MARK: ()})
    with pytest.raises(ValueError, match="遮罩"):
        SecretMasker.of({TARGET_SECRET_MARK: ("",)})


def test_the_masker_never_shows_the_values() -> None:
    masker = _masker("canary-value")

    assert "canary-value" not in repr(masker)
    assert "canary-value" not in str(masker)


def test_nothing_is_written_while_a_match_could_still_be_incomplete() -> None:
    masker = _masker("abcdef")

    masked, rest, count = masker.mask_chunk(b"abc", final=False)

    assert (masked, rest, count) == (b"", b"abc", 0)


def test_an_empty_final_chunk_is_fine() -> None:
    assert _masker("abcdef").mask_chunk(b"", final=True) == (b"", b"", 0)


@given(
    st.lists(st.sampled_from([b"zz", b"abc", b"abcdef", b"to%22k", b"\n", b"\xff"]), max_size=30),
    st.lists(st.integers(1, 40), max_size=20),
)
def test_chunking_never_changes_the_result(pieces: list[bytes], sizes: list[int]) -> None:
    masker = _masker("abcdef", 'to"k')
    data = b"".join(pieces)

    assert _chunked(masker, data, sizes) == _whole(masker, data)


@given(st.text(alphabet="abcXYZ012-._~+/=", min_size=1, max_size=32), st.binary(max_size=64))
def test_no_form_survives_with_arbitrary_surroundings(value: str, around: bytes) -> None:
    masker = _masker(value)
    data = around + b"".join(sorted(secret_variants(value))) + around

    masked, _ = _whole(masker, data)

    assert all(value.encode() not in piece for piece in masked.split(MARK))


def test_masking_is_linear_on_near_matches() -> None:
    masker = _masker("a" * 4096, *(f"value-{index}-{'x' * 64}" for index in range(64)))
    data = (b"a" * 4095 + b"b") * 1024  # 4 MiB，幾乎每個位置都差一點就比對到

    started = time.perf_counter()
    masked, count = _whole(masker, data)

    assert count == 0
    assert masked == data
    assert time.perf_counter() - started < LINEAR_TIME_BUDGET_SECONDS
