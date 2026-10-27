"""Idempotency-Key、請求內容的 fingerprint 與預算（docs/DECISIONS.md §13.1、§13.2）。"""

import dataclasses
from uuid import UUID

import pytest
from hypothesis import given
from hypothesis import strategies as st

from secscan.grants.domain.scope import Budget
from secscan.scans.domain.catalog import Engine, InvalidScanRequestError, ScanProfile
from secscan.scans.domain.request import (
    IDEMPOTENCY_KEY_MAX_LENGTH,
    IDEMPOTENCY_KEY_MIN_LENGTH,
    BudgetRequest,
    InvalidIdempotencyKeyError,
    ScanRequest,
    fingerprint,
    parse_idempotency_key,
    resolve_budget,
)

KEY = "8e03978e-40d5-43e8-bc93-6894a57f9324"
REQUEST = ScanRequest(
    target_id=UUID("11111111-1111-4111-8111-111111111111"),
    scope_grant_id=UUID("22222222-2222-4222-8222-222222222222"),
    api_spec_id=UUID("33333333-3333-4333-8333-333333333333"),
    auth_profile_id=UUID("44444444-4444-4444-8444-444444444444"),
    profile=ScanProfile.API_ACTIVE_LAB,
    engines=(Engine.FAKE,),
    budget=BudgetRequest(),
)
GRANT_BUDGET = Budget(requests_per_second=2, max_requests=5_000, max_duration_seconds=1_500)


# --- Idempotency-Key ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    [
        KEY,
        "a" * IDEMPOTENCY_KEY_MIN_LENGTH,
        "Z" * IDEMPOTENCY_KEY_MAX_LENGTH,
        "0123456789_-abcXYZ",
    ],
)
def test_accepts_keys_of_letters_digits_hyphens_and_underscores(key: str) -> None:
    assert parse_idempotency_key([key]) == key


def test_a_quoted_key_is_the_same_key() -> None:
    """IETF 草案的值是 Structured Field 的 String，範例有雙引號 [S79]。"""
    assert parse_idempotency_key([f'"{KEY}"']) == KEY


@pytest.mark.parametrize(
    "value",
    [
        "a" * (IDEMPOTENCY_KEY_MIN_LENGTH - 1),
        "a" * (IDEMPOTENCY_KEY_MAX_LENGTH + 1),
        f"{KEY} ",
        f"{KEY}\r\nX-Injected: 1",
        f"{KEY}.",
        f"{KEY}=",
        f"{KEY}/",
        f"{KEY}é",
        f"{KEY}\uff11",  # 全形的 1
        f'"{KEY}',
        f'{KEY}"',
        f'""{KEY}""',
        '""',
        "",
    ],
)
def test_rejects_keys_with_other_characters_or_lengths(value: str) -> None:
    with pytest.raises(InvalidIdempotencyKeyError) as caught:
        parse_idempotency_key([value])

    # 訊息說明規則，不回顯輸入（可能是日誌注入或其他人的資料）。
    message = str(caught.value)
    assert "16" in message
    assert "128" in message
    for fragment in (KEY, "X-Injected", "é", "\uff11"):
        assert fragment not in message


def test_a_missing_key_is_rejected() -> None:
    with pytest.raises(InvalidIdempotencyKeyError, match="缺少"):
        parse_idempotency_key([])


def test_more_than_one_key_is_rejected() -> None:
    """重複的 header 有歧義（伺服器與代理可能取不同的那一個）。"""
    with pytest.raises(InvalidIdempotencyKeyError, match="一個"):
        parse_idempotency_key([KEY, KEY])


# --- fingerprint --------------------------------------------------------------------------


def test_fingerprint_is_a_sha256_digest() -> None:
    assert len(fingerprint(REQUEST)) == 32


def test_the_same_content_has_the_same_fingerprint() -> None:
    assert fingerprint(REQUEST) == fingerprint(dataclasses.replace(REQUEST))


def test_engine_order_does_not_change_the_fingerprint() -> None:
    forward = dataclasses.replace(REQUEST, engines=(Engine.ZAP, Engine.NUCLEI))
    backward = dataclasses.replace(REQUEST, engines=(Engine.NUCLEI, Engine.ZAP))

    assert fingerprint(forward) == fingerprint(backward)


def test_an_omitted_budget_equals_an_all_null_budget() -> None:
    explicit = dataclasses.replace(
        REQUEST,
        budget=BudgetRequest(
            requests_per_second=None, max_requests=None, max_duration_seconds=None
        ),
    )

    assert fingerprint(explicit) == fingerprint(REQUEST)


OTHER_ID = UUID("99999999-9999-4999-8999-999999999999")
CHANGES: dict[str, object] = {
    "target_id": OTHER_ID,
    "scope_grant_id": OTHER_ID,
    "api_spec_id": None,
    "auth_profile_id": None,
    "profile": ScanProfile.WEB_ACTIVE_LAB,
    "engines": (Engine.ZAP,),
    "budget": BudgetRequest(requests_per_second=1),
}


@pytest.mark.parametrize("field", sorted(CHANGES))
def test_every_field_changes_the_fingerprint(field: str) -> None:
    changed = dataclasses.replace(REQUEST, **{field: CHANGES[field]})  # type: ignore[arg-type]

    assert fingerprint(changed) != fingerprint(REQUEST)


@pytest.mark.parametrize(
    "budget",
    [
        BudgetRequest(requests_per_second=1),
        BudgetRequest(max_requests=1),
        BudgetRequest(max_duration_seconds=1),
    ],
)
def test_every_budget_item_changes_the_fingerprint(budget: BudgetRequest) -> None:
    assert fingerprint(dataclasses.replace(REQUEST, budget=budget)) != fingerprint(REQUEST)


def test_ids_swapped_between_fields_change_the_fingerprint() -> None:
    """canonical JSON 以欄位名稱為 key：同樣的值放在不同欄位，不會得到相同的 fingerprint。"""
    swapped = dataclasses.replace(
        REQUEST, api_spec_id=REQUEST.auth_profile_id, auth_profile_id=REQUEST.api_spec_id
    )

    assert fingerprint(swapped) != fingerprint(REQUEST)


@given(st.permutations(list(Engine)))
def test_fingerprint_ignores_any_engine_permutation(engines: list[Engine]) -> None:
    permuted = dataclasses.replace(REQUEST, engines=tuple(engines))
    ordered = dataclasses.replace(REQUEST, engines=tuple(Engine))

    assert fingerprint(permuted) == fingerprint(ordered)


# --- 預算 ----------------------------------------------------------------------------------


def test_omitted_budget_items_take_the_grant_values() -> None:
    assert resolve_budget(BudgetRequest(), grant_budget=GRANT_BUDGET) == GRANT_BUDGET


def test_budget_items_up_to_the_grant_values_are_kept() -> None:
    requested = BudgetRequest(requests_per_second=1, max_requests=5_000, max_duration_seconds=60)

    assert resolve_budget(requested, grant_budget=GRANT_BUDGET) == Budget(
        requests_per_second=1, max_requests=5_000, max_duration_seconds=60
    )


@pytest.mark.parametrize(
    ("budget", "field"),
    [
        (BudgetRequest(requests_per_second=3), "requests_per_second"),
        (BudgetRequest(max_requests=5_001), "max_requests"),
        (BudgetRequest(max_duration_seconds=1_501), "max_duration_seconds"),
        (BudgetRequest(max_requests=0), "max_requests"),
        (BudgetRequest(max_requests=-1), "max_requests"),
    ],
)
def test_budget_items_must_be_positive_and_within_the_grant(
    budget: BudgetRequest, field: str
) -> None:
    with pytest.raises(InvalidScanRequestError, match=field):
        resolve_budget(budget, grant_budget=GRANT_BUDGET)


def test_budget_items_must_be_integers_not_booleans() -> None:
    with pytest.raises(InvalidScanRequestError, match="max_requests"):
        resolve_budget(BudgetRequest(max_requests=True), grant_budget=GRANT_BUDGET)
