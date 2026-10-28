"""每個 run 的 proxy 帳密（docs/DECISIONS.md §15.4）：Basic 的嚴格解析與 hash 比對。"""

import base64
from ipaddress import IPv4Address
from uuid import UUID

import pytest

from secscan.guard.domain.credentials import (
    ProxyCredentials,
    new_token,
    parse_proxy_authorization,
    proxy_url,
    token_digest,
    token_matches,
)

RUN_ID = UUID("6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b")
TOKEN = "A" * 20 + "b-_" + "9" * 20


def _basic(user: str, password: str, *, scheme: str = "Basic") -> str:
    encoded = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"{scheme} {encoded}"


def test_new_tokens_are_random_and_well_formed() -> None:
    tokens = {new_token() for _ in range(50)}

    assert len(tokens) == 50
    for token in tokens:
        credentials = parse_proxy_authorization([_basic(str(RUN_ID), token)])
        assert credentials == ProxyCredentials(run_id=RUN_ID, token=token)


def test_parses_the_header_the_runner_hands_out() -> None:
    assert parse_proxy_authorization([_basic(str(RUN_ID), TOKEN)]) == ProxyCredentials(
        RUN_ID, TOKEN
    )


def test_scheme_is_case_insensitive() -> None:
    """RFC 9110 §11.1：auth-scheme 不分大小寫。"""
    assert parse_proxy_authorization([_basic(str(RUN_ID), TOKEN, scheme="basic")]) is not None


@pytest.mark.parametrize(
    "values",
    [
        [],
        [_basic(str(RUN_ID), TOKEN), _basic(str(RUN_ID), TOKEN)],
        [_basic(str(RUN_ID), TOKEN, scheme="Bearer")],
        [_basic(str(RUN_ID), TOKEN).replace(" ", "  ")],
        ["Basic"],
        ["Basic !!!!"],
        [_basic(str(RUN_ID), TOKEN).rstrip("=") + "=="],
        [_basic(str(RUN_ID), TOKEN)[:-2]],  # 缺少 padding
        [_basic(str(RUN_ID).upper(), TOKEN)],
        [_basic(RUN_ID.hex, TOKEN)],
        [_basic(f"{{{RUN_ID}}}", TOKEN)],
        [_basic("admin", TOKEN)],
        [_basic(str(RUN_ID), TOKEN[:-1])],
        [_basic(str(RUN_ID), TOKEN + "x")],
        [_basic(str(RUN_ID), TOKEN[:-1] + "=")],
        [_basic(str(RUN_ID), TOKEN[:-1] + ":")],
        ["Basic " + base64.b64encode(b"\xff\xfe:" + TOKEN.encode()).decode()],
        ["Basic " + base64.b64encode(TOKEN.encode()).decode()],  # 沒有冒號
    ],
)
def test_rejects_anything_else(values: list[str]) -> None:
    assert parse_proxy_authorization(values) is None


def test_token_is_not_in_the_repr() -> None:
    assert TOKEN not in repr(ProxyCredentials(RUN_ID, TOKEN))


def test_digest_comparison() -> None:
    digest = token_digest(TOKEN)

    assert len(digest) == 64
    assert token_matches(TOKEN, digest)
    assert not token_matches(TOKEN[:-1] + "B", digest)
    assert not token_matches(TOKEN, digest.upper())


def test_proxy_url_carries_the_run_credentials() -> None:
    url = proxy_url(ProxyCredentials(RUN_ID, TOKEN), host=IPv4Address("10.89.8.254"), port=8080)

    assert url == f"http://{RUN_ID}:{TOKEN}@10.89.8.254:8080"
