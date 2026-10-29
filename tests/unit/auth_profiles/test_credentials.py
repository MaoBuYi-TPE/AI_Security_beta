"""認證類型與 secret 的格式（docs/DECISIONS.md §12.4）。

只接受各工具與伺服器解讀一致的嚴格子集；字元集本身就排除 CR、LF、NUL（header injection）。
錯誤訊息只說明欄位與原因，不回顯輸入（輸入可能就是 secret）。
"""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from secscan.auth_profiles.domain.credentials import (
    HEADER_NAME_MAX_LENGTH,
    MAX_COOKIES,
    MAX_SECRET_LENGTH,
    AuthType,
    Credential,
    SecretValue,
    check_secret,
    header_line,
)
from secscan.auth_profiles.domain.errors import InvalidAuthProfileError

BEARER = Credential(AuthType.BEARER)
API_KEY = Credential(AuthType.API_KEY_HEADER, header_name="X-API-Key")
COOKIE = Credential(AuthType.COOKIE)
CANARY = "canary7f3a"
# 平台 API key 的樣式以程式組出（pre-commit 會擋下檔案中完整的 key）。
PLATFORM_KEY = "secscan_" + "0123456789abcdef" + "_" + "a" * 64
TCHAR = "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
COOKIE_OCTETS = "".join(
    chr(code)
    for code in [
        0x21,
        *range(0x23, 0x2C),
        *range(0x2D, 0x3B),
        *range(0x3C, 0x5C),
        *range(0x5D, 0x7F),
    ]
)
VISIBLE_ASCII = "".join(chr(code) for code in range(0x21, 0x7F))


def _rejected(credential: Credential, secret: str) -> str:
    with pytest.raises(InvalidAuthProfileError) as raised:
        check_secret(credential, SecretValue(secret))
    return str(raised.value)


# --- bearer ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "secret",
    [
        "a",
        "abc.def.ghi",
        "A-Z_0~9+/x",
        "abc==",
        "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiJsYWIifQ" + ".c2lnbmF0dXJl",
        "x" * MAX_SECRET_LENGTH,
    ],
)
def test_bearer_tokens_are_b64tokens(secret: str) -> None:
    check_secret(BEARER, SecretValue(secret))


@pytest.mark.parametrize(
    "secret",
    [
        "",
        f"Bearer {CANARY}",
        f"{CANARY} x",
        f"{CANARY}\tx",
        f"{CANARY}\r\nX-Injected: 1",
        f"{CANARY}\n",
        f"{CANARY}=x",
        f"{CANARY}é",
        f"{CANARY}\x00",
        f'{CANARY}"',
        f"{CANARY},x",
        f"{CANARY};x",
        "x" * (MAX_SECRET_LENGTH + 1),
    ],
)
def test_bearer_rejects_everything_else_without_echoing(secret: str) -> None:
    message = _rejected(BEARER, secret)

    assert message.startswith("secret")
    assert CANARY not in message


def test_bearer_hint_mentions_the_prefix() -> None:
    assert "Bearer" in _rejected(BEARER, f"Bearer {CANARY}")


# --- api_key_header 的值 --------------------------------------------------------------------


@pytest.mark.parametrize(
    "secret",
    ["abc", "Token abc", "a  b", VISIBLE_ASCII, "x" * MAX_SECRET_LENGTH],
)
def test_header_values_are_visible_ascii_with_inner_spaces(secret: str) -> None:
    check_secret(API_KEY, SecretValue(secret))


@pytest.mark.parametrize(
    "secret",
    [
        "",
        f" {CANARY}",
        f"{CANARY} ",
        f"{CANARY}\tx",
        f"{CANARY}\r\nX-Injected: 1",
        f"{CANARY}\nx",
        f"{CANARY}\rx",
        f"{CANARY}\x00",
        f"{CANARY}\x7f",
        f"{CANARY}\x0b",
        f"{CANARY}é",
        "x" * (MAX_SECRET_LENGTH + 1),
    ],
)
def test_header_values_reject_control_characters_and_outer_spaces(secret: str) -> None:
    message = _rejected(API_KEY, secret)

    assert message.startswith("secret")
    assert CANARY not in message


# --- cookie ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "secret",
    [
        "a=1",
        "a=",
        'a="1"',
        'a=""',
        "a=1; b=2",
        "session=abc==",
        f"{TCHAR}=1",
        f"a={COOKIE_OCTETS}",
        "; ".join(f"c{index}=v" for index in range(MAX_COOKIES)),
        "a=" + "x" * (MAX_SECRET_LENGTH - 2),
    ],
)
def test_cookies_follow_the_rfc_6265_cookie_string(secret: str) -> None:
    check_secret(COOKIE, SecretValue(secret))


@pytest.mark.parametrize(
    "secret",
    [
        "",
        CANARY,
        f"={CANARY}",
        f"a={CANARY};b=2",
        f"a={CANARY};  b=2",
        f"a={CANARY}; ",
        f" a={CANARY}",
        f"a={CANARY} ",
        f'a={CANARY}"',
        f'a="{CANARY}',
        f'a=x"{CANARY}"',
        f"a={CANARY},2",
        f"a={CANARY}\\2",
        f"a b={CANARY}",
        f"a(b)={CANARY}",
        f"a={CANARY}é",
        f"a={CANARY}\x00",
        f"a={CANARY}\r\nX-Injected: 1",
        f"a={CANARY}; a=2",
        "; ".join(f"c{index}=v" for index in range(MAX_COOKIES + 1)),
        "a=" + "x" * (MAX_SECRET_LENGTH - 1),
    ],
)
def test_cookies_reject_everything_else_without_echoing(secret: str) -> None:
    message = _rejected(COOKIE, secret)

    assert message.startswith("secret")
    assert CANARY not in message


def test_duplicate_cookie_names_are_rejected() -> None:
    """RFC 6265 §4.2.2：同名的 cookie，伺服器不應依賴它們的順序；各工具送出的結果可能不同。"""
    assert "重複" in _rejected(COOKIE, "a=1; a=2")


# --- 平台 key ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("credential", "secret"),
    [
        (BEARER, PLATFORM_KEY),
        (BEARER, f"x{PLATFORM_KEY}x"),
        (API_KEY, f"Token {PLATFORM_KEY}"),
        (COOKIE, f"session={PLATFORM_KEY}"),
    ],
)
def test_platform_keys_are_never_sent_to_targets(credential: Credential, secret: str) -> None:
    message = _rejected(credential, secret)

    assert "平台" in message
    assert PLATFORM_KEY not in message


# --- header 名稱 ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name", ["X-API-Key", "Authorization", "api-key", "X-Auth-Token", "A", "a1-b2", "x" * 64]
)
def test_header_names_are_letters_digits_and_hyphens(name: str) -> None:
    assert Credential(AuthType.API_KEY_HEADER, header_name=name).header_name == name


@pytest.mark.parametrize(
    "name",
    [
        "",
        "X_API_Key",
        "X API",
        "-x",
        "x-",
        "x--y",
        "X.Key",
        "\uff38-Key",
        "x\r\nX-Injected",
        ":authority",
        "x" * (HEADER_NAME_MAX_LENGTH + 1),
    ],
)
def test_other_header_names_are_rejected(name: str) -> None:
    with pytest.raises(InvalidAuthProfileError, match="header_name"):
        Credential(AuthType.API_KEY_HEADER, header_name=name)


DENIED_HEADERS = [
    "Host",
    "Connection",
    "Keep-Alive",
    "Proxy-Connection",
    "TE",
    "Trailer",
    "Transfer-Encoding",
    "Upgrade",
    "Expect",
    "Content-Length",
    "Content-Type",
    "Content-Encoding",
    "Proxy-Authorization",
    "Proxy-Anything",
    "Forwarded",
    "Via",
    "Max-Forwards",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Real-IP",
    # 審查後補上（httpoxy 與其他代理、來源、host 或 path 的覆寫）
    "Proxy",
    "X-Forwarded",
    "X-Client-IP",
    "True-Client-IP",
    "X-Cluster-Client-IP",
    "Client-IP",
    "CF-Connecting-IP",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-Host",
    "X-HTTP-Host-Override",
    "X-Original-URI",
    "X-Envoy-Original-Path",
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
    "X-Original-URL",
    "X-Rewrite-URL",
    "Cookie",
    "Set-Cookie",
    "X-Secscan-Run",
]


@pytest.mark.parametrize("name", DENIED_HEADERS)
def test_headers_that_change_connections_routing_or_methods_are_denied(name: str) -> None:
    for variant in (name, name.lower(), name.upper()):
        with pytest.raises(InvalidAuthProfileError, match="header_name"):
            Credential(AuthType.API_KEY_HEADER, header_name=variant)


@given(name=st.sampled_from(DENIED_HEADERS), flips=st.lists(st.booleans(), min_size=40))
def test_denied_headers_ignore_case(name: str, flips: list[bool]) -> None:
    variant = "".join(
        character.swapcase() if flip else character
        for character, flip in zip(name, flips, strict=False)
    )

    with pytest.raises(InvalidAuthProfileError):
        Credential(AuthType.API_KEY_HEADER, header_name=variant)


def test_only_api_key_header_has_a_header_name() -> None:
    with pytest.raises(InvalidAuthProfileError, match="header_name"):
        Credential(AuthType.API_KEY_HEADER)
    for kind in (AuthType.BEARER, AuthType.COOKIE):
        with pytest.raises(InvalidAuthProfileError, match="header_name"):
            Credential(kind, header_name="X-API-Key")


# --- 性質：依文法產生的一定接受，插入禁止的字元一定拒絕 ---------------------------------------


B64TOKENS = st.builds(
    lambda body, padding: body + "=" * padding,
    st.text(alphabet="ABCxyz0189-._~+/", min_size=1, max_size=40),
    st.integers(0, 2),
)
HEADER_VALUES = st.lists(
    st.text(alphabet=VISIBLE_ASCII, min_size=1, max_size=10), min_size=1, max_size=5
).map(" ".join)
COOKIE_STRINGS = st.lists(
    st.tuples(
        st.text(alphabet=TCHAR, min_size=1, max_size=8),
        st.text(alphabet=COOKIE_OCTETS, max_size=8),
    ),
    min_size=1,
    max_size=6,
    unique_by=lambda pair: pair[0],
).map(lambda pairs: "; ".join(f"{name}={value}" for name, value in pairs))
INJECTED = st.sampled_from([" ", "\t", "\r", "\n", "\x00", "\x7f", "é", '"', ",", ";", "\\"])


@given(secret=B64TOKENS)
def test_generated_b64tokens_are_accepted(secret: str) -> None:
    check_secret(BEARER, SecretValue(secret))


@given(secret=B64TOKENS, character=INJECTED, position=st.integers(min_value=0))
def test_b64tokens_with_any_other_character_are_rejected(
    secret: str, character: str, position: int
) -> None:
    index = position % (len(secret) + 1)

    with pytest.raises(InvalidAuthProfileError):
        check_secret(BEARER, SecretValue(secret[:index] + character + secret[index:]))


@given(secret=HEADER_VALUES)
def test_generated_header_values_are_accepted(secret: str) -> None:
    check_secret(API_KEY, SecretValue(secret))


@given(
    secret=HEADER_VALUES,
    character=st.sampled_from(["\t", "\r", "\n", "\x00", "\x0b", "\x7f", "é", "\u2028"]),
    position=st.integers(min_value=0),
)
def test_header_values_with_control_characters_are_rejected(
    secret: str, character: str, position: int
) -> None:
    index = position % (len(secret) + 1)

    with pytest.raises(InvalidAuthProfileError):
        check_secret(API_KEY, SecretValue(secret[:index] + character + secret[index:]))


@given(secret=COOKIE_STRINGS)
def test_generated_cookie_strings_are_accepted(secret: str) -> None:
    check_secret(COOKIE, SecretValue(secret))


@given(
    name=st.text(alphabet=TCHAR, min_size=1, max_size=8),
    value=st.text(alphabet=COOKIE_OCTETS, max_size=12),
)
def test_cookie_values_with_any_other_character_are_rejected(name: str, value: str) -> None:
    """產生的值不含雙引號，插入一個雙引號一定不成對，所以也一定拒絕。"""
    for character in [" ", "\t", "\r", "\n", "\x00", "é", '"', ",", ";", "\\"]:
        for index in range(len(value) + 1):
            secret = f"{name}={value[:index]}{character}{value[index:]}"
            with pytest.raises(InvalidAuthProfileError):
                check_secret(COOKIE, SecretValue(secret))


# --- secret 不出現在 repr ---------------------------------------------------------------------


def test_secret_values_are_hidden_from_repr_and_str() -> None:
    secret = SecretValue(CANARY)

    assert CANARY not in repr(secret)
    assert CANARY not in str(secret)
    assert secret.value == CANARY


@pytest.mark.parametrize(
    ("credential", "header"),
    [(BEARER, "Authorization"), (API_KEY, "X-API-Key"), (COOKIE, "Cookie")],
)
def test_wire_header_names_the_header_that_carries_the_secret(
    credential: Credential, header: str
) -> None:
    """guard 據此判斷請求是否帶著目標的憑證（telemetry 的 auth 欄位，docs/DECISIONS.md §16）。"""
    assert credential.wire_header == header


@pytest.mark.parametrize(
    ("credential", "secret", "line"),
    [
        (BEARER, "abc.def", "Authorization: Bearer abc.def"),
        (API_KEY, "k 1", "X-API-Key: k 1"),
        (COOKIE, "a=1; b=2", "Cookie: a=1; b=2"),
    ],
)
def test_header_line_is_the_header_preflight_sends(
    credential: Credential, secret: str, line: str
) -> None:
    value = header_line(credential, SecretValue(secret))

    assert value.value == line
    assert secret not in repr(value)
