"""認證類型與 secret 的格式（docs/DECISIONS.md §12.4）。

P0 只有三種：bearer、api_key_header、cookie。只接受各工具與伺服器解讀一致的嚴格子集：
- bearer：RFC 6750 的 b64token。
- api_key_header：ASCII 可見字元，中間可以有空白；header 名稱只用英數字與 -，並拒絕會影響連線、
  代理、路由或 method 的 header。
- cookie：RFC 6265 的 cookie-string，名稱不可重複。
字元集本身就排除 CR、LF 與 NUL（header injection）。secret 含平台 API key 的樣式也拒絕。
錯誤訊息不回顯輸入：輸入可能就是 secret。
"""

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType

from secscan.auth_profiles.domain.errors import InvalidAuthProfileError
from secscan.security.api_key_tokens import contains_platform_key

MAX_SECRET_LENGTH = 4096
HEADER_NAME_MAX_LENGTH = 64
MAX_COOKIES = 32

# RFC 6750 §2.1：b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
_B64TOKEN = re.compile(r"[A-Za-z0-9\-._~+/]+=*")
# RFC 9110 token 的子集：英數字與 -，每段以英數字開頭與結尾
# （不收 _、. 這類會被某些伺服器改寫或丟掉的字元）。
_HEADER_NAME = re.compile(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*")
# RFC 6265 §4.1.1：cookie-name 是 token（RFC 9110 的 tchar）；cookie-value 是 cookie-octet，
# 可以整個加上雙引號。
_COOKIE_NAME = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_COOKIE_OCTETS = r"[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*"
_COOKIE_VALUE = re.compile(rf'{_COOKIE_OCTETS}|"{_COOKIE_OCTETS}"')
_COOKIE_SEPARATOR = "; "

# 不分大小寫拒絕（docs/DECISIONS.md §12.4 的表）：連線與訊息框架、代理與路由、改寫 method 或 path、
# Cookie（請用 cookie 類型），以及保留給平台的 X-Secscan-*。
_DENIED_HEADERS = frozenset(
    {
        "host",
        "connection",
        "keep-alive",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "expect",
        "forwarded",
        "via",
        "max-forwards",
        "x-real-ip",
        # 代理（httpoxy：CGI 把 Proxy: 當成 HTTP_PROXY）、來源 IP、host 與 path 的覆寫（審查後補上）
        "proxy",
        "x-forwarded",
        "x-client-ip",
        "true-client-ip",
        "x-cluster-client-ip",
        "client-ip",
        "cf-connecting-ip",
        "x-originating-ip",
        "x-remote-ip",
        "x-remote-addr",
        "x-host",
        "x-http-host-override",
        "x-original-uri",
        "x-envoy-original-path",
        "x-http-method-override",
        "x-http-method",
        "x-method-override",
        "x-original-url",
        "x-rewrite-url",
        "cookie",
        "set-cookie",
    }
)
_DENIED_HEADER_PREFIXES = ("content-", "proxy-", "x-forwarded-", "x-secscan-")


class AuthType(StrEnum):
    """secret 怎麼送出：Authorization: Bearer、指定的 header，或 Cookie。"""

    BEARER = "bearer"
    API_KEY_HEADER = "api_key_header"
    COOKIE = "cookie"


@dataclass(frozen=True, slots=True)
class SecretValue:
    """目標的 secret。repr 與 str 都不顯示內容，避免意外寫進 log 或例外訊息。"""

    value: str = field(repr=False)

    def __str__(self) -> str:
        return "<secret>"


@dataclass(frozen=True, slots=True)
class Credential:
    """secret 的送出方式（不含 secret 本身）；只有 api_key_header 有 header 名稱。"""

    type: AuthType
    header_name: str | None = None

    def __post_init__(self) -> None:
        if self.type is AuthType.API_KEY_HEADER:
            if self.header_name is None:
                raise InvalidAuthProfileError("header_name 是 api_key_header 必填的欄位")
            _check_header_name(self.header_name)
        elif self.header_name is not None:
            raise InvalidAuthProfileError("header_name 只能搭配 api_key_header")

    @property
    def wire_header(self) -> str:
        """送出 secret 的 header 名稱（只有 api_key_header 有 header_name，__post_init__ 保證）。"""
        if self.header_name is not None:
            return self.header_name
        return "Cookie" if self.type is AuthType.COOKIE else "Authorization"


def header_line(credential: Credential, secret: SecretValue) -> SecretValue:
    """送出 secret 的那一行 header（不含換行），例如 `Authorization: Bearer <token>`。

    secret 已通過 check_secret：字元集排除 CR、LF 與 NUL，不會注入其他 header。
    """
    prefix = "Bearer " if credential.type is AuthType.BEARER else ""
    return SecretValue(f"{credential.wire_header}: {prefix}{secret.value}")


def check_secret(credential: Credential, secret: SecretValue) -> None:
    """secret 符合這種送出方式的格式；不符合時拋出 InvalidAuthProfileError（不含 secret）。"""
    value = secret.value
    if not value:
        raise InvalidAuthProfileError("secret 不可為空")
    if len(value) > MAX_SECRET_LENGTH:
        raise InvalidAuthProfileError(f"secret 不可超過 {MAX_SECRET_LENGTH:,} 個字元")
    if contains_platform_key(value):
        raise InvalidAuthProfileError(
            "secret 看起來含有平台的 API key：平台 key 只用來呼叫本平台，不可送往被測網站"
        )
    problem = _SECRET_PROBLEMS[credential.type](value)
    if problem is not None:
        raise InvalidAuthProfileError(f"secret：{problem}")


def _bearer_problem(value: str) -> str | None:
    if _B64TOKEN.fullmatch(value) is not None:
        return None
    return (
        "Bearer token 只能使用 RFC 6750 的 b64token 字元（英數字與 - . _ ~ + /，結尾可以有 =），"
        '不可有空白；只填 token 本身，不要加上 "Bearer "'
    )


def _header_value_problem(value: str) -> str | None:
    if all(" " <= character <= "~" for character in value) and value.strip(" ") == value:
        return None
    return (
        "header 的值只能使用 ASCII 可見字元，中間可以有空白"
        "（不可有換行、tab、其他控制字元或非 ASCII 字元，開頭與結尾不可是空白）"
    )


def _cookie_problem(value: str) -> str | None:
    pairs = value.split(_COOKIE_SEPARATOR)
    if len(pairs) > MAX_COOKIES:
        return f"Cookie 最多 {MAX_COOKIES} 個"
    names: set[str] = set()
    for position, pair in enumerate(pairs, start=1):
        name, separator, cookie_value = pair.partition("=")
        if not separator or _COOKIE_NAME.fullmatch(name) is None:
            return (
                f"第 {position} 個 cookie 不是 name=value，或名稱不是 RFC 6265 的 token"
                "（多個 cookie 以「; 」分隔：分號加一個空白）"
            )
        if _COOKIE_VALUE.fullmatch(cookie_value) is None:
            return (
                f"第 {position} 個 cookie 的值含有不允許的字元"
                "（不可有空白、控制字元、非 ASCII 字元、逗號、分號或反斜線；雙引號只能整個包住值）"
            )
        if name in names:
            return f"第 {position} 個 cookie 的名稱與前面的重複"
        names.add(name)
    return None


_SECRET_PROBLEMS: Mapping[AuthType, Callable[[str], str | None]] = MappingProxyType(
    {
        AuthType.BEARER: _bearer_problem,
        AuthType.API_KEY_HEADER: _header_value_problem,
        AuthType.COOKIE: _cookie_problem,
    }
)


def _check_header_name(name: str) -> None:
    if len(name) > HEADER_NAME_MAX_LENGTH or _HEADER_NAME.fullmatch(name) is None:
        raise InvalidAuthProfileError(
            "header_name 只能使用英文字母、數字與 -（每段以英數字開頭與結尾），"
            f"最多 {HEADER_NAME_MAX_LENGTH} 個字元"
        )
    lowered = name.lower()
    if lowered in _DENIED_HEADERS or lowered.startswith(_DENIED_HEADER_PREFIXES):
        raise InvalidAuthProfileError(
            "header_name 不可以是影響連線、代理、路由或 method 的 header"
            "（例如 Host、Connection、Content-Length、Proxy-Authorization、X-Forwarded-For、"
            "X-HTTP-Method-Override）；Cookie 請用 cookie 類型"
        )
