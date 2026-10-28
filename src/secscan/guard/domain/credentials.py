"""每個 run 的 proxy 帳密（docs/DECISIONS.md §15.4）。

runner 為每個 run 產生一個 token，掃描容器拿到 `http://<run_id>:<token>@<guard>:8080`；policy 只存
token 的 sha256。guard 只接受一個 `Proxy-Authorization: Basic`：base64 必須是 canonical 寫法、
帳號是小寫的 UUID、token 的格式固定，以 hmac.compare_digest 比對 hash。
"""

import base64
import binascii
import hashlib
import hmac
import re
import secrets
from collections.abc import Sequence
from dataclasses import dataclass, field
from ipaddress import IPv4Address
from uuid import UUID

PROXY_REALM = "secscan-guard"
# ZAP 收到 407 時依這個 header 改用帳密重送（reactive auth）。
PROXY_AUTHENTICATE = f'Basic realm="{PROXY_REALM}"'
_TOKEN_BYTES = 32
# secrets.token_urlsafe(32)：43 個 base64url 字元、沒有 padding。
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")
_BASIC_PREFIX = "basic "


@dataclass(frozen=True, slots=True)
class ProxyCredentials:
    run_id: UUID
    token: str = field(repr=False)


def new_token() -> str:
    return secrets.token_urlsafe(_TOKEN_BYTES)


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def token_matches(token: str, digest: str) -> bool:
    return hmac.compare_digest(token_digest(token), digest)


def proxy_url(credentials: ProxyCredentials, *, host: IPv4Address, port: int) -> str:
    return f"http://{credentials.run_id}:{credentials.token}@{host}:{port}"


def parse_proxy_authorization(values: Sequence[str]) -> ProxyCredentials | None:
    """只有一個 header、格式完全正確時回傳帳密；其他情形一律 None（不說明原因）。"""
    if len(values) != 1:
        return None
    value = values[0]
    if value[: len(_BASIC_PREFIX)].lower() != _BASIC_PREFIX:
        return None
    decoded = _strict_base64(value[len(_BASIC_PREFIX) :])
    if decoded is None:
        return None
    user, separator, token = decoded.partition(":")
    run_id = _canonical_uuid(user)
    if not separator or run_id is None or _TOKEN.fullmatch(token) is None:
        return None
    return ProxyCredentials(run_id=run_id, token=token)


def _strict_base64(encoded: str) -> str | None:
    if not encoded.isascii():
        return None
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        return None
    if base64.b64encode(raw).decode("ascii") != encoded:
        return None
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        return None


def _canonical_uuid(text: str) -> UUID | None:
    try:
        parsed = UUID(text)
    except ValueError:
        return None
    return parsed if str(parsed) == text else None
