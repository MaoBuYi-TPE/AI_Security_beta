"""逐請求的判斷（docs/DECISIONS.md §15.5）；純函式，輸入是 mitmproxy 解析之後的值。

順序固定（拒絕時回報第一個不符的原因）：
1. 帳密與 policy（addon：要讀檔）→ 407。
2. run 的狀態：run_state_reason。
3. 請求的形狀 → 4. 改寫目的地的 header → 5. authority → 6. path 與 method：request_reason。
7. DNS 與 8. 綁定在 addon 與 addresses。

authority 逐字比對（parser differential，SEC-05）：mitmproxy 解出的 host、port、scheme，以及唯一的
Host header，都必須和 policy 的 canonical origin 相同；大寫、結尾的點、IP 的其他寫法都不放行。
path 不做正規化：會讓伺服器解讀成別的 path 的寫法（`%`、`;`、`//`、`.`、`..`、反斜線）一律拒絕。
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from urllib.parse import unquote_plus

from secscan.grants.domain.matching import IneligibleReason
from secscan.grants.domain.scope import InvalidScopeError, path_problem
from secscan.guard.domain.policy import CompiledPolicy, Policy, PolicyState
from secscan.targets.domain import DEFAULT_HTTP_PORT, HTTP_SCHEME, Origin


class Reason(StrEnum):
    """guard 拒絕的原因：寫在 guard 的 log 與回應的 X-Secscan-Guard header（§15.8）。"""

    PROXY_AUTH_REQUIRED = "PROXY_AUTH_REQUIRED"
    RUN_BLOCKED = "RUN_BLOCKED"
    RUN_EXPIRED = "RUN_EXPIRED"
    POLICY_STALE = "POLICY_STALE"
    CONNECT_DENIED = "CONNECT_DENIED"
    UPGRADE_DENIED = "UPGRADE_DENIED"
    SCHEME_DENIED = "SCHEME_DENIED"
    OVERRIDE_HEADER = "OVERRIDE_HEADER"
    ORIGIN_MISMATCH = "ORIGIN_MISMATCH"
    PATH_AMBIGUOUS = "PATH_AMBIGUOUS"
    PATH_EXCLUDED = "PATH_EXCLUDED"
    METHOD_NOT_AUTHORIZED = "METHOD_NOT_AUTHORIZED"
    PATH_NOT_AUTHORIZED = "PATH_NOT_AUTHORIZED"
    DNS_FAILED = "DNS_FAILED"
    ADDRESS_NOT_ALLOWED = "ADDRESS_NOT_ALLOWED"
    NOT_APPROVED = "NOT_APPROVED"
    TRAILERS_DENIED = "TRAILERS_DENIED"
    GUARD_ERROR = "GUARD_ERROR"


PROXY_AUTH_STATUS = 407
FORBIDDEN_STATUS = 403
DENY_STATUS: Mapping[Reason, int] = MappingProxyType(
    {
        reason: PROXY_AUTH_STATUS if reason is Reason.PROXY_AUTH_REQUIRED else FORBIDDEN_STATUS
        for reason in Reason
    }
)

# 會讓靶機改用別的 method、path 或 host 處理請求的 header（小寫）。
OVERRIDE_HEADERS = frozenset(
    {
        "x-http-method-override",
        "x-http-method",
        "x-method-override",
        "x-original-url",
        "x-rewrite-url",
        "x-forwarded-host",
        "x-host",
        "x-forwarded-server",
        "x-forwarded-prefix",
        "forwarded",
    }
)
_UPGRADE_HEADERS = frozenset({"upgrade", "http2-settings"})
_METHOD_OVERRIDE_KEY = "_method"
_QUERY_SEPARATORS = re.compile(r"[&;]")
# 重複解碼到不再改變為止（上限幾次）：`%255f` 這類雙重編碼也會被認出來。
_MAX_UNQUOTE_ROUNDS = 4
_SCOPE_REASONS: Mapping[IneligibleReason, Reason] = MappingProxyType(
    {
        IneligibleReason.PATH_EXCLUDED: Reason.PATH_EXCLUDED,
        IneligibleReason.METHOD_NOT_AUTHORIZED: Reason.METHOD_NOT_AUTHORIZED,
        IneligibleReason.PATH_NOT_AUTHORIZED: Reason.PATH_NOT_AUTHORIZED,
    }
)


@dataclass(frozen=True, slots=True)
class RequestView:
    """一個請求中 guard 要看的部分。method 是轉送時的原始寫法；target 是 path 加 query。"""

    method: str
    scheme: str
    host: str
    port: int
    target: str
    headers: tuple[tuple[str, str], ...]

    def values(self, name: str) -> tuple[str, ...]:
        """header 的所有值（名稱不分大小寫）。"""
        wanted = name.lower()
        return tuple(value for key, value in self.headers if key.lower() == wanted)

    def has(self, names: frozenset[str]) -> bool:
        return any(key.lower() in names for key, _ in self.headers)


def run_state_reason(policy: Policy, *, now: float) -> Reason | None:
    """已封鎖 → 已過期 → 沒有續約；時間邊界本身就算過期（>=）。"""
    if policy.state is PolicyState.BLOCKED:
        return Reason.RUN_BLOCKED
    if now >= policy.not_after:
        return Reason.RUN_EXPIRED
    if now >= policy.renew_until:
        return Reason.POLICY_STALE
    return None


def request_reason(view: RequestView, compiled: CompiledPolicy) -> Reason | None:
    """第 3 到 6 步；全部通過時回傳 None。"""
    return (
        _shape_reason(view)
        or _override_reason(view)
        or _authority_reason(view, compiled.origin)
        or _scope_reason(view, compiled)
    )


def canonical_authority(origin: Origin) -> str:
    """寫回上游請求的 Host：port 80 時省略。"""
    if origin.port == DEFAULT_HTTP_PORT:
        return origin.host
    return f"{origin.host}:{origin.port}"


def split_target(target: str) -> tuple[str, str]:
    path, _, query = target.partition("?")
    return path, query


def _shape_reason(view: RequestView) -> Reason | None:
    if view.has(_UPGRADE_HEADERS) or any(
        token.strip().lower() == "upgrade"
        for value in view.values("connection")
        for token in value.split(",")
    ):
        return Reason.UPGRADE_DENIED
    if view.scheme != HTTP_SCHEME:
        return Reason.SCHEME_DENIED
    if not (_visible_ascii(view.method) and _visible_ascii(view.target)) or "#" in view.target:
        return Reason.PATH_AMBIGUOUS
    return None


def _override_reason(view: RequestView) -> Reason | None:
    if view.has(OVERRIDE_HEADERS):
        return Reason.OVERRIDE_HEADER
    _, query = split_target(view.target)
    for piece in _QUERY_SEPARATORS.split(query):
        key = _fully_unquoted(piece.partition("=")[0])
        if key.strip().lower() == _METHOD_OVERRIDE_KEY:
            return Reason.OVERRIDE_HEADER
    return None


def _authority_reason(view: RequestView, origin: Origin) -> Reason | None:
    accepted = {canonical_authority(origin)}
    if origin.port == DEFAULT_HTTP_PORT:
        accepted.add(f"{origin.host}:{DEFAULT_HTTP_PORT}")
    host_headers = view.values("host")
    if (
        view.host != origin.host
        or view.port != origin.port
        or len(host_headers) != 1
        or host_headers[0] not in accepted
    ):
        return Reason.ORIGIN_MISMATCH
    return None


def _scope_reason(view: RequestView, compiled: CompiledPolicy) -> Reason | None:
    path, _ = split_target(view.target)
    # 字面的 {x} 會被 parse_route 當成佔位（涵蓋任何一段），所以請求中不接受大括號。
    if path_problem(path) is not None or "{" in path or "}" in path:
        return Reason.PATH_AMBIGUOUS
    try:
        ineligible = compiled.rules.classify(method=view.method, path=path)
    except InvalidScopeError:
        return Reason.PATH_AMBIGUOUS
    return None if ineligible is None else _SCOPE_REASONS[ineligible]


def _visible_ascii(text: str) -> bool:
    return bool(text) and all("!" <= character <= "~" for character in text)


def _fully_unquoted(text: str) -> str:
    for _ in range(_MAX_UNQUOTE_ROUNDS):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    return text
