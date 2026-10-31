"""runner 寫給 guard 的 policy（docs/DECISIONS.md §15.3、§21）：每個 run 一個檔案，schema 3。

guard 只依 policy 放行流量，所以格式只有一種寫法：
- encode_policy：排序的 key、沒有多餘的空白、只有 ASCII。
- decode_policy：key 完全相符、拒絕重複的 key、布林不能當整數、不接受浮點數；UUID、IP、origin
  都必須是 canonical 寫法；範圍以 Scope 重建（重跑 grant 的所有規則），比對規則和 T09 凍結
  operation 時相同（ScopeRules）。
錯誤訊息只說明欄位與原因，不含內容（token 的 hash、path 都不回顯）。
"""

import re
from dataclasses import dataclass, replace
from enum import StrEnum
from uuid import UUID

from secscan.grants.domain.matching import ScopeRules
from secscan.grants.domain.request_paths import PathEncoding
from secscan.grants.domain.scope import HttpMethod, InvalidScopeError, Scope
from secscan.guard.domain.budget import BudgetError, RunBudget
from secscan.guard.domain.strict import dump_canonical, load_object
from secscan.targets.domain import InvalidOriginError, Origin, parse_ipv4, parse_origin

# schema 3（T33）：每個 run 必須明確指定不可變的判斷政策版本。
POLICY_SCHEMA = 3
# 最大的 grant（256 個 512 字元的 path 等，§10.9）約 165 KB。
MAX_POLICY_BYTES = 512 * 1024
POLICY_SUFFIX = ".json"
# epoch 秒的範圍：0 到西元 5000 年左右，擋下明顯錯誤的值。
MAX_EPOCH_SECONDS = 10**11 - 1

_TOKEN_DIGEST = re.compile(r"[0-9a-f]{64}")
# 認證 header 的名稱（小寫的 token）：guard 只用它標示請求有沒有帶認證，不讀它的值。
# 與 auth profile 的 header 名稱相同的子集（英數字與 -），小寫：比對時 `_` 會換成 `-`。
_AUTH_HEADER = re.compile(r"(?=.{1,64}$)[a-z0-9]+(?:-[a-z0-9]+)*")
_FIELDS = frozenset(
    {
        "schema",
        "run_id",
        "scan_id",
        "state",
        "token_sha256",
        "not_after",
        "renew_until",
        "origin",
        "allowed_ips",
        "methods",
        "allow_all_paths",
        "paths",
        "excluded_paths",
        "requests_per_second",
        "burst",
        "max_requests",
        "auth_header",
        "policy_version",
    }
)
_METHODS = frozenset(method.value for method in HttpMethod)


class PolicyState(StrEnum):
    ACTIVE = "active"
    BLOCKED = "blocked"


class GuardPolicyVersion(StrEnum):
    STRICT = "strict-1"
    ENCODED_PARAMS = "encoded-params-1"

    @property
    def encoding(self) -> PathEncoding:
        if self is GuardPolicyVersion.STRICT:
            return PathEncoding.REJECT
        return PathEncoding.ROUTE_PARAMETERS


_STATES = frozenset(state.value for state in PolicyState)


class PolicyError(ValueError):
    """policy 不合格式。訊息只說明欄位與原因，不含內容。"""


@dataclass(frozen=True, slots=True)
class Policy:
    """一個 run 的出站範圍與預算。scope 只有一個 origin：scan 的 target（只放行它）。

    budget.max_requests 是這個 run 剩下的請求數（scan 的上限減去之前的 run 實際轉送的數量）；
    auth_header 是認證 header 的名稱（小寫），沒有認證時是 None。
    """

    run_id: UUID
    scan_id: UUID
    state: PolicyState
    token_sha256: str
    not_after: int
    renew_until: int
    scope: Scope
    budget: RunBudget
    auth_header: str | None
    policy_version: GuardPolicyVersion

    def __post_init__(self) -> None:
        if not isinstance(self.policy_version, GuardPolicyVersion):
            raise PolicyError("policy_version 必須是已知的 GuardPolicyVersion")
        if not isinstance(self.token_sha256, str) or not _TOKEN_DIGEST.fullmatch(self.token_sha256):
            raise PolicyError("token_sha256 必須是 64 個小寫十六進位字元")
        for field in ("not_after", "renew_until"):
            if not _is_epoch(getattr(self, field)):
                raise PolicyError(f"{field} 必須是 0 到 {MAX_EPOCH_SECONDS} 的整數（epoch 秒）")
        if len(self.scope.origins) != 1:
            raise PolicyError("policy 的範圍只能有一個 origin（scan 的 target）")
        if self.auth_header is not None and (
            not isinstance(self.auth_header, str) or not _AUTH_HEADER.fullmatch(self.auth_header)
        ):
            raise PolicyError("auth_header 必須是小寫的 header 名稱，最多 64 個字元")

    @property
    def origin(self) -> Origin:
        return self.scope.origins[0]

    def blocked(self) -> "Policy":
        return replace(self, state=PolicyState.BLOCKED)

    def renewed(self, renew_until: int) -> "Policy":
        return replace(self, renew_until=renew_until)


@dataclass(frozen=True, slots=True)
class CompiledPolicy:
    """policy 與已解析的比對規則（每個 policy 檔只解析一次）。"""

    policy: Policy
    rules: ScopeRules

    @property
    def origin(self) -> Origin:
        return self.policy.origin


def compile_policy(policy: Policy) -> CompiledPolicy:
    return CompiledPolicy(policy=policy, rules=ScopeRules.of(policy.scope))


def policy_file_name(run_id: UUID) -> str:
    return f"{run_id}{POLICY_SUFFIX}"


def encode_policy(policy: Policy) -> bytes:
    scope = policy.scope
    return dump_canonical(
        {
            "schema": POLICY_SCHEMA,
            "run_id": str(policy.run_id),
            "scan_id": str(policy.scan_id),
            "state": policy.state.value,
            "token_sha256": policy.token_sha256,
            "not_after": policy.not_after,
            "renew_until": policy.renew_until,
            "origin": str(policy.origin),
            "allowed_ips": [str(ip) for ip in scope.ips],
            "methods": [method.value for method in scope.methods],
            "allow_all_paths": scope.allow_all_paths,
            "paths": list(scope.paths),
            "excluded_paths": list(scope.excluded_paths),
            "requests_per_second": policy.budget.requests_per_second,
            "burst": policy.budget.burst,
            "max_requests": policy.budget.max_requests,
            "auth_header": policy.auth_header,
            "policy_version": policy.policy_version.value,
        }
    )


def decode_policy(raw: bytes, *, run_id: UUID) -> Policy:
    """解析 `<run_id>.json` 的內容；run_id 是檔名中的那一個，內容必須相同。"""
    document = load_object(
        raw, fields=_FIELDS, max_bytes=MAX_POLICY_BYTES, label="policy", error=PolicyError
    )
    if document.integer("schema") != POLICY_SCHEMA:
        raise PolicyError(f"schema 必須是 {POLICY_SCHEMA}")
    if document.uuid("run_id") != run_id:
        raise PolicyError("run_id 與檔名不同")
    try:
        scope = Scope(
            origins=(document.canonical(document.string("origin"), parse_origin, "origin"),),
            ips=tuple(
                document.canonical(value, parse_ipv4, "allowed_ips")
                for value in document.strings("allowed_ips")
            ),
            paths=document.strings("paths"),
            allow_all_paths=document.boolean("allow_all_paths"),
            excluded_paths=document.strings("excluded_paths"),
            methods=tuple(_method(value) for value in document.strings("methods")),
        )
        return Policy(
            run_id=run_id,
            scan_id=document.uuid("scan_id"),
            state=_state(document.string("state")),
            token_sha256=document.string("token_sha256"),
            not_after=document.integer("not_after"),
            renew_until=document.integer("renew_until"),
            scope=scope,
            budget=RunBudget(
                requests_per_second=document.integer("requests_per_second"),
                burst=document.integer("burst"),
                max_requests=document.integer("max_requests"),
            ),
            auth_header=_auth_header(document.raw("auth_header")),
            policy_version=_policy_version(document.string("policy_version")),
        )
    except (InvalidScopeError, InvalidOriginError, BudgetError) as exc:
        raise PolicyError(f"範圍或預算不合規則：{exc}") from None


def _auth_header(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise PolicyError("auth_header 必須是字串或 null")
    return value


def _policy_version(value: str) -> GuardPolicyVersion:
    try:
        return GuardPolicyVersion(value)
    except ValueError:
        raise PolicyError("policy_version 必須是已知的政策版本") from None


def _method(value: str) -> HttpMethod:
    if value not in _METHODS:
        raise PolicyError("methods 只接受大寫的 HTTP method（不含 TRACE、CONNECT）")
    return HttpMethod(value)


def _state(value: str) -> PolicyState:
    if value not in _STATES:
        raise PolicyError("state 必須是 active 或 blocked")
    return PolicyState(value)


def _is_epoch(value: object) -> bool:
    return type(value) is int and 0 <= value <= MAX_EPOCH_SECONDS
