"""runner 寫給 guard 的 policy（docs/DECISIONS.md §15.3）：每個 run 一個檔案，schema 1。

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
from secscan.grants.domain.scope import HttpMethod, InvalidScopeError, Scope
from secscan.guard.domain.strict import dump_canonical, load_object
from secscan.targets.domain import InvalidOriginError, Origin, parse_ipv4, parse_origin

POLICY_SCHEMA = 1
# 最大的 grant（256 個 512 字元的 path 等，§10.9）約 165 KB。
MAX_POLICY_BYTES = 512 * 1024
POLICY_SUFFIX = ".json"
# epoch 秒的範圍：0 到西元 5000 年左右，擋下明顯錯誤的值。
MAX_EPOCH_SECONDS = 10**11 - 1

_TOKEN_DIGEST = re.compile(r"[0-9a-f]{64}")
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
    }
)
_METHODS = frozenset(method.value for method in HttpMethod)


class PolicyState(StrEnum):
    ACTIVE = "active"
    BLOCKED = "blocked"


_STATES = frozenset(state.value for state in PolicyState)


class PolicyError(ValueError):
    """policy 不合格式。訊息只說明欄位與原因，不含內容。"""


@dataclass(frozen=True, slots=True)
class Policy:
    """一個 run 的出站範圍。scope 只有一個 origin：scan 的 target（T11 只放行它）。"""

    run_id: UUID
    scan_id: UUID
    state: PolicyState
    token_sha256: str
    not_after: int
    renew_until: int
    scope: Scope

    def __post_init__(self) -> None:
        if not isinstance(self.token_sha256, str) or not _TOKEN_DIGEST.fullmatch(self.token_sha256):
            raise PolicyError("token_sha256 必須是 64 個小寫十六進位字元")
        for field in ("not_after", "renew_until"):
            if not _is_epoch(getattr(self, field)):
                raise PolicyError(f"{field} 必須是 0 到 {MAX_EPOCH_SECONDS} 的整數（epoch 秒）")
        if len(self.scope.origins) != 1:
            raise PolicyError("policy 的範圍只能有一個 origin（scan 的 target）")

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
        )
    except (InvalidScopeError, InvalidOriginError) as exc:
        raise PolicyError(f"範圍不合規則：{exc}") from None


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
