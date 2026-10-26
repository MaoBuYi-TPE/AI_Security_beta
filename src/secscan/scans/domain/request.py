"""建立 scan 的請求：Idempotency-Key、內容的 fingerprint 與預算。

規則見 docs/DECISIONS.md §13.1、§13.2。
"""

import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from uuid import UUID

from secscan.core.json_types import JsonObject, JsonValue
from secscan.grants.domain.scope import Budget
from secscan.scans.domain.catalog import Engine, InvalidScanRequestError, ScanProfile

IDEMPOTENCY_KEY_MIN_LENGTH = 16
IDEMPOTENCY_KEY_MAX_LENGTH = 128
# 只收安全的字元（UUID 可用）：避免日誌注入與「不同寫法是否同一個 key」的歧義。
_KEY_PATTERN = re.compile(
    rf"[A-Za-z0-9_-]{{{IDEMPOTENCY_KEY_MIN_LENGTH},{IDEMPOTENCY_KEY_MAX_LENGTH}}}"
)
_QUOTE = '"'
# fingerprint 的格式版本：之後改變格式時，舊的 key 不會被誤判成相同內容。
FINGERPRINT_VERSION = 1


class InvalidIdempotencyKeyError(ValueError):
    """Idempotency-Key 缺少、重複或格式不符（400）。訊息說明規則，不含輸入。"""


def parse_idempotency_key(values: Sequence[str]) -> str:
    """header 的值（所有出現的那幾個）→ key。

    IETF 草案的值是 Structured Field 的 String，範例加上雙引號 [S79]：有引號與沒有引號的寫法
    視為同一個 key。
    """
    if not values:
        raise InvalidIdempotencyKeyError("缺少 Idempotency-Key header")
    if len(values) > 1:
        raise InvalidIdempotencyKeyError("Idempotency-Key header 只能有一個")
    value = values[0]
    if len(value) > 1 and value.startswith(_QUOTE) and value.endswith(_QUOTE):
        value = value[1:-1]
    if _KEY_PATTERN.fullmatch(value) is None:
        raise InvalidIdempotencyKeyError(
            f"Idempotency-Key 必須是 {IDEMPOTENCY_KEY_MIN_LENGTH} 到 {IDEMPOTENCY_KEY_MAX_LENGTH} "
            "個英數字、- 或 _（可以加上雙引號）"
        )
    return value


@dataclass(frozen=True, slots=True)
class BudgetRequest:
    """請求中的預算；None 代表使用 grant 的值。"""

    requests_per_second: int | None = None
    max_requests: int | None = None
    max_duration_seconds: int | None = None


@dataclass(frozen=True, slots=True)
class ScanRequest:
    """建立 scan 的請求內容（尚未檢查）。"""

    target_id: UUID
    scope_grant_id: UUID
    api_spec_id: UUID | None
    auth_profile_id: UUID | None
    profile: ScanProfile
    engines: tuple[Engine, ...]
    budget: BudgetRequest


def fingerprint(request: ScanRequest) -> bytes:
    """請求內容的 SHA-256（canonical JSON：key 排序、沒有空白）。

    比對的是請求本身，不是伺服器解析出的值（例如 profile 的最新版本）：同樣的請求重送，
    不會因為 profile 換過版本就變成 409。engines 先排序；省略 budget 等於每一項都是 null。
    """
    engines: list[JsonValue] = [*sorted(engine.value for engine in request.engines)]
    content: JsonObject = {
        "v": FINGERPRINT_VERSION,
        "target_id": str(request.target_id),
        "scope_grant_id": str(request.scope_grant_id),
        "api_spec_id": _optional_id(request.api_spec_id),
        "auth_profile_id": _optional_id(request.auth_profile_id),
        "profile": request.profile.value,
        "engines": engines,
        "budget": {
            "requests_per_second": request.budget.requests_per_second,
            "max_requests": request.budget.max_requests,
            "max_duration_seconds": request.budget.max_duration_seconds,
        },
    }
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).digest()


def resolve_budget(requested: BudgetRequest, *, grant_budget: Budget) -> Budget:
    """scan 的預算：省略的項目用 grant 的值，指定的項目必須是 1 到 grant 的值之間的整數。"""
    return Budget(
        requests_per_second=_within(
            "requests_per_second",
            requested.requests_per_second,
            grant_budget.requests_per_second,
        ),
        max_requests=_within("max_requests", requested.max_requests, grant_budget.max_requests),
        max_duration_seconds=_within(
            "max_duration_seconds",
            requested.max_duration_seconds,
            grant_budget.max_duration_seconds,
        ),
    )


def _within(field: str, value: int | None, cap: int) -> int:
    if value is None:
        return cap
    # bool 是 int 的子類別：True 不能被當成 1。
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= cap:
        raise InvalidScanRequestError(
            f"budget.{field} 必須是 1 到 {cap}（scope grant 的上限）的整數"
        )
    return value


def _optional_id(value: UUID | None) -> str | None:
    return str(value) if value is not None else None
