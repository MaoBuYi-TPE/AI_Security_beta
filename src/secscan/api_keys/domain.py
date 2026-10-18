"""平台 API key 的 domain model、權限規則與期限規則；只用標準函式庫。

平台 key 只授權使用本平台，與被測網站的憑證是兩套東西（CLAUDE.md §9）。資料庫只存 key 的
hash（固定 32 bytes）與可公開的 prefix；key 的格式與雜湊在 secscan.security.api_key_tokens。
權限與期限規則的理由見 docs/DECISIONS.md §9。
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import cast
from uuid import UUID

from secscan.core.text import require_text

KEY_HASH_BYTES = 32
API_KEY_NAME_MAX_LENGTH = 100
API_KEY_PREFIX_MAX_LENGTH = 32
DEFAULT_KEY_LIFETIME = timedelta(days=90)
MAX_KEY_LIFETIME = timedelta(days=365)


class Role(StrEnum):
    """platform_admin 是全域管理員；operator 與 viewer 綁定一個 project（API_CONTRACT §1）。"""

    PLATFORM_ADMIN = "platform_admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


def check_role_scope(role: Role, project_id: UUID | None) -> None:
    """platform_admin 不屬於任何 project；其他角色必須屬於一個 project。"""
    if role is Role.PLATFORM_ADMIN and project_id is not None:
        raise ValueError("platform_admin 不可綁定 project")
    if role is not Role.PLATFORM_ADMIN and project_id is None:
        raise ValueError(f"{role.value} 必須綁定 project")


@dataclass(frozen=True, slots=True)
class NewApiKey:
    """建立 key 的輸入。key_hash 不出現在 repr；所有 key 都必須有到期時間（DECISIONS.md §9.1）。"""

    role: Role
    name: str
    prefix: str
    key_hash: bytes = field(repr=False)
    expires_at: datetime
    project_id: UUID | None = None

    def __post_init__(self) -> None:
        check_role_scope(self.role, self.project_id)
        require_text(self.name, field="name", max_length=API_KEY_NAME_MAX_LENGTH)
        require_text(self.prefix, field="prefix", max_length=API_KEY_PREFIX_MAX_LENGTH)
        if len(self.key_hash) != KEY_HASH_BYTES:
            raise ValueError(f"key_hash 必須是 {KEY_HASH_BYTES} bytes")
        if self.expires_at.utcoffset() is None:
            # 沒有時區會被當成 UTC 存（台北機器上的 datetime.now() 會差 8 小時）。
            raise ValueError("expires_at 必須帶時區")


@dataclass(frozen=True, slots=True)
class ApiKey:
    id: UUID
    project_id: UUID | None
    role: Role
    name: str
    prefix: str
    key_hash: bytes = field(repr=False)
    created_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None


@dataclass(frozen=True, slots=True)
class IssuedApiKey:
    """剛建立的 key：完整值只在這裡出現一次（API 回應或 CLI 輸出），不出現在 repr。"""

    key: ApiKey
    value: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class Revocation:
    """撤銷結果；newly_revoked 為 False 表示先前已撤銷（保留第一次撤銷的時間）。"""

    key: ApiKey
    newly_revoked: bool


def resolve_expiry(requested: datetime | None, *, now: datetime) -> datetime:
    """key 的到期時間（UTC）：沒指定時為 90 天後；指定時必須帶時區、晚於現在，且不超過 365 天後。"""
    if requested is None:
        return (now + DEFAULT_KEY_LIFETIME).astimezone(UTC)
    if requested.utcoffset() is None:
        raise ValueError("expires_at 必須帶時區")
    if requested <= now:
        raise ValueError("expires_at 必須晚於現在")
    if requested > now + MAX_KEY_LIFETIME:
        raise ValueError(f"expires_at 不可超過 {MAX_KEY_LIFETIME.days} 天後")
    return requested.astimezone(UTC)


# --- 權限 -----------------------------------------------------------------------------------


class Permission(StrEnum):
    """操作需要的權限。PROJECT_* 一定針對某個 project；PLATFORM_ADMIN 可以是全域的操作。"""

    PROJECT_READ = "project:read"
    PROJECT_WRITE = "project:write"
    PLATFORM_MANAGE = "platform:manage"


class AccessDecision(StrEnum):
    ALLOWED = "allowed"
    # 不是自己的 project：和不存在一樣回 404，不洩漏其他 project 是否存在。
    NOT_FOUND = "not_found"
    # 自己的 project 或全域操作，但角色不足：403。
    FORBIDDEN = "forbidden"


# platform_admin 不查這張表（一律允許）；表中沒有的權限一律拒絕。
_PROJECT_ROLE_PERMISSIONS: Mapping[Role, frozenset[Permission]] = MappingProxyType(
    {
        Role.OPERATOR: frozenset({Permission.PROJECT_READ, Permission.PROJECT_WRITE}),
        Role.VIEWER: frozenset({Permission.PROJECT_READ}),
    }
)


@dataclass(frozen=True, slots=True)
class AllProjects:
    """清單查詢不限 project（只有 platform_admin）。"""


@dataclass(frozen=True, slots=True)
class OneProject:
    """清單查詢只限一個 project（operator、viewer）。"""

    project_id: UUID

    def __post_init__(self) -> None:
        # 不用 None 代表「全部」：漏傳的 project 不能變成看得到所有 project（fail closed）。
        if not isinstance(self.project_id, UUID):
            raise TypeError("OneProject 需要 project_id（UUID）")


# 清單查詢的 project 範圍。repository 必須明確收到其中一種，沒有「未指定就全部」的預設。
type ProjectScope = AllProjects | OneProject


@dataclass(frozen=True, slots=True)
class Principal:
    """通過驗證的呼叫者：哪一把 key、什麼角色、屬於哪個 project。"""

    key_id: UUID
    role: Role
    project_id: UUID | None

    def __post_init__(self) -> None:
        check_role_scope(self.role, self.project_id)

    @classmethod
    def of(cls, key: ApiKey) -> "Principal":
        return cls(key_id=key.id, role=key.role, project_id=key.project_id)

    @property
    def is_platform_admin(self) -> bool:
        return self.role is Role.PLATFORM_ADMIN

    @property
    def project_scope(self) -> ProjectScope:
        """platform_admin 看得到全部；其他角色只有自己的 project。

        __post_init__ 已保證非 platform_admin 一定有 project_id。
        """
        if self.is_platform_admin:
            return AllProjects()
        return OneProject(cast(UUID, self.project_id))


def decide(
    principal: Principal, permission: Permission, project_id: UUID | None = None
) -> AccessDecision:
    """先判斷 project，再判斷角色（docs/DECISIONS.md §9.2）。

    project_id 為 None 代表全域操作（例如建立 project、撤銷 key），只能搭配 PLATFORM_ADMIN。
    """
    if project_id is None and permission is not Permission.PLATFORM_MANAGE:
        raise ValueError(f"{permission.value} 必須指定 project_id")
    if principal.is_platform_admin:
        return AccessDecision.ALLOWED
    if project_id is not None and project_id != principal.project_id:
        return AccessDecision.NOT_FOUND
    if permission in _PROJECT_ROLE_PERMISSIONS.get(principal.role, frozenset()):
        return AccessDecision.ALLOWED
    return AccessDecision.FORBIDDEN


# --- 驗證失敗 -------------------------------------------------------------------------------


class RejectionReason(StrEnum):
    """key 驗證失敗的原因。只寫進伺服器日誌；對外除了 EXPIRED 之外都是同一個回應。"""

    MISSING = "missing"
    MALFORMED = "malformed"
    UNKNOWN_KEY = "unknown_key"
    # prefix 存在，但完整 key 的 hash 不符（secret 錯誤）。
    HASH_MISMATCH = "hash_mismatch"
    REVOKED = "revoked"
    EXPIRED = "expired"


class ApiKeyRejectedError(Exception):
    """key 驗證失敗。不帶 key 本身，只帶原因與已辨識出的 key id（若有）。"""

    def __init__(self, reason: RejectionReason, key_id: UUID | None = None) -> None:
        super().__init__(f"API key 驗證失敗：{reason.value}")
        self.reason = reason
        self.key_id = key_id
