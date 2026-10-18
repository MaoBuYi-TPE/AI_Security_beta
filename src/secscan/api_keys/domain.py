"""平台 API key 的 domain model；只用標準函式庫。

平台 key 只授權使用本平台，與被測網站的憑證是兩套東西（CLAUDE.md §9）。資料庫只存
key 的 hash（固定 32 bytes）與可公開的 prefix；產生、雜湊與驗證的規則在 T05。
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from secscan.core.text import require_text

KEY_HASH_BYTES = 32
API_KEY_NAME_MAX_LENGTH = 100
API_KEY_PREFIX_MAX_LENGTH = 32


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
    """建立 key 的輸入。key_hash 不出現在 repr。"""

    role: Role
    name: str
    prefix: str
    key_hash: bytes = field(repr=False)
    project_id: UUID | None = None
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        check_role_scope(self.role, self.project_id)
        require_text(self.name, field="name", max_length=API_KEY_NAME_MAX_LENGTH)
        require_text(self.prefix, field="prefix", max_length=API_KEY_PREFIX_MAX_LENGTH)
        if len(self.key_hash) != KEY_HASH_BYTES:
            raise ValueError(f"key_hash 必須是 {KEY_HASH_BYTES} bytes")
        if self.expires_at is not None and self.expires_at.utcoffset() is None:
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
