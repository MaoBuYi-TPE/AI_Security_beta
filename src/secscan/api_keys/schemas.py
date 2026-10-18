"""api_keys 的請求與回應 schema（docs/API_CONTRACT.md §13）。回應一律不含 key_hash。"""

from datetime import datetime
from typing import Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator

from secscan.api_keys.domain import API_KEY_NAME_MAX_LENGTH, IssuedApiKey, Role
from secscan.core.text import require_text


class ApiKeyCreate(BaseModel):
    """建立 project 範圍的 key。platform_admin key 只能由本機 CLI 建立（DECISIONS.md §9.1）。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=API_KEY_NAME_MAX_LENGTH)
    role: Literal[Role.OPERATOR, Role.VIEWER]
    expires_at: AwareDatetime | None = Field(
        default=None, description="必須帶時區；未指定時為 90 天後，最多 365 天後"
    )

    @field_validator("name")
    @classmethod
    def _name_is_text(cls, value: str) -> str:
        require_text(value, field="name", max_length=API_KEY_NAME_MAX_LENGTH)
        return value


class IssuedApiKeyOut(BaseModel):
    """剛建立的 key。完整的 key 只在這個回應出現一次，之後無法再取得。"""

    model_config = ConfigDict(frozen=True)

    id: UUID
    project_id: UUID | None
    role: Role
    name: str
    prefix: str
    created_at: datetime
    expires_at: datetime | None
    key: str = Field(repr=False, description="完整的 API key，只顯示這一次")

    @classmethod
    def of(cls, issued: IssuedApiKey) -> Self:
        key = issued.key
        return cls(
            id=key.id,
            project_id=key.project_id,
            role=key.role,
            name=key.name,
            prefix=key.prefix,
            created_at=key.created_at,
            expires_at=key.expires_at,
            key=issued.value,
        )
