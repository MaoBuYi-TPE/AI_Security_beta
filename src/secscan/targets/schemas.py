"""targets 的請求與回應 schema（docs/API_CONTRACT.md §3、§14）。

base_url 的格式由 domain 嚴格檢查（錯誤訊息說明原因）；這裡只限制型別與長度。
"""

from datetime import datetime
from typing import Self
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictStr,
    field_validator,
    model_validator,
)

from secscan.core.text import require_text
from secscan.targets.domain import (
    ORIGIN_MAX_LENGTH,
    TARGET_NAME_MAX_LENGTH,
    Target,
    TargetEnvironment,
    TargetKind,
    TargetUpdate,
)


class TargetCreate(BaseModel):
    """建立 target。base_url 只能是 origin（docs/DECISIONS.md §10.2）；P0 只有 lab 環境。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: StrictStr = Field(min_length=1, max_length=TARGET_NAME_MAX_LENGTH)
    kind: TargetKind
    base_url: StrictStr = Field(min_length=1, max_length=ORIGIN_MAX_LENGTH)
    environment: TargetEnvironment = TargetEnvironment.LAB

    @field_validator("name")
    @classmethod
    def _name_is_text(cls, value: str) -> str:
        require_text(value, field="name", max_length=TARGET_NAME_MAX_LENGTH)
        return value


class TargetPatch(BaseModel):
    """只能改名稱與啟用狀態（origin 要改就建立新的 target）。省略的欄位不修改，不接受 null。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: StrictStr | None = Field(default=None, min_length=1, max_length=TARGET_NAME_MAX_LENGTH)
    enabled: StrictBool | None = None

    @field_validator("name")
    @classmethod
    def _name_is_text(cls, value: str | None) -> str | None:
        if value is not None:
            require_text(value, field="name", max_length=TARGET_NAME_MAX_LENGTH)
        return value

    @model_validator(mode="after")
    def _changes_something(self) -> Self:
        if not self.model_fields_set:
            raise ValueError("至少要修改一個欄位（name 或 enabled）")
        if any(getattr(self, field) is None for field in self.model_fields_set):
            raise ValueError("欄位不可為 null；不修改的欄位請省略")
        return self

    def to_update(self) -> TargetUpdate:
        return TargetUpdate(name=self.name, enabled=self.enabled)


class TargetOut(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: UUID
    project_id: UUID
    name: str
    kind: TargetKind
    canonical_origin: str
    environment: TargetEnvironment
    enabled: bool
    created_at: datetime

    @classmethod
    def of(cls, target: Target) -> Self:
        return cls(
            id=target.id,
            project_id=target.project_id,
            name=target.name,
            kind=target.kind,
            canonical_origin=str(target.origin),
            environment=target.environment,
            enabled=target.enabled,
            created_at=target.created_at,
        )
