"""projects 的請求與回應 schema（docs/API_CONTRACT.md §13）。"""

from datetime import datetime
from typing import Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from secscan.core.text import require_text
from secscan.projects.domain import PROJECT_NAME_MAX_LENGTH, Project


class ProjectCreate(BaseModel):
    """建立專案；只接受名稱，不接受其他欄位。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=PROJECT_NAME_MAX_LENGTH)

    @field_validator("name")
    @classmethod
    def _name_is_text(cls, value: str) -> str:
        # 與 domain 相同的規則：全形空白、tab 也算空白，不可含 NUL。
        require_text(value, field="name", max_length=PROJECT_NAME_MAX_LENGTH)
        return value


class ProjectOut(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: UUID
    name: str
    created_at: datetime

    @classmethod
    def of(cls, project: Project) -> Self:
        return cls(id=project.id, name=project.name, created_at=project.created_at)
