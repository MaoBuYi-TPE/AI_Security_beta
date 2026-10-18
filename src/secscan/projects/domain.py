"""專案的 domain model；只用標準函式庫（不 import FastAPI、SQLAlchemy）。"""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from secscan.core.text import require_text

PROJECT_NAME_MAX_LENGTH = 100


@dataclass(frozen=True, slots=True)
class NewProject:
    """建立專案的輸入；名稱不可為空白、過長或含 NUL。"""

    name: str

    def __post_init__(self) -> None:
        require_text(self.name, field="name", max_length=PROJECT_NAME_MAX_LENGTH)


@dataclass(frozen=True, slots=True)
class Project:
    id: UUID
    name: str
    created_at: datetime
