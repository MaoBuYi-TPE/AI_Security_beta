"""projects 資料表（docs/ARCHITECTURE.md §6）。"""

from sqlalchemy import CheckConstraint, String
from sqlalchemy.orm import Mapped, mapped_column

from secscan.core.db import Base, CreatedAtMixin, UuidPrimaryKeyMixin
from secscan.projects.domain import PROJECT_NAME_MAX_LENGTH


class ProjectModel(UuidPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "projects"
    __table_args__ = (CheckConstraint("char_length(btrim(name)) > 0", name="name_not_blank"),)

    name: Mapped[str] = mapped_column(String(PROJECT_NAME_MAX_LENGTH), unique=True)
