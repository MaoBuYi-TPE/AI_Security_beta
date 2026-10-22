"""targets 資料表（docs/ARCHITECTURE.md §6、docs/DECISIONS.md §10.2）。"""

from uuid import UUID

from sqlalchemy import CheckConstraint, ForeignKey, String, UniqueConstraint, true
from sqlalchemy.orm import Mapped, mapped_column

from secscan.core.db import Base, CreatedAtMixin, UuidPrimaryKeyMixin
from secscan.targets.domain import (
    ORIGIN_MAX_LENGTH,
    TARGET_NAME_MAX_LENGTH,
    TargetEnvironment,
    TargetKind,
)

LABEL_MAX_LENGTH = 16
_KIND_VALUES = ", ".join(f"'{kind.value}'" for kind in TargetKind)
_ENVIRONMENT_VALUES = ", ".join(f"'{environment.value}'" for environment in TargetEnvironment)
# canonical origin 的形式：domain 已經檢查過，DB 再擋一次（最後一道防線）。
CANONICAL_ORIGIN_PATTERN = "^http://[a-z0-9.-]+(:[1-9][0-9]{0,4})?$"


class TargetModel(UuidPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "targets"
    __table_args__ = (
        # 同一個 project 內 origin 不重複；這個唯一索引也用來依 project 查詢。
        UniqueConstraint("project_id", "canonical_origin"),
        CheckConstraint("char_length(btrim(name)) > 0", name="name_not_blank"),
        CheckConstraint(f"kind IN ({_KIND_VALUES})", name="kind_valid"),
        CheckConstraint(f"environment IN ({_ENVIRONMENT_VALUES})", name="environment_valid"),
        CheckConstraint(
            f"canonical_origin ~ '{CANONICAL_ORIGIN_PATTERN}'", name="origin_canonical"
        ),
    )

    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"))
    name: Mapped[str] = mapped_column(String(TARGET_NAME_MAX_LENGTH))
    kind: Mapped[str] = mapped_column(String(LABEL_MAX_LENGTH))
    canonical_origin: Mapped[str] = mapped_column(String(ORIGIN_MAX_LENGTH))
    environment: Mapped[str] = mapped_column(String(LABEL_MAX_LENGTH))
    enabled: Mapped[bool] = mapped_column(default=True, server_default=true())
