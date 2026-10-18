"""api_keys 資料表（docs/ARCHITECTURE.md §6）。撤銷以 revoked_at 標記，不刪除資料列。"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import CheckConstraint, ForeignKey, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from secscan.api_keys.domain import (
    API_KEY_NAME_MAX_LENGTH,
    API_KEY_PREFIX_MAX_LENGTH,
    KEY_HASH_BYTES,
    Role,
)
from secscan.core.db import Base, CreatedAtMixin, UuidPrimaryKeyMixin

ROLE_MAX_LENGTH = 32
_ROLE_VALUES = ", ".join(f"'{role.value}'" for role in Role)


class ApiKeyModel(UuidPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "api_keys"
    __table_args__ = (
        CheckConstraint(f"role IN ({_ROLE_VALUES})", name="role_valid"),
        # platform_admin 是全域的（project_id 為 NULL）；operator/viewer 必須屬於一個 project。
        CheckConstraint(
            f"(role = '{Role.PLATFORM_ADMIN.value}') = (project_id IS NULL)",
            name="role_project_scope",
        ),
        CheckConstraint(f"octet_length(key_hash) = {KEY_HASH_BYTES}", name="key_hash_length"),
        CheckConstraint("char_length(btrim(name)) > 0", name="name_not_blank"),
        CheckConstraint("char_length(btrim(prefix)) > 0", name="prefix_not_blank"),
        CheckConstraint(
            "expires_at IS NULL OR expires_at > created_at", name="expires_after_created"
        ),
        CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= created_at", name="revoked_after_created"
        ),
    )

    project_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("projects.id", ondelete="RESTRICT"), index=True
    )
    role: Mapped[str] = mapped_column(String(ROLE_MAX_LENGTH))
    name: Mapped[str] = mapped_column(String(API_KEY_NAME_MAX_LENGTH))
    prefix: Mapped[str] = mapped_column(String(API_KEY_PREFIX_MAX_LENGTH), unique=True)
    key_hash: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    expires_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]
