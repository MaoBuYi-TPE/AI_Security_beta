"""runner_instances 資料表（docs/DECISIONS.md §14.7）：runner 與 worker 的心跳與能力。

每個程序一列（owner 唯一），每 5 秒更新 heartbeat_at；GET /scanners 依它判斷是否存活。
"""

from datetime import datetime

from sqlalchemy import CheckConstraint, Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from secscan.core.db import Base, CreatedAtMixin, UuidPrimaryKeyMixin
from secscan.core.json_types import JsonObject
from secscan.scanners.domain.instances import MAX_CAPABILITIES_BYTES, InstanceRole

ROLE_MAX_LENGTH = 16
OWNER_MAX_LENGTH = 128
VERSION_MAX_LENGTH = 64
_ROLES = ", ".join(f"'{role.value}'" for role in InstanceRole)


class RunnerInstanceModel(UuidPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "runner_instances"
    __table_args__ = (
        UniqueConstraint("owner"),
        Index("ix_runner_instances_role_heartbeat_at", "role", "heartbeat_at"),
        CheckConstraint(f"role IN ({_ROLES})", name="role_valid"),
        CheckConstraint("char_length(btrim(owner)) > 0", name="owner_not_blank"),
        CheckConstraint(
            "char_length(btrim(software_version)) > 0", name="software_version_not_blank"
        ),
        CheckConstraint(
            "jsonb_typeof(capabilities) = 'object' "
            f"AND octet_length(capabilities::text) <= {MAX_CAPABILITIES_BYTES}",
            name="capabilities_valid",
        ),
        CheckConstraint("heartbeat_at >= created_at", name="times"),
    )

    role: Mapped[str] = mapped_column(String(ROLE_MAX_LENGTH))
    owner: Mapped[str] = mapped_column(String(OWNER_MAX_LENGTH))
    software_version: Mapped[str] = mapped_column(String(VERSION_MAX_LENGTH))
    capabilities: Mapped[JsonObject] = mapped_column(JSONB)
    heartbeat_at: Mapped[datetime]
