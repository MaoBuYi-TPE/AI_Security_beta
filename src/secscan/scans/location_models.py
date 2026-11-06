"""複掃逐位置摘要；原始參數名稱不入庫，未知狀態保守保留。"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import CheckConstraint, ForeignKeyConstraint, PrimaryKeyConstraint, String, func
from sqlalchemy.orm import Mapped, mapped_column

from secscan.core.db import Base

_METHODS = "'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'"


class RunLocationModel(Base):
    __tablename__ = "run_locations"
    __table_args__ = (
        PrimaryKeyConstraint("scanner_run_id", "method", "path_sha256"),
        ForeignKeyConstraint(
            ["scanner_run_id", "scan_id"],
            ["scanner_runs.id", "scanner_runs.scan_id"],
            ondelete="RESTRICT",
        ),
        CheckConstraint(f"method IN ({_METHODS})", name="method_valid"),
        CheckConstraint(
            "path_sha256 ~ '^[0-9a-f]{64}$'",
            name="path_sha256_valid",
        ),
        CheckConstraint(
            "(NOT discovery_answered OR answered) AND (NOT authenticated OR answered)",
            name="answers_consistent",
        ),
    )

    scanner_run_id: Mapped[UUID]
    scan_id: Mapped[UUID]
    method: Mapped[str] = mapped_column(String(7))
    path_sha256: Mapped[str] = mapped_column(String(64))
    answered: Mapped[bool]
    discovery_answered: Mapped[bool]
    authenticated: Mapped[bool]
    unanswered: Mapped[bool]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class RunRuleLocationModel(Base):
    __tablename__ = "run_rule_locations"
    __table_args__ = (
        PrimaryKeyConstraint("scanner_run_id", "method", "path_sha256", "rule"),
        ForeignKeyConstraint(
            ["scanner_run_id", "method", "path_sha256"],
            ["run_locations.scanner_run_id", "run_locations.method", "run_locations.path_sha256"],
            ondelete="RESTRICT",
        ),
        CheckConstraint("rule ~ '^[0-9]{1,6}$'", name="rule_valid"),
        CheckConstraint("parameters_unknown", name="parameters_unknown_required"),
    )

    scanner_run_id: Mapped[UUID]
    method: Mapped[str] = mapped_column(String(7))
    path_sha256: Mapped[str] = mapped_column(String(64))
    rule: Mapped[str] = mapped_column(String(6))
    answered: Mapped[bool]
    parameters_unknown: Mapped[bool]
    parameters_truncated: Mapped[bool]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
