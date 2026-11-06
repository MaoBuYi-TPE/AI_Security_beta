"""複掃結果是同一交易封存、之後不可改寫的快照。"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    ForeignKeyConstraint,
    PrimaryKeyConstraint,
    String,
    UniqueConstraint,
    false,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from secscan.core.db import Base, CreatedAtMixin, UuidPrimaryKeyMixin
from secscan.core.json_types import JsonObject


class ScanComparisonModel(UuidPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "scan_comparisons"
    __table_args__ = (
        UniqueConstraint("baseline_scan_id", "current_scan_id", "algorithm_version"),
        UniqueConstraint("id", "target_id"),
        ForeignKeyConstraint(
            ["baseline_scan_id", "target_id", "project_id"],
            ["scans.id", "scans.target_id", "scans.project_id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["current_scan_id", "target_id", "project_id"],
            ["scans.id", "scans.target_id", "scans.project_id"],
            ondelete="RESTRICT",
        ),
        CheckConstraint("baseline_scan_id <> current_scan_id", name="different_scans"),
        CheckConstraint("algorithm_version > 0", name="algorithm_version_positive"),
        CheckConstraint(
            "comparability IN ('comparable', 'different', 'not_comparable')",
            name="comparability_valid",
        ),
        CheckConstraint(
            "jsonb_typeof(reasons) = 'array' AND octet_length(reasons::text) <= 16384",
            name="reasons_valid",
        ),
    )

    project_id: Mapped[UUID]
    target_id: Mapped[UUID]
    baseline_scan_id: Mapped[UUID]
    current_scan_id: Mapped[UUID]
    algorithm_version: Mapped[int]
    comparability: Mapped[str] = mapped_column(String(32))
    reasons: Mapped[list[str]] = mapped_column(JSONB)
    manual_review_required: Mapped[bool]
    sealed: Mapped[bool] = mapped_column(server_default=false())


class ScanComparisonFindingModel(Base):
    __tablename__ = "scan_comparison_findings"
    __table_args__ = (
        PrimaryKeyConstraint("comparison_id", "finding_id"),
        ForeignKeyConstraint(
            ["comparison_id", "target_id"],
            ["scan_comparisons.id", "scan_comparisons.target_id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["finding_id", "target_id"], ["findings.id", "findings.target_id"], ondelete="RESTRICT"
        ),
        CheckConstraint(
            "classification IN ('persistent', 'new', 'not_observed', "
            "'inconclusive', 'not_comparable')",
            name="classification_valid",
        ),
        CheckConstraint(
            "jsonb_typeof(reasons) = 'array' AND octet_length(reasons::text) <= 16384",
            name="reasons_valid",
        ),
        CheckConstraint(
            "jsonb_typeof(evidence) = 'object' AND octet_length(evidence::text) <= 16384",
            name="evidence_valid",
        ),
    )

    comparison_id: Mapped[UUID]
    finding_id: Mapped[UUID]
    target_id: Mapped[UUID]
    classification: Mapped[str] = mapped_column(String(32))
    reasons: Mapped[list[str]] = mapped_column(JSONB)
    evidence: Mapped[JsonObject] = mapped_column(JSONB)
    manual_review_required: Mapped[bool]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
