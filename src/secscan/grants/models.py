"""scope_grants 資料表（docs/ARCHITECTURE.md §6、docs/DECISIONS.md §10.3、§10.4）。

範圍、預算與期限建立後不可變。migration 另建 trigger：UPDATE 只允許 pending→approved、
pending→revoked、approved→revoked，DELETE 與 TRUNCATE 一律拒絕。
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import CheckConstraint, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY, INET
from sqlalchemy.orm import Mapped, mapped_column

from secscan.core.db import Base, CreatedAtMixin, UuidPrimaryKeyMixin
from secscan.grants.domain.lifecycle import DECISION_NOTE_MAX_LENGTH, GrantStatus
from secscan.grants.domain.scope import (
    AUTHORIZATION_REFERENCE_MAX_LENGTH,
    MAX_ALLOWED_IPS,
    MAX_ALLOWED_ORIGINS,
    MAX_ALLOWED_PATHS,
    MAX_EXCLUDED_PATHS,
    PATH_MAX_LENGTH,
    HttpMethod,
)
from secscan.targets.domain import ORIGIN_MAX_LENGTH

STATUS_MAX_LENGTH = 16
METHOD_MAX_LENGTH = 7
_STATUS_VALUES = ", ".join(f"'{status.value}'" for status in GrantStatus)
_METHODS = "ARRAY[" + ", ".join(f"'{method.value}'" for method in HttpMethod) + "]::varchar[]"


class ScopeGrantModel(UuidPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "scope_grants"
    __table_args__ = (
        # version 是每個 target 各自的流水號；這個唯一索引也用來依 target 查詢。
        UniqueConstraint("target_id", "version"),
        # scan 以 (scope_grant_id, target_id) 引用 grant：grant 一定屬於 scan 的 target。
        UniqueConstraint("id", "target_id"),
        CheckConstraint("version > 0", name="version_positive"),
        CheckConstraint(f"status IN ({_STATUS_VALUES})", name="status_valid"),
        CheckConstraint(
            f"cardinality(allowed_origins) BETWEEN 1 AND {MAX_ALLOWED_ORIGINS}",
            name="origins_count",
        ),
        CheckConstraint(
            f"cardinality(allowed_ips) BETWEEN 1 AND {MAX_ALLOWED_IPS}", name="ips_count"
        ),
        CheckConstraint(
            f"cardinality(allowed_methods) >= 1 AND allowed_methods <@ {_METHODS}",
            name="methods_valid",
        ),
        # 不用「空清單代表全部」：要全部 path 必須明確設定 allow_all_paths。
        CheckConstraint(
            f"cardinality(excluded_paths) <= {MAX_EXCLUDED_PATHS} AND CASE WHEN allow_all_paths "
            "THEN cardinality(allowed_paths) = 0 "
            f"ELSE cardinality(allowed_paths) BETWEEN 1 AND {MAX_ALLOWED_PATHS} END",
            name="paths_valid",
        ),
        # 上限是申請當時的政策，放在 domain；DB 只要求正數（docs/DECISIONS.md §10.3）。
        CheckConstraint(
            "requests_per_second > 0 AND max_requests > 0 AND max_duration_seconds > 0",
            name="budget_positive",
        ),
        CheckConstraint("valid_from < valid_until", name="window_order"),
        CheckConstraint(
            "char_length(btrim(authorization_reference)) > 0", name="reference_not_blank"
        ),
        # 核准、撤銷的 key、時間與說明必須成對，說明不可空白。
        CheckConstraint(
            "(approved_at IS NULL) = (approved_by_key_id IS NULL) "
            "AND (approved_at IS NULL) = (approval_note IS NULL) "
            "AND (revoked_at IS NULL) = (revoked_by_key_id IS NULL) "
            "AND (revoked_at IS NULL) = (revocation_reason IS NULL) "
            "AND (approval_note IS NULL OR char_length(btrim(approval_note)) > 0) "
            "AND (revocation_reason IS NULL OR char_length(btrim(revocation_reason)) > 0)",
            name="decisions_complete",
        ),
        CheckConstraint(
            "CASE status "
            "WHEN 'pending' THEN approved_at IS NULL AND revoked_at IS NULL "
            "WHEN 'approved' THEN approved_at IS NOT NULL AND revoked_at IS NULL "
            "ELSE revoked_at IS NOT NULL END",
            name="status_matches_decisions",
        ),
        # 核准必須在到期之前；核准與撤銷都不早於申請，撤銷不早於核准。
        CheckConstraint(
            "(approved_at IS NULL OR (approved_at >= created_at AND approved_at < valid_until)) "
            "AND (revoked_at IS NULL OR revoked_at >= created_at) "
            "AND (revoked_at IS NULL OR approved_at IS NULL OR revoked_at >= approved_at)",
            name="decision_times",
        ),
    )

    target_id: Mapped[UUID] = mapped_column(ForeignKey("targets.id", ondelete="RESTRICT"))
    version: Mapped[int]
    status: Mapped[str] = mapped_column(String(STATUS_MAX_LENGTH))
    allowed_origins: Mapped[list[str]] = mapped_column(ARRAY(String(ORIGIN_MAX_LENGTH)))
    allowed_ips: Mapped[list[str]] = mapped_column(ARRAY(INET))
    allowed_paths: Mapped[list[str]] = mapped_column(ARRAY(String(PATH_MAX_LENGTH)))
    allow_all_paths: Mapped[bool]
    excluded_paths: Mapped[list[str]] = mapped_column(ARRAY(String(PATH_MAX_LENGTH)))
    allowed_methods: Mapped[list[str]] = mapped_column(ARRAY(String(METHOD_MAX_LENGTH)))
    requests_per_second: Mapped[int]
    max_requests: Mapped[int]
    max_duration_seconds: Mapped[int]
    authorization_reference: Mapped[str] = mapped_column(String(AUTHORIZATION_REFERENCE_MAX_LENGTH))
    valid_from: Mapped[datetime]
    valid_until: Mapped[datetime]
    requested_by_key_id: Mapped[UUID] = mapped_column(
        ForeignKey("api_keys.id", ondelete="RESTRICT")
    )
    approved_by_key_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("api_keys.id", ondelete="RESTRICT")
    )
    approved_at: Mapped[datetime | None]
    approval_note: Mapped[str | None] = mapped_column(String(DECISION_NOTE_MAX_LENGTH))
    revoked_by_key_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("api_keys.id", ondelete="RESTRICT")
    )
    revoked_at: Mapped[datetime | None]
    revocation_reason: Mapped[str | None] = mapped_column(String(DECISION_NOTE_MAX_LENGTH))
