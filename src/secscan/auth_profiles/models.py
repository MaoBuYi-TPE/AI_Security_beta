"""auth_profiles 與 auth_profile_versions 資料表（docs/ARCHITECTURE.md §6、DECISIONS.md §12.3）。

- auth_profiles 建立後不可變。
- auth_profile_versions 只允許兩種 UPDATE：清除密文（同時記下 secret_erased_at）與重新加密；
  INSERT 必須帶密文，DELETE、TRUNCATE 一律拒絕（migration 的 trigger）。
- 部分唯一索引：每個 profile 最多一份密文（建立新版本時先清除上一版）。
密文欄位以 deferred 載入：一般的查詢不讀它。
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    LargeBinary,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from secscan.auth_profiles.domain.credentials import HEADER_NAME_MAX_LENGTH, AuthType
from secscan.auth_profiles.domain.model import (
    EXPECTED_JSON_MAX_BYTES,
    MAX_ENCRYPTED_SECRET_BYTES,
    PROFILE_NAME_MAX_LENGTH,
    RESERVED_ROLE_LABELS,
    ROLE_LABEL_MAX_LENGTH,
)
from secscan.auth_profiles.domain.preflight import (
    MAX_EXPECTED_STATUS,
    MIN_EXPECTED_STATUS,
    PREFLIGHT_METHOD,
)
from secscan.core.db import Base, CreatedAtMixin, UuidPrimaryKeyMixin
from secscan.core.json_types import JsonObject
from secscan.grants.domain.scope import PATH_MAX_LENGTH
from secscan.security.secret_cipher import TOKEN_PREFIX

TYPE_MAX_LENGTH = 16
METHOD_MAX_LENGTH = 7
_TYPE_VALUES = ", ".join(f"'{kind.value}'" for kind in AuthType)
_RESERVED_LABELS = ", ".join(f"'{label}'" for label in sorted(RESERVED_ROLE_LABELS))


class AuthProfileModel(UuidPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "auth_profiles"
    __table_args__ = (
        # role_label 是 finding fingerprint 中的 auth role：同一個 target 內不可重複。
        UniqueConstraint("target_id", "role_label"),
        CheckConstraint("char_length(btrim(name)) > 0", name="name_not_blank"),
        CheckConstraint(
            rf"role_label ~ '^[a-z][a-z0-9_]{{0,{ROLE_LABEL_MAX_LENGTH - 1}}}$' "
            f"AND role_label NOT IN ({_RESERVED_LABELS})",
            name="role_label_valid",
        ),
    )

    target_id: Mapped[UUID] = mapped_column(ForeignKey("targets.id", ondelete="RESTRICT"))
    name: Mapped[str] = mapped_column(String(PROFILE_NAME_MAX_LENGTH))
    role_label: Mapped[str] = mapped_column(String(ROLE_LABEL_MAX_LENGTH))
    created_by_key_id: Mapped[UUID] = mapped_column(ForeignKey("api_keys.id", ondelete="RESTRICT"))


class AuthProfileVersionModel(CreatedAtMixin, Base):
    __tablename__ = "auth_profile_versions"
    __table_args__ = (
        CheckConstraint("version > 0", name="version_positive"),
        CheckConstraint(f"type IN ({_TYPE_VALUES})", name="type_valid"),
        CheckConstraint(
            f"(type = '{AuthType.API_KEY_HEADER.value}') = (header_name IS NOT NULL)",
            name="header_name_matches_type",
        ),
        # 拒絕清單（Host、Proxy-*…）在 domain；DB 只確認字元的形式。
        CheckConstraint(
            "header_name IS NULL OR header_name ~ '^[A-Za-z0-9]+(-[A-Za-z0-9]+)*$'",
            name="header_name_valid",
        ),
        CheckConstraint(f"preflight_method = '{PREFLIGHT_METHOD}'", name="preflight_method_valid"),
        CheckConstraint(
            "left(preflight_path, 1) = '/' "
            "AND strpos(preflight_path, '{') = 0 AND strpos(preflight_path, '}') = 0",
            name="preflight_path_valid",
        ),
        CheckConstraint(
            f"preflight_expected_status BETWEEN {MIN_EXPECTED_STATUS} AND {MAX_EXPECTED_STATUS}",
            name="preflight_status_valid",
        ),
        CheckConstraint(
            "jsonb_typeof(preflight_expected_json) = 'object' "
            "AND preflight_expected_json <> '{}'::jsonb "
            f"AND octet_length(preflight_expected_json::text) <= {EXPECTED_JSON_MAX_BYTES}",
            name="preflight_expected_json_valid",
        ),
        CheckConstraint(
            "(encrypted_secret IS NULL) = (secret_erased_at IS NOT NULL)",
            name="secret_erasure_consistent",
        ),
        # 存進去的是 Fernet token，不是明文（版本 0x80 開頭），長度由最大的 secret 推算。
        CheckConstraint(
            "encrypted_secret IS NULL OR ("
            f"substring(encrypted_secret FROM 1 FOR {len(TOKEN_PREFIX)}) "
            f"= '{TOKEN_PREFIX.decode()}'::bytea "
            f"AND octet_length(encrypted_secret) <= {MAX_ENCRYPTED_SECRET_BYTES})",
            name="encrypted_secret_valid",
        ),
        Index(
            "uq_auth_profile_versions_live_secret",
            "profile_id",
            unique=True,
            postgresql_where=text("encrypted_secret IS NOT NULL"),
        ),
    )

    profile_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth_profiles.id", ondelete="RESTRICT"), primary_key=True
    )
    version: Mapped[int] = mapped_column(primary_key=True, autoincrement=False)
    type: Mapped[str] = mapped_column(String(TYPE_MAX_LENGTH))
    header_name: Mapped[str | None] = mapped_column(String(HEADER_NAME_MAX_LENGTH))
    preflight_method: Mapped[str] = mapped_column(String(METHOD_MAX_LENGTH))
    preflight_path: Mapped[str] = mapped_column(String(PATH_MAX_LENGTH))
    preflight_expected_status: Mapped[int]
    preflight_expected_json: Mapped[JsonObject] = mapped_column(JSONB)
    encrypted_secret: Mapped[bytes | None] = mapped_column(LargeBinary, deferred=True)
    secret_erased_at: Mapped[datetime | None]
    created_by_key_id: Mapped[UUID] = mapped_column(ForeignKey("api_keys.id", ondelete="RESTRICT"))
