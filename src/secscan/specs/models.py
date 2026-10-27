"""api_specs 與 api_spec_operations 資料表（docs/ARCHITECTURE.md §6、docs/DECISIONS.md §11.5）。

規格與 inventory 建立後不可變。migration 另建 trigger：兩張表的 UPDATE、DELETE、TRUNCATE
一律拒絕。正規化文件存在 DB（bytea），DB 以 CHECK 確認 sha256 相符。
"""

from uuid import UUID

from sqlalchemy import CheckConstraint, ForeignKey, LargeBinary, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from secscan.core.db import Base, CreatedAtMixin, UuidPrimaryKeyMixin
from secscan.grants.domain.scope import PATH_MAX_LENGTH
from secscan.specs.domain.documents import MAX_SPEC_BYTES, SpecFormat
from secscan.specs.domain.model import SHA256_BYTES
from secscan.specs.domain.openapi import (
    MAX_DOCUMENT_BYTES,
    MAX_OPERATIONS,
    OPERATION_ID_MAX_LENGTH,
    OPERATION_METHODS,
)

FORMAT_MAX_LENGTH = 8
VERSION_TEXT_MAX_LENGTH = 16
METHOD_MAX_LENGTH = 7
_FORMAT_VALUES = ", ".join(f"'{spec_format.value}'" for spec_format in SpecFormat)
_METHOD_VALUES = ", ".join(f"'{method.upper()}'" for method in OPERATION_METHODS)


class ApiSpecModel(UuidPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "api_specs"
    __table_args__ = (
        # version 是每個 target 各自的流水號；這個唯一索引也用來依 target 查詢。
        UniqueConstraint("target_id", "version"),
        # scan 以 (api_spec_id, target_id) 引用規格：規格一定屬於 scan 的 target。
        UniqueConstraint("id", "target_id"),
        CheckConstraint("version > 0", name="version_positive"),
        CheckConstraint(f"source_format IN ({_FORMAT_VALUES})", name="format_valid"),
        CheckConstraint(
            f"source_size_bytes BETWEEN 1 AND {MAX_SPEC_BYTES}", name="source_size_valid"
        ),
        CheckConstraint(
            f"octet_length(source_sha256) = {SHA256_BYTES}", name="source_sha256_length"
        ),
        CheckConstraint(
            f"octet_length(document) BETWEEN 1 AND {MAX_DOCUMENT_BYTES}",
            name="document_size_valid",
        ),
        # 文件與 hash 由 DB 再核對一次：之後交給工具的內容就是 hash 所指的內容。
        CheckConstraint("document_sha256 = sha256(document)", name="document_sha256_matches"),
        CheckConstraint(
            r"openapi_version ~ '^3\.0\.(0|[1-9][0-9]*)$'", name="openapi_version_valid"
        ),
        CheckConstraint(
            "base_path = '' OR (left(base_path, 1) = '/' AND right(base_path, 1) <> '/')",
            name="base_path_valid",
        ),
        CheckConstraint(
            f"operation_count BETWEEN 0 AND {MAX_OPERATIONS}", name="operation_count_valid"
        ),
    )

    target_id: Mapped[UUID] = mapped_column(ForeignKey("targets.id", ondelete="RESTRICT"))
    version: Mapped[int]
    source_format: Mapped[str] = mapped_column(String(FORMAT_MAX_LENGTH))
    source_size_bytes: Mapped[int]
    source_sha256: Mapped[bytes] = mapped_column(LargeBinary)
    # 最大 2 MiB：一般查詢只讀 metadata，不把文件一起讀出來。
    document: Mapped[bytes] = mapped_column(LargeBinary, deferred=True)
    document_sha256: Mapped[bytes] = mapped_column(LargeBinary)
    openapi_version: Mapped[str] = mapped_column(String(VERSION_TEXT_MAX_LENGTH))
    base_path: Mapped[str] = mapped_column(String(PATH_MAX_LENGTH))
    operation_count: Mapped[int]
    uploaded_by_key_id: Mapped[UUID] = mapped_column(ForeignKey("api_keys.id", ondelete="RESTRICT"))


class ApiSpecOperationModel(Base):
    __tablename__ = "api_spec_operations"
    __table_args__ = (
        UniqueConstraint("spec_id", "method", "path"),
        # NULL 彼此不相等：沒有 operationId 的 operation 可以有很多個。
        UniqueConstraint("spec_id", "operation_id"),
        CheckConstraint(f"method IN ({_METHOD_VALUES})", name="method_valid"),
        CheckConstraint("left(path, 1) = '/'", name="path_valid"),
        CheckConstraint(
            "operation_id IS NULL OR char_length(btrim(operation_id)) > 0",
            name="operation_id_not_blank",
        ),
        CheckConstraint(f"ordinal >= 0 AND ordinal < {MAX_OPERATIONS}", name="ordinal_valid"),
    )

    spec_id: Mapped[UUID] = mapped_column(
        ForeignKey("api_specs.id", ondelete="RESTRICT"), primary_key=True
    )
    # inventory 的順序（依 path、method 排序後的位置）。
    ordinal: Mapped[int] = mapped_column(primary_key=True, autoincrement=False)
    method: Mapped[str] = mapped_column(String(METHOD_MAX_LENGTH))
    path: Mapped[str] = mapped_column(String(PATH_MAX_LENGTH))
    operation_id: Mapped[str | None] = mapped_column(String(OPERATION_ID_MAX_LENGTH))
