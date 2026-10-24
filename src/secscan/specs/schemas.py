"""API 規格的回應 schema（docs/API_CONTRACT.md §15）。上傳是 raw body，沒有請求 schema。"""

from datetime import datetime
from typing import Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from secscan.grants.domain.matching import IneligibleReason
from secscan.specs.domain.documents import SpecFormat
from secscan.specs.domain.model import ApiSpec, InventoryEntry


class ApiSpecOut(BaseModel):
    """不含文件內容：工具在 M3 直接從 DB 取；hash 以小寫 hex 表示。"""

    model_config = ConfigDict(frozen=True)

    id: UUID
    target_id: UUID
    project_id: UUID
    version: int
    openapi_version: str
    source_format: SpecFormat
    source_size_bytes: int
    source_sha256: str
    document_sha256: str
    server_url: str
    base_path: str
    operation_count: int
    uploaded_by_key_id: UUID
    created_at: datetime

    @classmethod
    def of(cls, spec: ApiSpec) -> Self:
        return cls(
            id=spec.id,
            target_id=spec.target_id,
            project_id=spec.project_id,
            version=spec.version,
            openapi_version=spec.openapi_version,
            source_format=spec.source_format,
            source_size_bytes=spec.source_size,
            source_sha256=spec.source_sha256.hex(),
            document_sha256=spec.document_sha256.hex(),
            server_url=spec.server_url,
            base_path=spec.base_path,
            operation_count=spec.operation_count,
            uploaded_by_key_id=spec.uploaded_by_key_id,
            created_at=spec.created_at,
        )


class SpecOperationOut(BaseModel):
    """沒有指定 scope_grant_id 時，eligible 與 reason 都是 null。"""

    model_config = ConfigDict(frozen=True)

    method: str
    path: str
    operation_id: str | None
    eligible: bool | None
    reason: IneligibleReason | None

    @classmethod
    def of(cls, entry: InventoryEntry) -> Self:
        return cls(
            method=entry.operation.method,
            path=entry.operation.path,
            operation_id=entry.operation.operation_id,
            eligible=entry.eligible,
            reason=entry.reason,
        )
