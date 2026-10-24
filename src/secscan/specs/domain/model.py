"""規格的 domain model（docs/DECISIONS.md §11.5、§11.6）。"""

from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

from secscan.grants.domain.matching import IneligibleReason
from secscan.specs.domain.documents import SpecFormat
from secscan.targets.domain import Origin

SHA256_BYTES = 32


@dataclass(frozen=True, slots=True)
class SpecOperation:
    """inventory 的一列：method 大寫（含 TRACE），path 是 base path 加上規格中的 path。"""

    method: str
    path: str
    operation_id: str | None = None


@dataclass(frozen=True, slots=True)
class SpecUpload:
    """上傳的內容（尚未檢查）；格式由 Content-Type 決定，不從內容猜測。"""

    spec_format: SpecFormat
    content: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class InventoryEntry:
    """inventory 的一列與它在某個 grant 下的判斷。

    沒有指定 grant 時 eligible 與 reason 都是 None。
    """

    operation: SpecOperation
    eligible: bool | None = None
    reason: IneligibleReason | None = None


@dataclass(frozen=True, slots=True)
class NormalizedSpec:
    """已檢查、servers 已改綁的規格。document 是 canonical JSON（key 排序、沒有空白）。"""

    source_format: SpecFormat
    source_size: int
    source_sha256: bytes
    document: bytes = field(repr=False)
    document_sha256: bytes
    openapi_version: str
    base_path: str
    operations: tuple[SpecOperation, ...]


@dataclass(frozen=True, slots=True)
class NewApiSpec:
    """上傳的內容；version 由 repository 在鎖住 target 之後決定。"""

    target_id: UUID
    spec: NormalizedSpec
    uploaded_by_key_id: UUID


@dataclass(frozen=True, slots=True)
class ApiSpec:
    """已保存的規格（不含文件內容）。origin 是 target 的 origin，用來組出改綁後的 server URL。"""

    id: UUID
    target_id: UUID
    project_id: UUID
    origin: Origin
    version: int
    source_format: SpecFormat
    source_size: int
    source_sha256: bytes
    document_sha256: bytes
    openapi_version: str
    base_path: str
    operation_count: int
    uploaded_by_key_id: UUID
    created_at: datetime

    def __post_init__(self) -> None:
        # 從 DB 讀回的資料也經過這裡：不合規則就讀取失敗（fail closed）。
        if self.version < 1 or self.operation_count < 0 or self.source_size < 1:
            raise ValueError("api spec 的 version、大小或 operation 數量不正確")
        if len(self.source_sha256) != SHA256_BYTES or len(self.document_sha256) != SHA256_BYTES:
            raise ValueError("api spec 的 sha256 必須是 32 bytes")

    @property
    def server_url(self) -> str:
        """改綁後的 server：target 的 origin 加上 base path。"""
        return f"{self.origin}{self.base_path}"
