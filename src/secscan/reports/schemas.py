"""報告的請求與回應 schema（docs/API_CONTRACT.md；docs/DECISIONS.md §28.5）。

回應只有 metadata（狀態、格式、大小、sha256、截斷、錯誤碼）；內容以 /reports/{id}/download 取得。
不輸出 idempotency key、request_sha256、lease 與 key id。
"""

from datetime import datetime
from typing import Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from secscan.reports.domain.model import ReportFormat, ReportStatus
from secscan.reports.service import Report


class ReportCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    format: ReportFormat


class ReportOut(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: UUID
    scan_id: UUID
    format: ReportFormat
    schema_version: int
    status: ReportStatus
    attempts: int
    error_code: str | None
    data_as_of: datetime | None
    generated_at: datetime | None
    size_bytes: int | None
    sha256: str | None
    truncated: bool | None
    omitted_findings: int | None
    created_at: datetime
    finished_at: datetime | None
    # 保留期限（docs/DECISIONS.md §30.5）：succeeded 才有；清除之後下載回 410，
    # metadata 與 sha256 保留。
    expires_at: datetime | None
    content_purged_at: datetime | None

    @classmethod
    def of(cls, report: Report) -> Self:
        return cls(
            id=report.id,
            scan_id=report.scan_id,
            format=report.format,
            schema_version=report.schema_version,
            status=report.status,
            attempts=report.attempts,
            error_code=report.error_code,
            data_as_of=report.data_as_of,
            generated_at=report.generated_at,
            size_bytes=report.size_bytes,
            sha256=report.sha256,
            truncated=report.truncated,
            omitted_findings=report.omitted_findings,
            created_at=report.created_at,
            finished_at=report.finished_at,
            expires_at=report.expires_at,
            content_purged_at=report.content_purged_at,
        )
