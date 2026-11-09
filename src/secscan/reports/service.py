"""報告的業務規則（T21；docs/DECISIONS.md §28.5）。

- 建立：先以 scan 的 project 授權（其他 project 404、角色不足 403）；Idempotency-Key 的範圍是
  project，同一個 key、同樣的內容回原本的報告，內容不同（包含 format）回 409。scan 必須已終止。
  配額（每個 project 5 份進行中、每個 scan 20 份未失敗的報告）在鎖住 project 列之後計數與寫入，
  同時送出也不會超額。報告由 worker 產生，這裡只排入佇列（202）。
- 下載：只有 succeeded 能下載；內容已過期清除時回 410（REPORT_EXPIRED）。解密（context 綁定這份
  報告）之後重新核對 sha256，解不開或不符就回 500、不送出內容。只能以 report id 下載，沒有 path 或
  storage_key 參數。
- 每個 scan 的配額不計失敗與內容已清除的報告。
"""

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from http import HTTPStatus
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from secscan.api_keys.access import authorize
from secscan.api_keys.domain import Permission, Principal
from secscan.audit.service import AuditTrail
from secscan.core.errors import AppError, ErrorCode, not_found_error
from secscan.core.pagination import Page, PageRequest
from secscan.projects.models import ProjectModel
from secscan.reports.domain.model import (
    ACTIVE_REPORT_STATUSES,
    MAX_REPORT_BYTES,
    SCHEMA_VERSION,
    ReportFormat,
    ReportStatus,
    report_context,
)
from secscan.reports.models import ReportContentModel, ReportModel
from secscan.scans.domain.model import Scan
from secscan.scans.service import ScanService
from secscan.security.blob_cipher import BlobCipher, SealedDataUnreadableError
from secscan.targets.domain import LabNetwork

logger = logging.getLogger(__name__)

MAX_ACTIVE_PER_PROJECT = 5
MAX_PER_SCAN = 20
REQUEST_VERSION = 1


@dataclass(frozen=True, slots=True)
class Report:
    id: UUID
    project_id: UUID
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
    expires_at: datetime | None = None
    content_purged_at: datetime | None = None

    @property
    def is_terminal(self) -> bool:
        return self.status in {ReportStatus.SUCCEEDED, ReportStatus.FAILED}


def request_fingerprint(scan_id: UUID, report_format: ReportFormat) -> bytes:
    content = {"v": REQUEST_VERSION, "scan_id": str(scan_id), "format": report_format.value}
    return hashlib.sha256(
        json.dumps(content, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).digest()


class ReportService:
    def __init__(self, session: Session, *, lab: LabNetwork) -> None:
        self._session = session
        self._scans = ScanService(session, lab=lab)
        self._audit = AuditTrail(session)

    def create(
        self,
        principal: Principal,
        scan_id: UUID,
        report_format: ReportFormat,
        *,
        idempotency_key: str,
        request_id: str | None,
    ) -> tuple[Report, bool]:
        scan = self._scans.get(principal, scan_id)
        authorize(principal, Permission.PROJECT_WRITE, scan.project_id)
        fingerprint = request_fingerprint(scan_id, report_format)
        # 先鎖住 project：同一個 project 的建立排隊，配額與 idempotency 的判斷都看得到前一個的結果。
        self._session.execute(
            select(ProjectModel.id)
            .where(ProjectModel.id == scan.project_id)
            .with_for_update(key_share=True)
        )
        replay = self._replay(scan.project_id, idempotency_key, fingerprint)
        if replay is not None:
            return replay, False
        if not scan.is_terminal:
            raise AppError(
                status_code=HTTPStatus.CONFLICT,
                code=ErrorCode.SCAN_NOT_TERMINAL,
                message="scan 結束之後才能產生報告。",
            )
        self._check_quota(scan.project_id, scan_id)
        report = self._enqueue(
            principal, scan, report_format, idempotency_key, fingerprint, request_id
        )
        return report, True

    def _enqueue(
        self,
        principal: Principal,
        scan: Scan,
        report_format: ReportFormat,
        idempotency_key: str,
        fingerprint: bytes,
        request_id: str | None,
    ) -> Report:
        model = ReportModel(
            project_id=scan.project_id,
            target_id=scan.target_id,
            scan_id=scan.id,
            format=report_format.value,
            schema_version=SCHEMA_VERSION,
            status=ReportStatus.QUEUED.value,
            idempotency_key=idempotency_key,
            request_sha256=fingerprint,
            requested_by_key_id=principal.key_id,
        )
        self._session.add(model)
        self._session.flush()
        self._session.refresh(model)
        self._audit.record(
            action="report.create",
            object_type="report",
            object_id=model.id,
            actor_key_id=principal.key_id,
            project_id=scan.project_id,
            request_id=request_id,
            changes={"scan_id": str(scan.id), "format": report_format.value},
        )
        return _report(model)

    def _replay(self, project_id: UUID, idempotency_key: str, fingerprint: bytes) -> Report | None:
        """同一個 key：內容相同回原本的報告，不同（包含 format）回 409。"""
        existing = self._session.scalar(
            select(ReportModel).where(
                ReportModel.project_id == project_id,
                ReportModel.idempotency_key == idempotency_key,
            )
        )
        if existing is None:
            return None
        if existing.request_sha256 != fingerprint:
            raise AppError(
                status_code=HTTPStatus.CONFLICT,
                code=ErrorCode.IDEMPOTENCY_CONFLICT,
                message="同一個 Idempotency-Key 已用於內容不同的報告請求。",
            )
        return _report(existing)

    def get(self, principal: Principal, report_id: UUID) -> Report:
        model = self._session.get(ReportModel, report_id)
        if model is None:
            raise not_found_error()
        authorize(principal, Permission.PROJECT_READ, model.project_id)
        return _report(model)

    def for_scan(self, principal: Principal, scan_id: UUID, page: PageRequest) -> Page[Report]:
        self._scans.get(principal, scan_id)
        total = self._session.scalar(
            select(func.count()).select_from(ReportModel).where(ReportModel.scan_id == scan_id)
        )
        models = self._session.scalars(
            select(ReportModel)
            .where(ReportModel.scan_id == scan_id)
            .order_by(ReportModel.queue_position.desc())
            .offset(page.offset)
            .limit(page.limit)
        ).all()
        return Page(items=tuple(_report(model) for model in models), total=total or 0, request=page)

    def download(
        self, principal: Principal, report_id: UUID, cipher: BlobCipher
    ) -> tuple[Report, bytes]:
        report = self.get(principal, report_id)
        if report.status is not ReportStatus.SUCCEEDED:
            raise AppError(
                status_code=HTTPStatus.CONFLICT,
                code=ErrorCode.REPORT_NOT_READY,
                message="報告尚未產生完成或已失敗。",
            )
        if report.content_purged_at is not None:
            raise AppError(
                status_code=HTTPStatus.GONE,
                code=ErrorCode.REPORT_EXPIRED,
                message="報告內容已超過保留期限並清除（metadata 與 sha256 仍保留）。",
            )
        token = self._session.scalar(
            select(ReportContentModel.content).where(ReportContentModel.report_id == report_id)
        )
        content = _opened(cipher, report_id, token)
        if content is None or hashlib.sha256(content).hexdigest() != report.sha256:
            logger.error("報告 %s 的內容與 sha256 不符：不送出內容", report_id)
            raise AppError(
                status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
                code=ErrorCode.INTERNAL_ERROR,
                message="報告內容核對失敗。",
            )
        return report, content

    def _check_quota(self, project_id: UUID, scan_id: UUID) -> None:
        active = self._session.scalar(
            select(func.count())
            .select_from(ReportModel)
            .where(
                ReportModel.project_id == project_id,
                ReportModel.status.in_([status.value for status in ACTIVE_REPORT_STATUSES]),
            )
        )
        # 失敗的報告不計入每個 scan 的上限：反覆失敗不會讓這個 scan 永久無法產生報告
        # （安全審查 L8）。
        per_scan = self._session.scalar(
            select(func.count())
            .select_from(ReportModel)
            .where(
                ReportModel.scan_id == scan_id,
                ReportModel.status != ReportStatus.FAILED.value,
                ReportModel.content_purged_at.is_(None),
            )
        )
        if (active or 0) >= MAX_ACTIVE_PER_PROJECT or (per_scan or 0) >= MAX_PER_SCAN:
            raise AppError(
                status_code=HTTPStatus.CONFLICT,
                code=ErrorCode.QUOTA_EXCEEDED,
                message=(
                    f"報告數量超過上限（每個 project 同時 {MAX_ACTIVE_PER_PROJECT} 份進行中、"
                    f"每個 scan {MAX_PER_SCAN} 份未失敗、內容未清除的報告）。"
                ),
            )


def _report(model: ReportModel) -> Report:
    return Report(
        id=model.id,
        project_id=model.project_id,
        scan_id=model.scan_id,
        format=ReportFormat(model.format),
        schema_version=model.schema_version,
        status=ReportStatus(model.status),
        attempts=model.attempts,
        error_code=model.error_code,
        data_as_of=model.data_as_of,
        generated_at=model.generated_at,
        size_bytes=model.size_bytes,
        sha256=model.sha256,
        truncated=model.truncated,
        omitted_findings=model.omitted_findings,
        created_at=model.created_at,
        finished_at=model.finished_at,
        expires_at=model.expires_at,
        content_purged_at=model.content_purged_at,
    )


def _opened(cipher: BlobCipher, report_id: UUID, token: bytes | None) -> bytes | None:
    """解密報告內容；沒有內容或解不開（金鑰不對、被改過、屬於別的報告）時回 None。"""
    if token is None:
        return None
    try:
        return cipher.unseal(token, context=report_context(report_id), max_bytes=MAX_REPORT_BYTES)
    except SealedDataUnreadableError:
        return None
