"""報告內容與人工複測摘錄的金鑰換版（docs/DECISIONS.md §30.6）。

以 CONTENT_ENCRYPTION_KEYS 的第一個金鑰重新加密（rotate 先確認解得開、context 相符）：
- 報告：一份一個 transaction（密文最大約 11 MiB，避開 30 秒的 statement 上限與記憶體上限）；以
  FOR UPDATE 鎖住內容，和到期清除互斥。已清除的報告沒有內容，略過。
- 摘錄：每批最多 batch 段一個 transaction，以 keyset 分頁。
- 解不開的保留原狀並列出（只有 id，不含任何內容），其他照常換版；可以重複執行。
"""

from collections.abc import Sequence
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import Row, select, tuple_, update
from sqlalchemy.orm import Session, sessionmaker

from secscan.findings.domain.triage import EXCERPT_MAX_BYTES, ExcerptKind, excerpt_context
from secscan.findings.models import FindingTriageExcerptModel
from secscan.reports.domain.model import MAX_REPORT_BYTES, report_context
from secscan.reports.models import ReportContentModel, ReportModel
from secscan.security.blob_cipher import BlobCipher, SealedDataUnreadableError

BATCH = 100
_EXCERPTS = FindingTriageExcerptModel


@dataclass(frozen=True, slots=True)
class RotationResult:
    reports: int
    excerpts: int
    unreadable_reports: tuple[UUID, ...]
    unreadable_excerpts: tuple[tuple[UUID, int, str], ...]

    @property
    def failures(self) -> int:
        return len(self.unreadable_reports) + len(self.unreadable_excerpts)


class ContentRotation:
    def __init__(
        self, sessions: sessionmaker[Session], cipher: BlobCipher, *, batch: int = BATCH
    ) -> None:
        self._sessions = sessions
        self._cipher = cipher
        self._batch = batch

    def run(self) -> RotationResult:
        reports, unreadable_reports = self._reports()
        excerpts, unreadable_excerpts = self._excerpts()
        return RotationResult(
            reports, excerpts, tuple(unreadable_reports), tuple(unreadable_excerpts)
        )

    def _reports(self) -> tuple[int, list[UUID]]:
        with self._sessions() as session:
            ids = session.scalars(
                select(ReportContentModel.report_id).order_by(ReportContentModel.report_id)
            ).all()
        rotated, unreadable = 0, []
        for report_id in ids:
            with self._sessions.begin() as session:
                token = session.scalar(
                    select(ReportContentModel.content)
                    .join(ReportModel, ReportModel.id == ReportContentModel.report_id)
                    .where(
                        ReportContentModel.report_id == report_id,
                        ReportModel.content_purged_at.is_(None),
                    )
                    .with_for_update(of=ReportContentModel)
                )
                if token is None:
                    continue
                try:
                    renewed = self._cipher.rotate(
                        token, context=report_context(report_id), max_bytes=MAX_REPORT_BYTES
                    )
                except SealedDataUnreadableError:
                    unreadable.append(report_id)
                    continue
                session.execute(
                    update(ReportContentModel)
                    .where(ReportContentModel.report_id == report_id)
                    .values(content=renewed)
                    .execution_options(synchronize_session=False)
                )
                rotated += 1
        return rotated, unreadable

    def _excerpts(self) -> tuple[int, list[tuple[UUID, int, str]]]:
        rotated, unreadable = 0, []
        after: tuple[UUID, int, str] | None = None
        while True:
            with self._sessions.begin() as session:
                rows = self._excerpt_batch(session, after)
                for row in rows:
                    key = (row.finding_id, row.sequence, row.kind)
                    renewed = self._rotated_excerpt(row)
                    if renewed is None:
                        unreadable.append(key)
                        continue
                    session.execute(
                        update(_EXCERPTS)
                        .where(
                            _EXCERPTS.finding_id == row.finding_id,
                            _EXCERPTS.sequence == row.sequence,
                            _EXCERPTS.kind == row.kind,
                        )
                        .values(sealed_content=renewed)
                        .execution_options(synchronize_session=False)
                    )
                    rotated += 1
            if len(rows) < self._batch:
                return rotated, unreadable
            last = rows[-1]
            after = (last.finding_id, last.sequence, last.kind)

    def _excerpt_batch(
        self, session: Session, after: tuple[UUID, int, str] | None
    ) -> Sequence[Row[UUID, int, str, bytes | None]]:
        query = select(
            _EXCERPTS.finding_id, _EXCERPTS.sequence, _EXCERPTS.kind, _EXCERPTS.sealed_content
        ).where(_EXCERPTS.sealed_content.is_not(None))
        if after is not None:
            query = query.where(
                tuple_(_EXCERPTS.finding_id, _EXCERPTS.sequence, _EXCERPTS.kind) > tuple_(*after)
            )
        return session.execute(
            query.order_by(_EXCERPTS.finding_id, _EXCERPTS.sequence, _EXCERPTS.kind)
            .limit(self._batch)
            .with_for_update()
        ).all()

    def _rotated_excerpt(self, row: Row[UUID, int, str, bytes | None]) -> bytes | None:
        kind = ExcerptKind(row.kind)
        if row.sealed_content is None:
            return None
        try:
            return self._cipher.rotate(
                row.sealed_content,
                context=excerpt_context(row.finding_id, row.sequence, kind),
                max_bytes=EXCERPT_MAX_BYTES[kind],
            )
        except SealedDataUnreadableError:
            return None
