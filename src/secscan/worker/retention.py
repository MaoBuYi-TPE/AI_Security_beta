"""報告內容與人工複測摘錄的到期清除（docs/DECISIONS.md §30.5）；worker 每 10 分鐘執行一次。

- 報告：succeeded、還沒清除、expires_at 已過 → 寫入 content_purged_at，刪除 report_contents
  （同一個 transaction；DB 的 trigger 只允許到期的報告這樣做）。reports 列、sha256 與 audit 保留，
  下載回 410。
- 摘錄：還沒清除、expires_at 已過 → sealed_content 改成 NULL、寫入 purged_at（tombstone；事件中的
  雜湊與長度、「每個人工複測事件恰好兩筆」都不變）。
- 到期以 DB 的時鐘判斷（和 trigger 的檢查相同）；每批有數量上限，以 FOR UPDATE SKIP LOCKED 認領，
  和換版、其他 worker 不衝突。
- 只是刪除欄位與資料列：DB 的 dead tuple、WAL 與備份仍保留舊資料，直到 VACUUM 或備份輪替。
"""

from dataclasses import dataclass

from sqlalchemy import ColumnElement, and_, delete, func, select, tuple_, update
from sqlalchemy.orm import Session, sessionmaker

from secscan.findings.models import FindingTriageExcerptModel
from secscan.reports.domain.model import ReportStatus
from secscan.reports.models import ReportContentModel, ReportModel

PURGE_EVERY_SECONDS = 600.0
BATCH = 50
_EXCERPTS = FindingTriageExcerptModel


@dataclass(frozen=True, slots=True)
class PurgeReport:
    reports: int
    excerpts: int


@dataclass(frozen=True, slots=True)
class ContentSummary:
    """retention-status 的數量：保留中、已到期待清除、已清除。"""

    reports_kept: int
    reports_due: int
    reports_purged: int
    excerpts_kept: int
    excerpts_due: int
    excerpts_purged: int


class ContentRetention:
    def __init__(self, sessions: sessionmaker[Session], *, batch: int = BATCH) -> None:
        self._sessions = sessions
        self._batch = batch

    def purge(self) -> PurgeReport:
        return PurgeReport(reports=self._reports(), excerpts=self._excerpts())

    def summary(self) -> ContentSummary:
        with self._sessions() as session:

            def count(*conditions: ColumnElement[bool]) -> int:
                return int(session.scalar(select(func.count()).where(*conditions)) or 0)

            succeeded = ReportModel.status == ReportStatus.SUCCEEDED.value
            kept = and_(succeeded, ReportModel.content_purged_at.is_(None))
            return ContentSummary(
                reports_kept=count(kept),
                reports_due=count(_report_due()),
                reports_purged=count(ReportModel.content_purged_at.is_not(None)),
                excerpts_kept=count(_EXCERPTS.purged_at.is_(None)),
                excerpts_due=count(_excerpt_due()),
                excerpts_purged=count(_EXCERPTS.purged_at.is_not(None)),
            )

    def _reports(self) -> int:
        with self._sessions.begin() as session:
            ids = session.scalars(
                select(ReportModel.id)
                .where(_report_due())
                .order_by(ReportModel.expires_at, ReportModel.id)
                .limit(self._batch)
                .with_for_update(skip_locked=True)
            ).all()
            if not ids:
                return 0
            session.execute(
                update(ReportModel)
                .where(ReportModel.id.in_(ids))
                .values(content_purged_at=func.clock_timestamp())
                .execution_options(synchronize_session=False)
            )
            session.execute(
                delete(ReportContentModel)
                .where(ReportContentModel.report_id.in_(ids))
                .execution_options(synchronize_session=False)
            )
            return len(ids)

    def _excerpts(self) -> int:
        with self._sessions.begin() as session:
            keys = session.execute(
                select(_EXCERPTS.finding_id, _EXCERPTS.sequence, _EXCERPTS.kind)
                .where(_excerpt_due())
                .order_by(_EXCERPTS.expires_at, _EXCERPTS.finding_id, _EXCERPTS.sequence)
                .limit(self._batch)
                .with_for_update(skip_locked=True)
            ).all()
            if not keys:
                return 0
            session.execute(
                update(_EXCERPTS)
                .where(
                    tuple_(_EXCERPTS.finding_id, _EXCERPTS.sequence, _EXCERPTS.kind).in_(
                        [tuple(key) for key in keys]
                    )
                )
                .values(sealed_content=None, purged_at=func.clock_timestamp())
                .execution_options(synchronize_session=False)
            )
            return len(keys)


def _report_due() -> ColumnElement[bool]:
    return and_(
        ReportModel.status == ReportStatus.SUCCEEDED.value,
        ReportModel.content_purged_at.is_(None),
        ReportModel.expires_at <= func.clock_timestamp(),
    )


def _excerpt_due() -> ColumnElement[bool]:
    return and_(
        _EXCERPTS.purged_at.is_(None),
        _EXCERPTS.expires_at <= func.clock_timestamp(),
    )
