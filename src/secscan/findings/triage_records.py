"""triage 事件與人工複測摘錄的讀寫（T21；docs/DECISIONS.md §28.3、§28.4）。

寫入順序固定（DB 的事件鏈檢查）：先在持有 finding 列鎖時 UPDATE finding（版本 +1），再 INSERT
事件，最後 INSERT 摘錄。resolve 時 trigger 計算 watermark 與連結數；不採用 app 給的值。
人工 PATCH 與 linker 的自動重開共用這裡，鎖都是 FOR NO KEY UPDATE（和比較快照建立時 FK 檢查的
KEY SHARE 相容）。
"""

from collections.abc import Sequence
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import Row, and_, func, insert, select, update
from sqlalchemy.orm import Session

from secscan.api_keys.models import ApiKeyModel
from secscan.core.pagination import Page, PageRequest
from secscan.findings.domain.model import LifecycleState, TriageState
from secscan.findings.domain.triage import (
    ActorKind,
    ExcerptKind,
    NewTriageEvent,
    Resolution,
    ResolutionBasis,
    TriageEvent,
    TriageReasonCode,
    TriageStatus,
)
from secscan.findings.models import (
    FindingModel,
    FindingTriageEventModel,
    FindingTriageExcerptModel,
)

_EVENTS = FindingTriageEventModel


@dataclass(frozen=True, slots=True)
class LockedTriage:
    """PATCH 鎖住 finding 之後看到的狀態。"""

    id: UUID
    target_id: UUID
    status: TriageStatus
    observations_linked: int


class StaleTriageVersionError(Exception):
    """UPDATE 時版本已不同（只會在沒有先鎖住 finding 時發生）。"""


class TriageRecords:
    def __init__(self, session: Session) -> None:
        self._session = session

    def lock(self, finding_id: UUID) -> LockedTriage | None:
        row = self._session.execute(
            select(
                FindingModel.id,
                FindingModel.target_id,
                FindingModel.triage_state,
                FindingModel.lifecycle_state,
                FindingModel.triage_version,
                FindingModel.observations_linked,
            )
            .where(FindingModel.id == finding_id)
            .with_for_update(key_share=True)
        ).first()
        if row is None:
            return None
        status = TriageStatus(
            TriageState(row.triage_state), LifecycleState(row.lifecycle_state), row.triage_version
        )
        return LockedTriage(row.id, row.target_id, status, row.observations_linked)

    def apply(self, finding_id: UUID, planned: TriageStatus) -> None:
        """已鎖住的 finding 改成 planned（版本必須恰好是目前 +1）。"""
        updated = self._session.execute(
            update(FindingModel)
            .where(
                FindingModel.id == finding_id,
                FindingModel.triage_version == planned.version - 1,
            )
            .values(
                triage_state=planned.triage.value,
                lifecycle_state=planned.lifecycle.value,
                triage_version=planned.version,
            )
            .returning(FindingModel.id)
            .execution_options(synchronize_session=False)
        ).scalar_one_or_none()
        if updated is None:
            raise StaleTriageVersionError("finding 的 triage 版本已改變")

    def append(self, event: NewTriageEvent) -> None:
        self._session.execute(
            insert(_EVENTS).values(
                finding_id=event.finding_id,
                target_id=event.target_id,
                sequence=event.sequence,
                actor_kind=event.actor_kind.value,
                actor_key_id=event.actor_key_id,
                request_id=event.request_id,
                previous_triage_state=event.previous.triage.value,
                triage_state=event.current.triage.value,
                previous_lifecycle_state=event.previous.lifecycle.value,
                lifecycle_state=event.current.lifecycle.value,
                reason_code=event.reason_code.value,
                reason=event.reason,
                comparison_id=event.comparison_id,
                resolution_basis=event.basis.value if event.basis is not None else None,
                run_id=event.run_id,
                scan_id=event.scan_id,
                evidence=event.evidence,
            )
        )

    def append_excerpts(self, finding_id: UUID, sequence: int, request: str, response: str) -> None:
        self._session.execute(
            insert(FindingTriageExcerptModel),
            [
                {"finding_id": finding_id, "sequence": sequence, "kind": kind, "content": text}
                for kind, text in ((ExcerptKind.REQUEST, request), (ExcerptKind.RESPONSE, response))
            ],
        )

    def events(
        self, finding_id: UUID, page: PageRequest, *, with_excerpts: bool
    ) -> Page[TriageEvent]:
        total = self._session.scalar(
            select(func.count()).select_from(_EVENTS).where(_EVENTS.finding_id == finding_id)
        )
        rows = self._session.execute(
            select(_EVENTS, ApiKeyModel.name, ApiKeyModel.role)
            .outerjoin(ApiKeyModel, ApiKeyModel.id == _EVENTS.actor_key_id)
            .where(_EVENTS.finding_id == finding_id)
            .order_by(_EVENTS.sequence)
            .offset(page.offset)
            .limit(page.limit)
        ).all()
        excerpts = (
            self._excerpts(finding_id, [row[0].sequence for row in rows]) if with_excerpts else {}
        )
        items = tuple(
            _event(row, excerpts.get(row[0].sequence, ()) if with_excerpts else None)
            for row in rows
        )
        return Page(items=items, total=total or 0, request=page)

    def resolution(self, finding_id: UUID) -> Resolution | None:
        """目前的 resolved 依據：finding 是 resolved 時，最後一次轉成 resolved 的事件。"""
        row = self._session.execute(
            select(_EVENTS, ApiKeyModel.name, ApiKeyModel.role)
            .join(
                FindingModel,
                and_(
                    FindingModel.id == _EVENTS.finding_id,
                    FindingModel.lifecycle_state == LifecycleState.RESOLVED.value,
                ),
            )
            .outerjoin(ApiKeyModel, ApiKeyModel.id == _EVENTS.actor_key_id)
            .where(_EVENTS.finding_id == finding_id, _EVENTS.comparison_id.is_not(None))
            .order_by(_EVENTS.sequence.desc())
            .limit(1)
        ).first()
        if row is None:
            return None
        event: FindingTriageEventModel = row[0]
        attestation = event.evidence.get("attestation")
        if event.comparison_id is None or event.resolution_basis is None:
            return None
        return Resolution(
            basis=ResolutionBasis(event.resolution_basis),
            comparison_id=event.comparison_id,
            decided_at=event.created_at,
            decided_by_role=row.role,
            decided_by_name=row.name,
            event_sequence=event.sequence,
            attestation=attestation if isinstance(attestation, dict) else None,
        )

    def _excerpts(
        self, finding_id: UUID, sequences: Sequence[int]
    ) -> dict[int, tuple[tuple[ExcerptKind, str], ...]]:
        if not sequences:
            return {}
        rows = self._session.execute(
            select(
                FindingTriageExcerptModel.sequence,
                FindingTriageExcerptModel.kind,
                FindingTriageExcerptModel.content,
            )
            .where(
                FindingTriageExcerptModel.finding_id == finding_id,
                FindingTriageExcerptModel.sequence.in_(sequences),
            )
            .order_by(FindingTriageExcerptModel.sequence, FindingTriageExcerptModel.kind)
        )
        excerpts: dict[int, list[tuple[ExcerptKind, str]]] = {}
        for row in rows:
            excerpts.setdefault(row.sequence, []).append((ExcerptKind(row.kind), row.content))
        return {sequence: tuple(items) for sequence, items in excerpts.items()}


def _event(
    row: Row[FindingTriageEventModel, str | None, str | None],
    excerpts: tuple[tuple[ExcerptKind, str], ...] | None,
) -> TriageEvent:
    model: FindingTriageEventModel = row[0]
    return TriageEvent(
        sequence=model.sequence,
        actor_kind=ActorKind(model.actor_kind),
        actor_key_id=model.actor_key_id,
        actor_name=row.name,
        actor_role=row.role,
        request_id=model.request_id,
        previous_triage=TriageState(model.previous_triage_state),
        triage=TriageState(model.triage_state),
        previous_lifecycle=LifecycleState(model.previous_lifecycle_state),
        lifecycle=LifecycleState(model.lifecycle_state),
        reason_code=TriageReasonCode(model.reason_code),
        reason=model.reason,
        comparison_id=model.comparison_id,
        basis=ResolutionBasis(model.resolution_basis) if model.resolution_basis else None,
        run_id=model.run_id,
        scan_id=model.scan_id,
        evidence=model.evidence,
        created_at=model.created_at,
        excerpts=excerpts,
    )
