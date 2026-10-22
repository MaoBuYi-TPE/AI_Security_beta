"""targets 的資料存取；回傳 frozen domain model。誰能看到、修改哪些 target 由 service 決定。"""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from secscan.core.db import flush_or_raise
from secscan.core.pagination import Page, PageRequest
from secscan.targets.domain import (
    NewTarget,
    Target,
    TargetChange,
    TargetEnvironment,
    TargetKind,
    TargetUpdate,
    parse_origin,
)
from secscan.targets.models import TargetModel


class TargetRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, new_target: NewTarget) -> Target:
        """新增 target；同一個 project 已有相同 origin 時拋出 ConstraintViolationError
        （uq_targets_project_id_canonical_origin）。"""
        model = TargetModel(
            project_id=new_target.project_id,
            name=new_target.name,
            kind=new_target.kind.value,
            canonical_origin=str(new_target.origin),
            environment=new_target.environment.value,
        )
        self._session.add(model)
        flush_or_raise(self._session)
        return _to_domain(model)

    def get(self, target_id: UUID) -> Target | None:
        model = self._session.get(TargetModel, target_id)
        return _to_domain(model) if model is not None else None

    def lock(self, target_id: UUID, *, shared: bool = False) -> Target | None:
        """鎖住 target，並以 DB 的最新值覆蓋已載入的物件。

        shared=False 是 FOR UPDATE（要修改它，或依它決定 grant 的 version）；
        shared=True 是 FOR SHARE（建立 scan 時，避免同時被停用；docs/DECISIONS.md §10.6）。
        """
        model = self._session.get(
            TargetModel, target_id, with_for_update={"read": shared}, populate_existing=True
        )
        return _to_domain(model) if model is not None else None

    def count_in_project(self, project_id: UUID) -> int:
        return (
            self._session.scalar(
                select(func.count())
                .select_from(TargetModel)
                .where(TargetModel.project_id == project_id)
            )
            or 0
        )

    def list_by_project(self, project_id: UUID, page: PageRequest) -> Page[Target]:
        """依建立時間由舊到新（同時間再依 id，分頁順序穩定）。"""
        in_project = TargetModel.project_id == project_id
        total = (
            self._session.scalar(select(func.count()).select_from(TargetModel).where(in_project))
            or 0
        )
        rows = self._session.scalars(
            select(TargetModel)
            .where(in_project)
            .order_by(TargetModel.created_at, TargetModel.id)
            .offset(page.offset)
            .limit(page.limit)
        )
        return Page(items=tuple(_to_domain(row) for row in rows), total=total, request=page)

    def update(self, target_id: UUID, changes: TargetUpdate) -> TargetChange | None:
        """先鎖住再修改，回傳修改前後的值；不存在時回 None。origin 不能改。"""
        model = self._session.get(
            TargetModel, target_id, with_for_update={"read": False}, populate_existing=True
        )
        if model is None:
            return None
        before = _to_domain(model)
        if changes.name is not None:
            model.name = changes.name
        if changes.enabled is not None:
            model.enabled = changes.enabled
        flush_or_raise(self._session)
        return TargetChange(before=before, after=_to_domain(model))


def _to_domain(model: TargetModel) -> Target:
    # origin 再經過一次正規化規則：DB 中不合規則的值會讓讀取失敗（fail closed）。
    return Target(
        id=model.id,
        project_id=model.project_id,
        name=model.name,
        kind=TargetKind(model.kind),
        origin=parse_origin(model.canonical_origin),
        environment=TargetEnvironment(model.environment),
        enabled=model.enabled,
        created_at=model.created_at,
    )
