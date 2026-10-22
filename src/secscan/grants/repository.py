"""scope_grants 的資料存取；回傳 frozen domain model。轉換是否合法由 domain 與 service 決定。

grant 所屬的 project 由 target 取得（join targets），不在 grant 重複存放。
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import Row, Select, func, select
from sqlalchemy.orm import Session

from secscan.core.db import flush_or_raise
from secscan.core.pagination import Page, PageRequest
from secscan.grants.domain.lifecycle import GrantStatus, ScopeGrant
from secscan.grants.domain.scope import (
    Budget,
    HttpMethod,
    NewScopeGrant,
    Scope,
    ValidityWindow,
)
from secscan.grants.models import ScopeGrantModel
from secscan.targets.domain import parse_ipv4, parse_origin
from secscan.targets.models import TargetModel


class ScopeGrantRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def next_version(self, target_id: UUID) -> int:
        """target 的下一個 version。呼叫端必須先以 FOR UPDATE 鎖住 target，否則同時申請會撞號。"""
        current = self._session.scalar(
            select(func.max(ScopeGrantModel.version)).where(ScopeGrantModel.target_id == target_id)
        )
        return (current or 0) + 1

    def count_pending(self, target_id: UUID, *, now: datetime) -> int:
        """target 待核准的申請數（pending 且尚未過期；過期的已不能核准，不佔名額）。"""
        return (
            self._session.scalar(
                select(func.count())
                .select_from(ScopeGrantModel)
                .where(
                    ScopeGrantModel.target_id == target_id,
                    ScopeGrantModel.status == GrantStatus.PENDING.value,
                    ScopeGrantModel.valid_until > now,
                )
            )
            or 0
        )

    def create(self, new_grant: NewScopeGrant, *, version: int) -> ScopeGrant:
        """新增 pending 的 grant；version 重複時拋出 ConstraintViolationError。"""
        scope, budget, window = new_grant.scope, new_grant.budget, new_grant.window
        model = ScopeGrantModel(
            target_id=new_grant.target_id,
            version=version,
            status=GrantStatus.PENDING.value,
            allowed_origins=[str(origin) for origin in scope.origins],
            allowed_ips=[str(address) for address in scope.ips],
            allowed_paths=list(scope.paths),
            allow_all_paths=scope.allow_all_paths,
            excluded_paths=list(scope.excluded_paths),
            allowed_methods=[method.value for method in scope.methods],
            requests_per_second=budget.requests_per_second,
            max_requests=budget.max_requests,
            max_duration_seconds=budget.max_duration_seconds,
            authorization_reference=new_grant.authorization_reference,
            valid_from=window.valid_from,
            valid_until=window.valid_until,
            requested_by_key_id=new_grant.requested_by_key_id,
        )
        self._session.add(model)
        flush_or_raise(self._session)
        return self._required(model.id)

    def get(self, grant_id: UUID) -> ScopeGrant | None:
        row = self._session.execute(_with_project().where(ScopeGrantModel.id == grant_id)).first()
        return _from_row(row) if row is not None else None

    def lock(self, grant_id: UUID, *, shared: bool = False) -> ScopeGrant | None:
        """鎖住 grant（不鎖 target），並以 DB 的最新值覆蓋已載入的物件。

        shared=False 是 FOR UPDATE（核准或撤銷）；shared=True 是 FOR SHARE（掃描 gate）。
        """
        statement = (
            _with_project()
            .where(ScopeGrantModel.id == grant_id)
            .with_for_update(of=ScopeGrantModel, read=shared)
            .execution_options(populate_existing=True)
        )
        row = self._session.execute(statement).first()
        return _from_row(row) if row is not None else None

    def list_by_target(self, target_id: UUID, page: PageRequest) -> Page[ScopeGrant]:
        """新版本在前。"""
        of_target = ScopeGrantModel.target_id == target_id
        total = (
            self._session.scalar(select(func.count()).select_from(ScopeGrantModel).where(of_target))
            or 0
        )
        rows = self._session.execute(
            _with_project()
            .where(of_target)
            .order_by(ScopeGrantModel.version.desc())
            .offset(page.offset)
            .limit(page.limit)
        )
        return Page(items=tuple(_from_row(row) for row in rows), total=total, request=page)

    def record_approval(self, grant_id: UUID, *, key_id: UUID, note: str) -> ScopeGrant:
        """記下核准。呼叫端必須已在同一個 transaction 中鎖住這個 grant。

        時間是 transaction 開始的時間（now()）：它不晚於 service 判斷「尚未到期」時用的時間，
        所以 CHECK 的 approved_at < valid_until 與 domain 的判斷一致。
        """
        model = self._loaded(grant_id)
        model.status = GrantStatus.APPROVED.value
        model.approved_by_key_id = key_id
        model.approved_at = func.now()
        model.approval_note = note
        flush_or_raise(self._session)
        return self._required(grant_id)

    def record_revocation(self, grant_id: UUID, *, key_id: UUID, reason: str) -> ScopeGrant:
        """記下撤銷。呼叫端必須已在同一個 transaction 中鎖住這個 grant。

        時間用 clock_timestamp()（取得鎖之後實際寫入的時間），不用 now()：撤銷的 transaction
        可能比一個同時進行的核准更早開始，卻在核准 commit 之後才拿到鎖；記成 transaction 開始
        的時間會早於 approved_at，違反 CHECK（docs/DECISIONS.md §10.4）。
        """
        model = self._loaded(grant_id)
        model.status = GrantStatus.REVOKED.value
        model.revoked_by_key_id = key_id
        model.revoked_at = func.clock_timestamp()
        model.revocation_reason = reason
        flush_or_raise(self._session)
        return self._required(grant_id)

    def _loaded(self, grant_id: UUID) -> ScopeGrantModel:
        model = self._session.get(ScopeGrantModel, grant_id)
        if model is None:
            raise LookupError("找不到要更新的 scope grant")
        return model

    def _required(self, grant_id: UUID) -> ScopeGrant:
        grant = self.get(grant_id)
        if grant is None:
            raise LookupError("找不到剛寫入的 scope grant")
        return grant


def _with_project() -> Select[ScopeGrantModel, UUID]:
    return select(ScopeGrantModel, TargetModel.project_id).join(
        TargetModel, TargetModel.id == ScopeGrantModel.target_id
    )


def _from_row(row: Row[ScopeGrantModel, UUID]) -> ScopeGrant:
    model, project_id = row
    return _to_domain(model, project_id)


def _to_domain(model: ScopeGrantModel, project_id: UUID) -> ScopeGrant:
    # 讀回的值再經過 domain 的規則：DB 中不合規則的資料（例如網段）會讓讀取失敗（fail closed）。
    return ScopeGrant(
        id=model.id,
        target_id=model.target_id,
        project_id=project_id,
        version=model.version,
        status=GrantStatus(model.status),
        scope=Scope(
            origins=tuple(parse_origin(origin) for origin in model.allowed_origins),
            ips=tuple(parse_ipv4(str(address)) for address in model.allowed_ips),
            paths=tuple(model.allowed_paths),
            allow_all_paths=model.allow_all_paths,
            excluded_paths=tuple(model.excluded_paths),
            methods=tuple(HttpMethod(method) for method in model.allowed_methods),
        ),
        budget=Budget(
            requests_per_second=model.requests_per_second,
            max_requests=model.max_requests,
            max_duration_seconds=model.max_duration_seconds,
        ),
        window=ValidityWindow(valid_from=model.valid_from, valid_until=model.valid_until),
        authorization_reference=model.authorization_reference,
        requested_by_key_id=model.requested_by_key_id,
        created_at=model.created_at,
        approved_by_key_id=model.approved_by_key_id,
        approved_at=model.approved_at,
        approval_note=model.approval_note,
        revoked_by_key_id=model.revoked_by_key_id,
        revoked_at=model.revoked_at,
        revocation_reason=model.revocation_reason,
    )
