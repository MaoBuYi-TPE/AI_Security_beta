"""scope grant 的業務規則（docs/DECISIONS.md §10.3 到 §10.6）：

- 申請：PROJECT_WRITE。先以 FOR UPDATE 鎖住 target，再取下一個 version。
- 核准、撤銷：PLATFORM_MANAGE（admin）。先以 FOR UPDATE 鎖住 grant，再以 DB 的最新狀態判斷轉換。
- 掃描 gate（require_usable）：T09 建立 scan 時在同一個 transaction 呼叫。
- 其他 project 的 target 與 grant 一律和不存在的一樣回 404；變更寫入 audit。
"""

from collections.abc import Mapping
from datetime import datetime
from http import HTTPStatus
from types import MappingProxyType
from uuid import UUID

from sqlalchemy.orm import Session

from secscan.api_keys.access import authorize
from secscan.api_keys.domain import Permission, Principal
from secscan.audit.service import AuditTrail
from secscan.core.errors import AppError, ErrorCode, not_found_error
from secscan.core.json_types import JsonObject
from secscan.core.pagination import Page, PageRequest
from secscan.core.text import require_text
from secscan.grants.domain.lifecycle import (
    DECISION_NOTE_MAX_LENGTH,
    GrantAction,
    GrantState,
    GrantStatus,
    GrantUnusableError,
    InvalidTransitionError,
    ScopeGrant,
    UnusableReason,
    check_usable,
    plan_transition,
)
from secscan.grants.domain.scope import (
    GrantRequest,
    InvalidScopeError,
    NewScopeGrant,
    build_new_grant,
    check_lab,
)
from secscan.grants.repository import ScopeGrantRepository
from secscan.targets.domain import InvalidOriginError, LabNetwork, OutsideLabError, Target
from secscan.targets.errors import invalid_target_error, outside_lab_error
from secscan.targets.repository import TargetRepository

# grant 無法刪除、單筆最大可達上百 KB：每個 target 待核准（pending 且未過期）的申請有上限，
# 一把外洩的 operator key 才不會塞滿磁碟（docs/DECISIONS.md §10.9）。
MAX_PENDING_GRANTS_PER_TARGET = 10

_ACTION_LABELS: Mapping[GrantAction, str] = MappingProxyType(
    {GrantAction.APPROVE: "核准", GrantAction.REVOKE: "撤銷"}
)
UNUSABLE_ERRORS: Mapping[UnusableReason, tuple[HTTPStatus, ErrorCode, str]] = MappingProxyType(
    {
        UnusableReason.WRONG_TARGET: (
            HTTPStatus.UNPROCESSABLE_ENTITY,
            ErrorCode.INVALID_REQUEST,
            "scope grant 不屬於這個 target。",
        ),
        UnusableReason.ORIGIN_NOT_GRANTED: (
            HTTPStatus.UNPROCESSABLE_ENTITY,
            ErrorCode.INVALID_REQUEST,
            "target 的 origin 不在 scope grant 的範圍內。",
        ),
        UnusableReason.NOT_APPROVED: (
            HTTPStatus.FORBIDDEN,
            ErrorCode.SCOPE_NOT_APPROVED,
            "scope grant 尚未核准。",
        ),
        UnusableReason.REVOKED: (
            HTTPStatus.FORBIDDEN,
            ErrorCode.SCOPE_NOT_APPROVED,
            "scope grant 已撤銷。",
        ),
        UnusableReason.NOT_YET_VALID: (
            HTTPStatus.FORBIDDEN,
            ErrorCode.SCOPE_NOT_APPROVED,
            "scope grant 尚未生效（valid_from 之後才能使用）。",
        ),
        UnusableReason.EXPIRED: (
            HTTPStatus.FORBIDDEN,
            ErrorCode.SCOPE_EXPIRED,
            "scope grant 已過期，請重新申請。",
        ),
        UnusableReason.TARGET_DISABLED: (
            HTTPStatus.CONFLICT,
            ErrorCode.TARGET_DISABLED,
            "target 已停用。",
        ),
    }
)


class ScopeGrantService:
    def __init__(self, session: Session, *, lab: LabNetwork) -> None:
        self._grants = ScopeGrantRepository(session)
        self._targets = TargetRepository(session)
        self._audit = AuditTrail(session)
        self._lab = lab

    def request(
        self,
        principal: Principal,
        target_id: UUID,
        request: GrantRequest,
        *,
        now: datetime,
        request_id: str | None,
    ) -> ScopeGrant:
        """申請一個 pending 的 grant（新的版本）；範圍與 IP 不合規則時回 422，什麼都不寫入。"""
        self._target(principal, target_id, Permission.PROJECT_WRITE)
        # FOR UPDATE：同時申請時，version 依 commit 的先後遞增，不會撞號。
        target = self._targets.lock(target_id)
        if target is None:
            raise not_found_error()
        if self._grants.count_pending(target_id, now=now) >= MAX_PENDING_GRANTS_PER_TARGET:
            raise AppError(
                status_code=HTTPStatus.CONFLICT,
                code=ErrorCode.QUOTA_EXCEEDED,
                message=(
                    f"這個 target 已有 {MAX_PENDING_GRANTS_PER_TARGET} 個待核准的申請；"
                    "請先核准或撤銷，再申請新的版本。"
                ),
            )
        new_grant = self._validated(request, target, principal, now)
        grant = self._grants.create(new_grant, version=self._grants.next_version(target_id))
        self._record(grant, "scope_grant.create", principal, request_id, _summary(grant))
        return grant

    def list_for_target(
        self, principal: Principal, target_id: UUID, page: PageRequest
    ) -> Page[ScopeGrant]:
        self._target(principal, target_id, Permission.PROJECT_READ)
        return self._grants.list_by_target(target_id, page)

    def get(self, principal: Principal, grant_id: UUID) -> ScopeGrant:
        return self._grant(principal, grant_id, Permission.PROJECT_READ)

    def approve(
        self,
        principal: Principal,
        grant_id: UUID,
        *,
        note: str,
        now: datetime,
        request_id: str | None,
    ) -> ScopeGrant:
        """pending → approved。核准時以當下的 LAB_CIDR 重新檢查（設定可能在申請後改變）。"""
        self._grant(principal, grant_id, Permission.PLATFORM_MANAGE)
        _check_decision_text(note, field="note")
        grant = self._locked(grant_id)
        _transition(GrantAction.APPROVE, grant.state_at(now))
        try:
            check_lab(grant.scope, self._lab)
        except OutsideLabError as exc:
            raise outside_lab_error(exc) from None
        approved = self._grants.record_approval(grant_id, key_id=principal.key_id, note=note)
        changes: JsonObject = {"version": approved.version, "note": note}
        self._record(approved, "scope_grant.approve", principal, request_id, changes)
        return approved

    def revoke(
        self,
        principal: Principal,
        grant_id: UUID,
        *,
        reason: str,
        now: datetime,
        request_id: str | None,
    ) -> ScopeGrant:
        """pending、approved → revoked。已撤銷的再撤銷一次不改變任何東西，也不重記 audit。"""
        self._grant(principal, grant_id, Permission.PLATFORM_MANAGE)
        _check_decision_text(reason, field="reason")
        grant = self._locked(grant_id)
        state = grant.state_at(now)
        if _transition(GrantAction.REVOKE, state) is None:
            return grant
        revoked = self._grants.record_revocation(grant_id, key_id=principal.key_id, reason=reason)
        changes: JsonObject = {
            "version": revoked.version,
            "reason": reason,
            "previous_state": state.value,
        }
        self._record(revoked, "scope_grant.revoke", principal, request_id, changes)
        return revoked

    def require_usable(
        self, principal: Principal, *, target_id: UUID, grant_id: UUID, now: datetime
    ) -> ScopeGrant:
        """這個 grant 現在能不能用來建立 scan（docs/DECISIONS.md §10.6）。

        T09 建立 scan 時在同一個 transaction 呼叫。以 FOR SHARE 依序鎖住 target 與 grant：
        撤銷或停用一旦 commit，之後就不可能再通過；反過來，正在建立 scan 時，撤銷會等它 commit。
        """
        self._target(principal, target_id, Permission.PROJECT_WRITE)
        self._grant(principal, grant_id, Permission.PROJECT_WRITE)
        target = self._targets.lock(target_id, shared=True)
        grant = self._grants.lock(grant_id, shared=True)
        if target is None or grant is None:
            raise not_found_error()
        try:
            check_usable(grant, target=target, lab=self._lab, now=now)
        except GrantUnusableError as exc:
            status, code, message = UNUSABLE_ERRORS[exc.reason]
            raise AppError(status_code=status, code=code, message=message) from None
        except OutsideLabError as exc:
            raise outside_lab_error(exc) from None
        return grant

    def _target(self, principal: Principal, target_id: UUID, permission: Permission) -> Target:
        """先取出所屬的 project 再檢查權限：其他 project 與不存在的一樣回 404。"""
        target = self._targets.get(target_id)
        if target is None:
            raise not_found_error()
        authorize(principal, permission, target.project_id)
        return target

    def _grant(self, principal: Principal, grant_id: UUID, permission: Permission) -> ScopeGrant:
        grant = self._grants.get(grant_id)
        if grant is None:
            raise not_found_error()
        authorize(principal, permission, grant.project_id)
        return grant

    def _locked(self, grant_id: UUID) -> ScopeGrant:
        """FOR UPDATE：同時核准與撤銷時，後到的那一個以先到的結果判斷。"""
        grant = self._grants.lock(grant_id)
        if grant is None:
            raise not_found_error()
        return grant

    def _validated(
        self, request: GrantRequest, target: Target, principal: Principal, now: datetime
    ) -> NewScopeGrant:
        try:
            new_grant = build_new_grant(
                request,
                target_id=target.id,
                target_origin=target.origin,
                requested_by=principal.key_id,
                now=now,
            )
            check_lab(new_grant.scope, self._lab)
        except InvalidOriginError as exc:
            raise invalid_target_error(exc) from None
        except OutsideLabError as exc:
            raise outside_lab_error(exc) from None
        except InvalidScopeError as exc:
            raise _invalid_request(str(exc)) from None
        return new_grant

    def _record(
        self,
        grant: ScopeGrant,
        action: str,
        principal: Principal,
        request_id: str | None,
        changes: JsonObject,
    ) -> None:
        self._audit.record(
            action=action,
            object_type="scope_grant",
            object_id=grant.id,
            actor_key_id=principal.key_id,
            project_id=grant.project_id,
            request_id=request_id,
            changes=changes,
        )


def _transition(action: GrantAction, state: GrantState) -> GrantStatus | None:
    try:
        return plan_transition(action, state)
    except InvalidTransitionError:
        raise AppError(
            status_code=HTTPStatus.CONFLICT,
            code=ErrorCode.INVALID_STATE_TRANSITION,
            message=f"scope grant 目前的狀態是 {state.value}，不能{_ACTION_LABELS[action]}。",
        ) from None


def _check_decision_text(value: str, *, field: str) -> None:
    try:
        require_text(value, field=field, max_length=DECISION_NOTE_MAX_LENGTH)
    except ValueError as exc:
        raise _invalid_request(str(exc)) from None


def _invalid_request(reason: str) -> AppError:
    return AppError(
        status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
        code=ErrorCode.INVALID_REQUEST,
        message=f"{reason}。",
    )


def _summary(grant: ScopeGrant) -> JsonObject:
    """申請的摘要。完整的 path 清單不寫進 audit：grant 本身不可變，也避免超過大小上限。

    授權文件編號以 reference 記錄：欄位名稱含 authorization 會被遮罩規則整個遮掉。
    """
    scope, budget, window = grant.scope, grant.budget, grant.window
    return {
        "version": grant.version,
        "target_id": str(grant.target_id),
        "origins": [str(origin) for origin in scope.origins],
        "ips": [str(address) for address in scope.ips],
        "methods": [method.value for method in scope.methods],
        "allow_all_paths": scope.allow_all_paths,
        "path_count": len(scope.paths),
        "excluded_path_count": len(scope.excluded_paths),
        "budget": {
            "requests_per_second": budget.requests_per_second,
            "max_requests": budget.max_requests,
            "max_duration_seconds": budget.max_duration_seconds,
        },
        "valid_from": window.valid_from.isoformat(),
        "valid_until": window.valid_until.isoformat(),
        "reference": grant.authorization_reference,
    }
