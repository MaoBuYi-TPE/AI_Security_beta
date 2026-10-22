"""grant 的狀態、轉換與掃描 gate（docs/DECISIONS.md §10.4、§10.6）。

DB 只存 pending、approved、revoked；expired 由 valid_until 推導，所以不需要排程工作，
也沒有「已過期、DB 卻還是 approved」的空窗。
"""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from uuid import UUID

from secscan.grants.domain.scope import Budget, Scope, ValidityWindow, check_lab
from secscan.targets.domain import LabNetwork, Target

DECISION_NOTE_MAX_LENGTH = 500


class GrantStatus(StrEnum):
    """存在 DB 的狀態。"""

    PENDING = "pending"
    APPROVED = "approved"
    REVOKED = "revoked"


class GrantState(StrEnum):
    """對外的狀態：存的狀態，加上由 valid_until 推導出的 expired。"""

    PENDING = "pending"
    APPROVED = "approved"
    REVOKED = "revoked"
    EXPIRED = "expired"


def effective_state(status: GrantStatus, *, valid_until: datetime, now: datetime) -> GrantState:
    """revoked 優先；pending 與 approved 從 valid_until 那一刻起就是 expired。"""
    if status is GrantStatus.REVOKED:
        return GrantState.REVOKED
    if now >= valid_until:
        return GrantState.EXPIRED
    return GrantState(status.value)


class GrantAction(StrEnum):
    APPROVE = "approve"
    REVOKE = "revoke"


class InvalidTransitionError(Exception):
    """目前的狀態不允許這個動作。"""

    def __init__(self, action: GrantAction, state: GrantState) -> None:
        super().__init__(f"grant 目前是 {state.value}，不能 {action.value}")
        self.action = action
        self.state = state


# 允許的轉換：值是轉換後要存的狀態，None 代表不需要改變（重複撤銷）。表外的組合一律拒絕：
# 撤銷是安全方向，可以安全重試；核准是放行方向，必須明確。
_TRANSITIONS: Mapping[tuple[GrantAction, GrantState], GrantStatus | None] = MappingProxyType(
    {
        (GrantAction.APPROVE, GrantState.PENDING): GrantStatus.APPROVED,
        (GrantAction.REVOKE, GrantState.PENDING): GrantStatus.REVOKED,
        (GrantAction.REVOKE, GrantState.APPROVED): GrantStatus.REVOKED,
        (GrantAction.REVOKE, GrantState.REVOKED): None,
    }
)


def plan_transition(action: GrantAction, state: GrantState) -> GrantStatus | None:
    """回傳轉換後要存的狀態；None 代表不需要改變。不允許時拋出 InvalidTransitionError。"""
    try:
        return _TRANSITIONS[(action, state)]
    except KeyError:
        raise InvalidTransitionError(action, state) from None


@dataclass(frozen=True, slots=True)
class ScopeGrant:
    """已申請的 grant。範圍、預算與期限建立後不可變；狀態只能依 plan_transition() 改變。"""

    id: UUID
    target_id: UUID
    project_id: UUID
    version: int
    status: GrantStatus
    scope: Scope
    budget: Budget
    window: ValidityWindow
    authorization_reference: str
    requested_by_key_id: UUID
    created_at: datetime
    approved_by_key_id: UUID | None = None
    approved_at: datetime | None = None
    approval_note: str | None = None
    revoked_by_key_id: UUID | None = None
    revoked_at: datetime | None = None
    revocation_reason: str | None = None

    def __post_init__(self) -> None:
        approved = _decided(self.approved_by_key_id, self.approved_at, self.approval_note)
        revoked = _decided(self.revoked_by_key_id, self.revoked_at, self.revocation_reason)
        if self.status is GrantStatus.PENDING and (approved or revoked):
            raise ValueError("pending 的 grant 不可有核准或撤銷紀錄")
        if self.status is GrantStatus.APPROVED and (not approved or revoked):
            raise ValueError("approved 的 grant 必須有核准紀錄，而且沒有撤銷紀錄")
        if self.status is GrantStatus.REVOKED and not revoked:
            raise ValueError("revoked 的 grant 必須有撤銷紀錄")

    def state_at(self, now: datetime) -> GrantState:
        return effective_state(self.status, valid_until=self.window.valid_until, now=now)


def _decided(key_id: UUID | None, at: datetime | None, note: str | None) -> bool:
    """核准或撤銷的三個欄位（key、時間、說明）必須同時有值，或同時為空。"""
    present = {value is not None for value in (key_id, at, note)}
    if len(present) != 1:
        raise ValueError("核准與撤銷的欄位（key、時間、說明）必須成對")
    return present == {True}


# --- 掃描 gate ------------------------------------------------------------------------------


class UnusableReason(StrEnum):
    """grant 現在不能用來掃描的原因；service 對應成穩定的錯誤碼。"""

    WRONG_TARGET = "wrong_target"
    # target 的 origin 不在 grant 的範圍內（API 不能改 origin，只可能是直接改了 DB）。
    ORIGIN_NOT_GRANTED = "origin_not_granted"
    NOT_APPROVED = "not_approved"
    REVOKED = "revoked"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    TARGET_DISABLED = "target_disabled"


class GrantUnusableError(Exception):
    def __init__(self, reason: UnusableReason) -> None:
        super().__init__(f"grant 不能用來掃描：{reason.value}")
        self.reason = reason


_STATE_REASONS: Mapping[GrantState, UnusableReason] = MappingProxyType(
    {
        GrantState.PENDING: UnusableReason.NOT_APPROVED,
        GrantState.REVOKED: UnusableReason.REVOKED,
        GrantState.EXPIRED: UnusableReason.EXPIRED,
    }
)


def check_usable(grant: ScopeGrant, *, target: Target, lab: LabNetwork, now: datetime) -> None:
    """grant 現在能不能用來掃描 target（建立 scan、runner 啟動前都以這裡為準）。

    不行時拋出 GrantUnusableError；IP 不在目前的 LAB_CIDR 內時拋出 OutsideLabError。
    """
    if grant.target_id != target.id:
        raise GrantUnusableError(UnusableReason.WRONG_TARGET)
    if target.origin not in grant.scope.origins:
        raise GrantUnusableError(UnusableReason.ORIGIN_NOT_GRANTED)
    state = grant.state_at(now)
    if state is not GrantState.APPROVED:
        raise GrantUnusableError(_STATE_REASONS[state])
    if now < grant.window.valid_from:
        raise GrantUnusableError(UnusableReason.NOT_YET_VALID)
    if not target.enabled:
        raise GrantUnusableError(UnusableReason.TARGET_DISABLED)
    check_lab(grant.scope, lab)
