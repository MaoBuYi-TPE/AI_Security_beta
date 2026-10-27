"""run 的狀態轉換與 scan 狀態的彙總（docs/DECISIONS.md §13.4、ARCHITECTURE.md §8）。

scan 的狀態不獨立轉換：每次 run 轉換之後，以 aggregate() 由所有 run 的狀態與「是否要求過取消」
重新算出，和 run 的轉換在同一個 transaction 寫入，所以兩者不會不一致。
"""

from collections.abc import Collection, Iterable, Mapping
from enum import StrEnum
from types import MappingProxyType

from secscan.grants.domain.lifecycle import UnusableReason


class RunStatus(StrEnum):
    QUEUED = "queued"
    PREPARING = "preparing"
    RUNNING = "running"
    COLLECTING = "collecting"
    COLLECTED = "collected"
    NORMALIZING = "normalizing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLING = "cancelling"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


class ScanStatus(StrEnum):
    QUEUED = "queued"
    PREPARING = "preparing"
    RUNNING = "running"
    COLLECTING = "collecting"
    NORMALIZING = "normalizing"
    CANCELLING = "cancelling"
    COMPLETED = "completed"
    PARTIALLY_COMPLETED = "partially_completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


TERMINAL_RUN_STATUSES = frozenset(
    {
        RunStatus.SUCCEEDED,
        RunStatus.FAILED,
        RunStatus.TIMED_OUT,
        RunStatus.CANCELLED,
        RunStatus.INTERRUPTED,
    }
)
# 持有 lease 的狀態：runner 階段（preparing、running、collecting、cancelling）與 worker 的解析。
LEASED_RUN_STATUSES = frozenset(
    {
        RunStatus.PREPARING,
        RunStatus.RUNNING,
        RunStatus.COLLECTING,
        RunStatus.CANCELLING,
        RunStatus.NORMALIZING,
    }
)
RUNNER_STAGE_RUN_STATUSES = frozenset(
    {RunStatus.PREPARING, RunStatus.RUNNING, RunStatus.COLLECTING, RunStatus.CANCELLING}
)
# 不再送出流量：後面的引擎可以開始（失敗的引擎不擋住後面的引擎）。interrupted 也算：只有確定
# 已停止才標成 interrupted（T09 的 fake 不發流量；T13 的對帳要先封鎖 guard、確認容器已終止）。
TRAFFIC_STOPPED_RUN_STATUSES = TERMINAL_RUN_STATUSES | {RunStatus.COLLECTED, RunStatus.NORMALIZING}
ERROR_REQUIRED_RUN_STATUSES = frozenset(
    {RunStatus.FAILED, RunStatus.TIMED_OUT, RunStatus.INTERRUPTED}
)
TERMINAL_SCAN_STATUSES = frozenset(
    {
        ScanStatus.COMPLETED,
        ScanStatus.PARTIALLY_COMPLETED,
        ScanStatus.FAILED,
        ScanStatus.TIMED_OUT,
        ScanStatus.CANCELLED,
        ScanStatus.INTERRUPTED,
    }
)
ACTIVE_SCAN_STATUSES = frozenset(ScanStatus) - TERMINAL_SCAN_STATUSES


class RunErrorCode(StrEnum):
    """run 失敗的原因（穩定的對外代碼）。DB 只檢查格式，清單在這裡。"""

    SCOPE_REVOKED = "SCOPE_REVOKED"
    SCOPE_EXPIRED = "SCOPE_EXPIRED"
    SCOPE_NOT_APPROVED = "SCOPE_NOT_APPROVED"
    SCOPE_NOT_YET_VALID = "SCOPE_NOT_YET_VALID"
    TARGET_DISABLED = "TARGET_DISABLED"
    SCOPE_OUTSIDE_LAB = "SCOPE_OUTSIDE_LAB"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    AUTH_PROFILE_SUPERSEDED = "AUTH_PROFILE_SUPERSEDED"
    # 建立 scan 的平台 key 已被撤銷（外洩時排進佇列的 scan 也不會開始）。
    CREATOR_KEY_REVOKED = "CREATOR_KEY_REVOKED"
    ENGINE_FAILED = "ENGINE_FAILED"
    LEASE_EXPIRED = "LEASE_EXPIRED"


# runner 啟動前重新判斷 gate（§10.6）不通過的原因。grant 不屬於這個 target、origin 不在範圍內，
# 都只有直接改了 DB 才會發生。
GATE_ERROR_CODES: Mapping[UnusableReason, RunErrorCode] = MappingProxyType(
    {
        UnusableReason.WRONG_TARGET: RunErrorCode.SCOPE_MISMATCH,
        UnusableReason.ORIGIN_NOT_GRANTED: RunErrorCode.SCOPE_MISMATCH,
        UnusableReason.NOT_APPROVED: RunErrorCode.SCOPE_NOT_APPROVED,
        UnusableReason.REVOKED: RunErrorCode.SCOPE_REVOKED,
        UnusableReason.EXPIRED: RunErrorCode.SCOPE_EXPIRED,
        UnusableReason.NOT_YET_VALID: RunErrorCode.SCOPE_NOT_YET_VALID,
        UnusableReason.TARGET_DISABLED: RunErrorCode.TARGET_DISABLED,
    }
)

# 允許的轉換；表外的組合一律拒絕，終止狀態不能再轉換。
_RUN_TRANSITIONS: Mapping[RunStatus, frozenset[RunStatus]] = MappingProxyType(
    {
        RunStatus.QUEUED: frozenset({RunStatus.PREPARING, RunStatus.CANCELLED}),
        RunStatus.PREPARING: frozenset(
            {RunStatus.RUNNING, RunStatus.FAILED, RunStatus.CANCELLING, RunStatus.INTERRUPTED}
        ),
        RunStatus.RUNNING: frozenset(
            {
                RunStatus.COLLECTING,
                RunStatus.FAILED,
                RunStatus.TIMED_OUT,
                RunStatus.CANCELLING,
                RunStatus.INTERRUPTED,
            }
        ),
        RunStatus.COLLECTING: frozenset(
            {RunStatus.COLLECTED, RunStatus.FAILED, RunStatus.CANCELLING, RunStatus.INTERRUPTED}
        ),
        RunStatus.CANCELLING: frozenset({RunStatus.CANCELLED, RunStatus.INTERRUPTED}),
        RunStatus.COLLECTED: frozenset({RunStatus.NORMALIZING}),
        # lease 過期時退回 collected：解析不可變的 artifact 可以安全重試（CLAUDE.md §8）。
        RunStatus.NORMALIZING: frozenset(
            {RunStatus.SUCCEEDED, RunStatus.FAILED, RunStatus.COLLECTED}
        ),
    }
)


class InvalidRunTransitionError(Exception):
    def __init__(self, current: RunStatus, to: RunStatus) -> None:
        super().__init__(f"run 不能從 {current.value} 轉換到 {to.value}")
        self.current = current
        self.to = to


def plan_run_transition(
    current: RunStatus, to: RunStatus, *, error_code: RunErrorCode | None
) -> None:
    """檢查轉換是否允許；failed、timed_out、interrupted 必須有錯誤碼，其他狀態不能有。"""
    if to not in _RUN_TRANSITIONS.get(current, frozenset()):
        raise InvalidRunTransitionError(current, to)
    if (to in ERROR_REQUIRED_RUN_STATUSES) != (error_code is not None):
        raise ValueError(
            f"{to.value} {'必須' if to in ERROR_REQUIRED_RUN_STATUSES else '不可'}有錯誤碼"
        )


def aggregate(runs: Iterable[RunStatus], *, cancel_requested: bool) -> ScanStatus:
    """由所有 run 的狀態算出 scan 的狀態；和 run 的順序無關（docs/DECISIONS.md §13.4）。"""
    statuses = tuple(runs)
    if not statuses:
        raise ValueError("scan 至少要有一個 run")
    present = frozenset(statuses)
    if present <= TERMINAL_RUN_STATUSES:
        return _finished(present, cancel_requested=cancel_requested)
    return _in_progress(present, cancel_requested=cancel_requested)


def _finished(present: Collection[RunStatus], *, cancel_requested: bool) -> ScanStatus:
    # interrupted 排在最前面：它無法證明工作已正常停止。要求過取消、但 runner 沒有確認就遺失時，
    # 也不能說是 cancelled（確認之後才是 cancelled，CLAUDE.md §8；審查發現）。
    if RunStatus.INTERRUPTED in present:
        return ScanStatus.INTERRUPTED
    if cancel_requested:
        return ScanStatus.CANCELLED
    if RunStatus.TIMED_OUT in present:
        return ScanStatus.TIMED_OUT
    if present == {RunStatus.SUCCEEDED}:
        return ScanStatus.COMPLETED
    if RunStatus.SUCCEEDED in present:
        return ScanStatus.PARTIALLY_COMPLETED
    return ScanStatus.FAILED


def _in_progress(present: frozenset[RunStatus], *, cancel_requested: bool) -> ScanStatus:
    # 只有要求過取消才是 cancelling（和 DB 的 ck_scans_cancel_matches_status 一致）；
    # run 轉到 cancelling 也要求 scan 已被要求取消（scans.progress）。
    if cancel_requested:
        return ScanStatus.CANCELLING
    if present == {RunStatus.QUEUED}:
        return ScanStatus.QUEUED
    if present <= {RunStatus.QUEUED, RunStatus.PREPARING}:
        return ScanStatus.PREPARING
    if present & {RunStatus.PREPARING, RunStatus.RUNNING}:
        return ScanStatus.RUNNING
    if present & {RunStatus.COLLECTING, RunStatus.COLLECTED}:
        return ScanStatus.COLLECTING
    if RunStatus.NORMALIZING in present:
        return ScanStatus.NORMALIZING
    # 有引擎已經結束、其餘還在排隊。
    return ScanStatus.RUNNING
