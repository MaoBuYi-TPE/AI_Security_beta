"""scan 的業務規則（docs/DECISIONS.md §13）：建立、查詢、事件與取消。

建立（PROJECT_WRITE）的檢查順序見 §13.3：target 的權限 → Idempotency-Key → 引擎與 profile →
忙碌與上限（不取鎖）→ gate（target FOR NO KEY UPDATE、grant FOR SHARE，之後才取時間）→ 規格 →
auth profile（FOR SHARE）→ 預算 → 忙碌與上限（持有鎖時再查一次）→ 寫入。scan、run、凍結的
operation、事件與 audit 在同一個 transaction。
其他 project 的資源一律和不存在的一樣回 404。
"""

from collections.abc import Callable
from datetime import datetime, timedelta
from http import HTTPStatus
from uuid import UUID

from sqlalchemy.orm import Session

from secscan.api_keys.access import authorize
from secscan.api_keys.domain import Permission, Principal
from secscan.audit.service import AuditTrail
from secscan.auth_profiles.repository import AuthProfileRepository
from secscan.core.db import ConstraintViolationError
from secscan.core.errors import AppError, ErrorCode, not_found_error
from secscan.core.json_types import JsonObject
from secscan.core.pagination import Page, PageRequest
from secscan.grants.domain.matching import ScopeRules
from secscan.grants.domain.scope import Budget
from secscan.grants.service import ScopeGrantService, UsableGrant
from secscan.scans.domain.catalog import (
    IncompatibleProfileError,
    InvalidScanRequestError,
    PlannedRun,
    UnsupportedEngineError,
    check_operations,
    check_profile,
    plan_runs,
)
from secscan.scans.domain.lifecycle import RunStatus
from secscan.scans.domain.model import (
    AuthBinding,
    EventType,
    FrozenOperation,
    NewScan,
    Scan,
    ScanEvent,
    created_payload,
)
from secscan.scans.domain.request import ScanRequest, fingerprint, resolve_budget
from secscan.scans.progress import ScanProgress
from secscan.scans.repository import ScanFilters, ScanRepository
from secscan.specs.repository import ApiSpecRepository
from secscan.targets.domain import LabNetwork, Target
from secscan.targets.repository import TargetRepository

# scan 不能刪除，每個最多帶 1,000 列 operation：每個 target 在 24 小時內的數量有上限，
# 一把外洩的 operator key 才不能無限寫入（docs/DECISIONS.md §13.1）。
MAX_SCANS_PER_TARGET_PER_DAY = 50
QUOTA_WINDOW = timedelta(hours=24)
KEY_CONSTRAINT = "uq_scans_project_id_idempotency_key"
ACTIVE_TARGET_CONSTRAINT = "uq_scans_active_target"


class ScanService:
    def __init__(self, session: Session, *, lab: LabNetwork) -> None:
        self._scans = ScanRepository(session)
        self._progress = ScanProgress(session)
        self._targets = TargetRepository(session)
        self._grants = ScopeGrantService(session, lab=lab)
        self._specs = ApiSpecRepository(session)
        self._profiles = AuthProfileRepository(session)
        self._audit = AuditTrail(session)

    def create(
        self,
        principal: Principal,
        request: ScanRequest,
        *,
        idempotency_key: str,
        clock: Callable[[], datetime],
        request_id: str | None,
    ) -> Scan:
        """建立 queued 的 scan；同一個 key、同樣的內容回原本的 scan（不寫入任何東西）。"""
        target = self._target(principal, request.target_id, Permission.PROJECT_WRITE)
        digest = fingerprint(request)
        replayed = self._replay(target.project_id, idempotency_key, digest)
        if replayed is not None:
            return replayed
        runs = _planned_runs(request, target)
        # 先在取得任何鎖之前查一次忙碌與上限：註定失敗的請求不和撤銷、停用搶鎖（安全審查發現）。
        # 取得鎖之後再查一次才是準的（同時建立時另以唯一索引為準）。
        self._check_capacity(target.id, now=clock())
        usable = self._grants.require_usable(
            principal, target_id=target.id, grant_id=request.scope_grant_id, clock=clock
        )
        # 等 target 的鎖時，同一個 key 的另一個請求可能已經 commit：先重查 key，才不會被當成忙碌。
        replayed = self._replay(target.project_id, idempotency_key, digest)
        if replayed is not None:
            return replayed
        rules = ScopeRules.of(usable.grant.scope)
        operations = self._operations(principal, request, usable.target, rules)
        auth = self._auth(principal, request, usable.target, rules)
        budget = _budget(request, usable)
        self._check_capacity(target.id, now=usable.checked_at)
        new_scan = NewScan(
            project_id=target.project_id,
            target_id=target.id,
            target_origin=usable.target.origin,
            scope_grant_id=usable.grant.id,
            api_spec_id=request.api_spec_id,
            auth=auth,
            profile=request.profile,
            budget=budget,
            runs=runs,
            operations=operations,
            idempotency_key=idempotency_key,
            request_sha256=digest,
            created_by_key_id=principal.key_id,
        )
        try:
            scan_id = self._scans.create(new_scan)
        except ConstraintViolationError as violation:
            return self._after_conflict(violation, new_scan)
        engines = tuple(run.engine for run in runs)
        self._scans.append_event(
            scan_id,
            EventType.SCAN_CREATED,
            created_payload(profile=request.profile, engines=engines),
        )
        scan = self._existing(scan_id)
        self._audit.record(
            action="scan.create",
            object_type="scan",
            object_id=scan.id,
            actor_key_id=principal.key_id,
            project_id=scan.project_id,
            request_id=request_id,
            changes=_created(scan, operations),
        )
        return scan

    def get(self, principal: Principal, scan_id: UUID) -> Scan:
        return self._scan(principal, scan_id, Permission.PROJECT_READ)

    def list(self, principal: Principal, filters: ScanFilters, page: PageRequest) -> Page[Scan]:
        """呼叫者看得到的 project 中的 scan：其他 project 的 target 當成篩選條件時就是沒有結果。"""
        return self._scans.list(principal.project_scope, filters, page)

    def events(
        self, principal: Principal, scan_id: UUID, *, after_sequence: int, limit: int
    ) -> tuple[ScanEvent, ...]:
        """sequence 大於 after_sequence 的事件，依 sequence 遞增，最多 limit 個。"""
        self._scan(principal, scan_id, Permission.PROJECT_READ)
        return self._scans.events(scan_id, after_sequence=after_sequence, limit=limit)

    def cancel(self, principal: Principal, scan_id: UUID, *, request_id: str | None) -> Scan:
        """要求取消（docs/DECISIONS.md §13.6）：排隊中的 run 直接取消；runner 與 worker 階段的
        run 由它們確認。已終止或已要求過取消時不改變任何東西，也不重記事件與 audit。"""
        self._scan(principal, scan_id, Permission.PROJECT_WRITE)
        locked = self._progress.lock_scan(scan_id)
        if locked is None:
            raise not_found_error()
        if locked.is_terminal or locked.cancel_requested:
            return self._existing(scan_id)
        requested = self._progress.request_cancel(locked)
        for run in self._progress.runs(scan_id):
            if run.status is RunStatus.QUEUED:
                self._progress.move(requested, run, RunStatus.CANCELLED)
        status = self._progress.settle(requested)
        self._audit.record(
            action="scan.cancel",
            object_type="scan",
            object_id=scan_id,
            actor_key_id=principal.key_id,
            project_id=locked.project_id,
            request_id=request_id,
            changes={"previous_status": locked.status.value, "status": status.value},
        )
        return self._existing(scan_id)

    def _replay(self, project_id: UUID, idempotency_key: str, digest: bytes) -> Scan | None:
        """這個 key 已建立過 scan：內容相同回它目前的狀態，不同回 409。"""
        keyed = self._scans.find_by_key(project_id, idempotency_key)
        if keyed is None:
            return None
        if keyed.request_sha256 != digest:
            raise AppError(
                status_code=HTTPStatus.CONFLICT,
                code=ErrorCode.IDEMPOTENCY_CONFLICT,
                message="這個 Idempotency-Key 已用於內容不同的請求；新的請求請使用新的 key。",
            )
        return self._existing(keyed.scan_id)

    def _after_conflict(self, violation: ConstraintViolationError, new_scan: NewScan) -> Scan:
        """寫入時撞到唯一索引：同時建立的另一個請求先 commit 了。

        先重查 key（同一個 key：重送或 409），再判斷是不是這個 target 已有進行中的 scan。
        """
        if violation.constraint not in {KEY_CONSTRAINT, ACTIVE_TARGET_CONSTRAINT}:
            raise violation
        replayed = self._replay(
            new_scan.project_id, new_scan.idempotency_key, new_scan.request_sha256
        )
        if replayed is not None:
            return replayed
        if violation.constraint == ACTIVE_TARGET_CONSTRAINT:
            raise _target_busy()
        raise violation

    def _operations(
        self, principal: Principal, request: ScanRequest, target: Target, rules: ScopeRules
    ) -> tuple[FrozenOperation, ...]:
        """以 grant 的範圍判斷規格中每個 operation，凍結成 coverage 的分母。"""
        if request.api_spec_id is None:
            return ()
        spec = self._specs.get(request.api_spec_id)
        if spec is None:
            raise not_found_error()
        authorize(principal, Permission.PROJECT_WRITE, spec.project_id)
        if spec.target_id != target.id:
            raise _invalid_request("api spec 不屬於這個 target。")
        operations = tuple(
            FrozenOperation(
                ordinal=ordinal,
                method=operation.method,
                path=operation.path,
                operation_id=operation.operation_id,
                ineligible_reason=rules.classify(method=operation.method, path=operation.path),
            )
            for ordinal, operation in enumerate(self._specs.all_operations(spec.id))
        )
        eligible = sum(1 for operation in operations if operation.ineligible_reason is None)
        try:
            check_operations(request.profile, eligible_operations=eligible)
        except IncompatibleProfileError as exc:
            raise _incompatible(exc) from None
        return operations

    def _auth(
        self, principal: Principal, request: ScanRequest, target: Target, rules: ScopeRules
    ) -> AuthBinding | None:
        """綁定 profile 目前的版本；沒有 profile 是匿名。

        以 FOR SHARE 鎖住 profile：PATCH 會等這個 transaction，不會綁到即將被清除的版本。
        """
        if request.auth_profile_id is None:
            return None
        profile = self._profiles.get(request.auth_profile_id)
        if profile is None:
            raise not_found_error()
        authorize(principal, Permission.PROJECT_WRITE, profile.project_id)
        if profile.target_id != target.id:
            raise _invalid_request("auth profile 不屬於這個 target。")
        locked = self._profiles.lock(profile.id, shared=True)
        if locked is None:
            raise not_found_error()
        current = locked.current
        if not current.secret_configured:
            # 只有直接改了 DB 才會發生（trigger 允許清除）：沒有 secret 就不能認證。
            raise AppError(
                status_code=HTTPStatus.CONFLICT,
                code=ErrorCode.INVALID_STATE_TRANSITION,
                message="auth profile 目前的版本沒有 secret：請先以 PATCH 設定新的 secret。",
            )
        preflight = current.definition.preflight
        reason = rules.classify(method=preflight.method, path=preflight.path)
        if reason is not None:
            # 不附 path：訊息只說明原因（path 可能含帳號名稱）。
            raise _invalid_request(
                f"auth profile 的 preflight 不在 scope grant 的範圍內（{reason.value}）。"
            )
        return AuthBinding(
            profile_id=locked.id, version=current.version, role_label=locked.role_label
        )

    def _check_capacity(self, target_id: UUID, *, now: datetime) -> None:
        if self._scans.has_active(target_id):
            raise _target_busy()
        if self._scans.count_created_since(target_id, now - QUOTA_WINDOW) >= (
            MAX_SCANS_PER_TARGET_PER_DAY
        ):
            raise AppError(
                status_code=HTTPStatus.CONFLICT,
                code=ErrorCode.QUOTA_EXCEEDED,
                message=(
                    f"每個 target 在 24 小時內最多建立 {MAX_SCANS_PER_TARGET_PER_DAY} 個 scan。"
                ),
            )

    def _target(self, principal: Principal, target_id: UUID, permission: Permission) -> Target:
        """先取出所屬的 project 再檢查權限：其他 project 與不存在的一樣回 404。"""
        target = self._targets.get(target_id)
        if target is None:
            raise not_found_error()
        authorize(principal, permission, target.project_id)
        return target

    def _scan(self, principal: Principal, scan_id: UUID, permission: Permission) -> Scan:
        scan = self._scans.get(scan_id)
        if scan is None:
            raise not_found_error()
        authorize(principal, permission, scan.project_id)
        return scan

    def _existing(self, scan_id: UUID) -> Scan:
        # 已在同一個 transaction 寫入，或已 commit：一定讀得到。
        scan = self._scans.get(scan_id)
        if scan is None:
            raise RuntimeError("剛建立的 scan 讀不到")
        return scan


def _planned_runs(request: ScanRequest, target: Target) -> tuple[PlannedRun, ...]:
    """引擎與 profile 的規則：只看請求本身與 target 的種類，在取得任何鎖之前判斷。"""
    try:
        runs = plan_runs(request.engines, authenticated=request.auth_profile_id is not None)
        check_profile(
            request.profile, target_kind=target.kind, has_spec=request.api_spec_id is not None
        )
    except UnsupportedEngineError as exc:
        raise AppError(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            code=ErrorCode.ENGINE_UNSUPPORTED,
            message=f"{exc}。",
        ) from None
    except IncompatibleProfileError as exc:
        raise _incompatible(exc) from None
    except InvalidScanRequestError as exc:
        raise _invalid_request(f"{exc}。") from None
    return runs


def _budget(request: ScanRequest, usable: UsableGrant) -> Budget:
    try:
        return resolve_budget(request.budget, grant_budget=usable.grant.budget)
    except InvalidScanRequestError as exc:
        raise _invalid_request(f"{exc}。") from None


def _target_busy() -> AppError:
    return AppError(
        status_code=HTTPStatus.CONFLICT,
        code=ErrorCode.TARGET_BUSY,
        message="這個 target 已有進行中的 scan；請等它結束或取消之後再建立。",
    )


def _incompatible(exc: IncompatibleProfileError) -> AppError:
    return AppError(
        status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
        code=ErrorCode.PROFILE_INCOMPATIBLE,
        message=f"{exc}。",
    )


def _invalid_request(message: str) -> AppError:
    return AppError(
        status_code=HTTPStatus.UNPROCESSABLE_ENTITY, code=ErrorCode.INVALID_REQUEST, message=message
    )


def _created(scan: Scan, operations: tuple[FrozenOperation, ...]) -> JsonObject:
    """快照的摘要。欄位名稱避開遮罩規則（auth、key 這類片段整個會被遮掉）：
    auth profile 記為 identity；Idempotency-Key 不記。"""
    spec = scan.api_spec
    auth = scan.auth
    return {
        "target_id": str(scan.target_id),
        "scope_grant": {"id": str(scan.scope_grant.id), "version": scan.scope_grant.version},
        "api_spec": {"id": str(spec.id), "version": spec.version} if spec is not None else None,
        "identity": (
            {
                "profile_id": str(auth.profile_id),
                "version": auth.version,
                "role_label": auth.role_label,
            }
            if auth is not None
            else None
        ),
        "scan_profile": scan.profile.value,
        "engines": [run.engine.value for run in scan.runs],
        "budget": {
            "requests_per_second": scan.budget.requests_per_second,
            "max_requests": scan.budget.max_requests,
            "max_duration_seconds": scan.budget.max_duration_seconds,
        },
        "eligible_operations": (
            sum(1 for operation in operations if operation.ineligible_reason is None)
            if spec is not None
            else None
        ),
    }
