"""targets 的業務規則（docs/DECISIONS.md §10）：

- 建立與修改需要 PROJECT_WRITE（operator、admin），查詢需要 PROJECT_READ。
- 其他 project 的 target 與不存在的一樣回 404。
- base_url 只能是 origin，嚴格解析；host 是 IP 時要在目前的 LAB_CIDR 內。
- 變更寫入 audit，與業務變更在同一個 transaction。
"""

from http import HTTPStatus
from uuid import UUID

from sqlalchemy.orm import Session

from secscan.api_keys.access import authorize
from secscan.api_keys.domain import Permission, Principal
from secscan.audit.service import AuditTrail
from secscan.core.db import ConstraintViolationError
from secscan.core.errors import AppError, ErrorCode, not_found_error
from secscan.core.json_types import JsonObject
from secscan.core.pagination import Page, PageRequest
from secscan.projects.repository import ProjectRepository
from secscan.targets.domain import (
    InvalidOriginError,
    LabNetwork,
    NewTarget,
    Origin,
    OutsideLabError,
    Target,
    TargetChange,
    TargetEnvironment,
    TargetKind,
    TargetUpdate,
    parse_origin,
)
from secscan.targets.errors import invalid_target_error, outside_lab_error
from secscan.targets.repository import TargetRepository

ORIGIN_CONFLICT_CONSTRAINT = "uq_targets_project_id_canonical_origin"
# 每個 target 的待核准申請有上限，target 的數量也要有上限，申請的總量才有上界
# （docs/DECISIONS.md §10.9）。這是軟上限：同時建立時可能略為超過。
MAX_TARGETS_PER_PROJECT = 100


class TargetService:
    def __init__(self, session: Session, *, lab: LabNetwork) -> None:
        self._targets = TargetRepository(session)
        self._projects = ProjectRepository(session)
        self._audit = AuditTrail(session)
        self._lab = lab

    def create(
        self,
        principal: Principal,
        project_id: UUID,
        *,
        name: str,
        kind: TargetKind,
        base_url: str,
        request_id: str | None,
        environment: TargetEnvironment = TargetEnvironment.LAB,
    ) -> Target:
        authorize(principal, Permission.PROJECT_WRITE, project_id)
        self._require_project(project_id)
        if self._targets.count_in_project(project_id) >= MAX_TARGETS_PER_PROJECT:
            raise AppError(
                status_code=HTTPStatus.CONFLICT,
                code=ErrorCode.QUOTA_EXCEEDED,
                message=f"每個專案最多 {MAX_TARGETS_PER_PROJECT} 個 target。",
            )
        origin = lab_origin(base_url, self._lab)
        try:
            target = self._targets.create(
                NewTarget(
                    project_id=project_id,
                    name=name,
                    kind=kind,
                    origin=origin,
                    environment=environment,
                )
            )
        except ConstraintViolationError as violation:
            if violation.constraint == ORIGIN_CONFLICT_CONSTRAINT:
                raise AppError(
                    status_code=HTTPStatus.CONFLICT,
                    code=ErrorCode.TARGET_ORIGIN_CONFLICT,
                    message="這個專案已有相同 origin 的 target。",
                ) from None
            raise
        self._audit.record(
            action="target.create",
            object_type="target",
            object_id=target.id,
            actor_key_id=principal.key_id,
            project_id=project_id,
            request_id=request_id,
            changes={"name": target.name, "kind": target.kind.value, "origin": str(target.origin)},
        )
        return target

    def list_in_project(
        self, principal: Principal, project_id: UUID, page: PageRequest
    ) -> Page[Target]:
        authorize(principal, Permission.PROJECT_READ, project_id)
        self._require_project(project_id)
        return self._targets.list_by_project(project_id, page)

    def get(self, principal: Principal, target_id: UUID) -> Target:
        return self._authorized(principal, target_id, Permission.PROJECT_READ)

    def update(
        self,
        principal: Principal,
        target_id: UUID,
        changes: TargetUpdate,
        *,
        request_id: str | None,
    ) -> Target:
        """修改名稱或啟用狀態；停用後，已核准的 grant 也不能用來建立新的 scan。"""
        target = self._authorized(principal, target_id, Permission.PROJECT_WRITE)
        change = self._targets.update(target_id, changes)
        if change is None:
            raise not_found_error()
        diff = _diff(change)
        if diff:
            self._audit.record(
                action="target.update",
                object_type="target",
                object_id=target_id,
                actor_key_id=principal.key_id,
                project_id=target.project_id,
                request_id=request_id,
                changes=diff,
            )
        return change.after

    def _authorized(self, principal: Principal, target_id: UUID, permission: Permission) -> Target:
        """先取出 target 所屬的 project 再檢查權限：其他 project 與不存在的 target 一樣回 404。"""
        target = self._targets.get(target_id)
        if target is None:
            raise not_found_error()
        authorize(principal, permission, target.project_id)
        return target

    def _require_project(self, project_id: UUID) -> None:
        # 只有 admin 會走到這裡時 project 不存在（其他角色在權限檢查就回 404）。
        if self._projects.get(project_id) is None:
            raise not_found_error()


def lab_origin(base_url: str, lab: LabNetwork) -> Origin:
    """嚴格解析 origin；host 是 IP 時再檢查目前的 LAB_CIDR。"""
    try:
        origin = parse_origin(base_url)
        lab.check_origin(origin)
    except InvalidOriginError as exc:
        raise invalid_target_error(exc) from None
    except OutsideLabError as exc:
        raise outside_lab_error(exc) from None
    return origin


def _diff(change: TargetChange) -> JsonObject:
    """只記有變動的欄位，含前後值。"""
    before, after = change.before, change.after
    diff: JsonObject = {}
    if before.name != after.name:
        diff["name"] = {"from": before.name, "to": after.name}
    if before.enabled != after.enabled:
        diff["enabled"] = {"from": before.enabled, "to": after.enabled}
    return diff
