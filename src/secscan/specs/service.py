"""API 規格的業務規則（docs/DECISIONS.md §11）：

- 上傳：PROJECT_WRITE。先檢查權限再解析；解析完才以 FOR UPDATE 鎖住 target、取下一個 version，
  不拖長鎖住 target 的時間。每個 target 的版本數有上限。
- 查詢與 inventory：PROJECT_READ。帶 grant 預覽時，也要讀得到那個 grant，而且它必須屬於
  同一個 target。
- 其他 project 的 target、規格與 grant 一律和不存在的一樣回 404；上傳寫入 audit。
"""

from http import HTTPStatus
from uuid import UUID

from sqlalchemy.orm import Session

from secscan.api_keys.access import authorize
from secscan.api_keys.domain import Permission, Principal
from secscan.audit.service import AuditTrail
from secscan.core.errors import AppError, ErrorCode, not_found_error
from secscan.core.json_types import JsonObject
from secscan.core.pagination import Page, PageRequest
from secscan.grants.domain.matching import ScopeRules
from secscan.grants.repository import ScopeGrantRepository
from secscan.specs.domain.documents import InvalidSpecError
from secscan.specs.domain.model import (
    ApiSpec,
    InventoryEntry,
    NewApiSpec,
    NormalizedSpec,
    SpecUpload,
)
from secscan.specs.domain.openapi import normalize_spec
from secscan.specs.errors import invalid_spec_error
from secscan.specs.repository import ApiSpecRepository
from secscan.targets.domain import Origin, Target
from secscan.targets.repository import TargetRepository

# 規格不能刪除，每份最大 2 MiB：版本數要有上限，一把外洩的 operator key 才不能無限寫入
# （docs/DECISIONS.md §11.5）。
MAX_SPECS_PER_TARGET = 20


class ApiSpecService:
    def __init__(self, session: Session) -> None:
        self._specs = ApiSpecRepository(session)
        self._targets = TargetRepository(session)
        self._grants = ScopeGrantRepository(session)
        self._audit = AuditTrail(session)

    def upload(
        self, principal: Principal, target_id: UUID, upload: SpecUpload, *, request_id: str | None
    ) -> ApiSpec:
        """檢查並保存新版本的規格；不合規則時回 413 或 422，什麼都不寫入。"""
        target = self._target(principal, target_id, Permission.PROJECT_WRITE)
        normalized = _normalized(upload, target.origin)
        # FOR UPDATE：同時上傳時，version 依 commit 的先後遞增，配額也是精確的。
        if self._targets.lock(target_id) is None:
            raise not_found_error()
        if self._specs.count_for_target(target_id) >= MAX_SPECS_PER_TARGET:
            raise AppError(
                status_code=HTTPStatus.CONFLICT,
                code=ErrorCode.QUOTA_EXCEEDED,
                message=f"每個 target 最多 {MAX_SPECS_PER_TARGET} 個規格版本。",
            )
        spec = self._specs.create(
            NewApiSpec(target_id=target_id, spec=normalized, uploaded_by_key_id=principal.key_id),
            version=self._specs.next_version(target_id),
        )
        self._audit.record(
            action="api_spec.create",
            object_type="api_spec",
            object_id=spec.id,
            actor_key_id=principal.key_id,
            project_id=spec.project_id,
            request_id=request_id,
            changes=_summary(spec),
        )
        return spec

    def list_for_target(
        self, principal: Principal, target_id: UUID, page: PageRequest
    ) -> Page[ApiSpec]:
        self._target(principal, target_id, Permission.PROJECT_READ)
        return self._specs.list_by_target(target_id, page)

    def get(self, principal: Principal, spec_id: UUID) -> ApiSpec:
        return self._spec(principal, spec_id)

    def operations(
        self, principal: Principal, spec_id: UUID, page: PageRequest, *, grant_id: UUID | None
    ) -> Page[InventoryEntry]:
        """inventory；帶 grant 時以它的範圍判斷每個 operation（grant 的任何狀態都可以預覽）。"""
        spec = self._spec(principal, spec_id)
        rules = None if grant_id is None else self._preview_rules(principal, spec, grant_id)
        operations = self._specs.list_operations(spec_id, page)
        entries = []
        for operation in operations.items:
            if rules is None:
                entries.append(InventoryEntry(operation))
                continue
            reason = rules.classify(method=operation.method, path=operation.path)
            entries.append(InventoryEntry(operation, eligible=reason is None, reason=reason))
        return Page(items=tuple(entries), total=operations.total, request=page)

    def _preview_rules(self, principal: Principal, spec: ApiSpec, grant_id: UUID) -> ScopeRules:
        grant = self._grants.get(grant_id)
        if grant is None:
            raise not_found_error()
        authorize(principal, Permission.PROJECT_READ, grant.project_id)
        if grant.target_id != spec.target_id:
            raise AppError(
                status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
                code=ErrorCode.INVALID_REQUEST,
                message="scope grant 不屬於這份規格的 target。",
            )
        return ScopeRules.of(grant.scope)

    def _target(self, principal: Principal, target_id: UUID, permission: Permission) -> Target:
        """先取出所屬的 project 再檢查權限：其他 project 與不存在的一樣回 404。"""
        target = self._targets.get(target_id)
        if target is None:
            raise not_found_error()
        authorize(principal, permission, target.project_id)
        return target

    def _spec(self, principal: Principal, spec_id: UUID) -> ApiSpec:
        spec = self._specs.get(spec_id)
        if spec is None:
            raise not_found_error()
        authorize(principal, Permission.PROJECT_READ, spec.project_id)
        return spec


def _normalized(upload: SpecUpload, origin: Origin) -> NormalizedSpec:
    try:
        return normalize_spec(upload.content, upload.spec_format, origin=origin)
    except InvalidSpecError as exc:
        raise invalid_spec_error(exc) from None


def _summary(spec: ApiSpec) -> JsonObject:
    """上傳的摘要；文件本身不寫進 audit（規格不可變，以 hash 對應）。"""
    return {
        "version": spec.version,
        "target_id": str(spec.target_id),
        "format": spec.source_format.value,
        "size_bytes": spec.source_size,
        "source_sha256": spec.source_sha256.hex(),
        "document_sha256": spec.document_sha256.hex(),
        "operation_count": spec.operation_count,
        "base_path": spec.base_path,
    }
