"""api_specs 與 api_spec_operations 的資料存取；回傳 frozen domain model。

誰能看到哪些規格由 service 決定。

規格所屬的 project 與 origin 由 target 取得（join targets），不重複存放。正規化文件只在新增時寫入；
一般的查詢不讀它（deferred）。
"""

from uuid import UUID

from sqlalchemy import Row, Select, func, insert, select
from sqlalchemy.orm import Session

from secscan.core.db import flush_or_raise
from secscan.core.pagination import Page, PageRequest
from secscan.specs.domain.documents import SpecFormat
from secscan.specs.domain.model import ApiSpec, NewApiSpec, SpecOperation
from secscan.specs.models import ApiSpecModel, ApiSpecOperationModel
from secscan.targets.domain import parse_origin
from secscan.targets.models import TargetModel


class ApiSpecRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def next_version(self, target_id: UUID) -> int:
        """target 的下一個 version。呼叫端必須先以 FOR UPDATE 鎖住 target，否則同時上傳會撞號。"""
        current = self._session.scalar(
            select(func.max(ApiSpecModel.version)).where(ApiSpecModel.target_id == target_id)
        )
        return (current or 0) + 1

    def count_for_target(self, target_id: UUID) -> int:
        return (
            self._session.scalar(
                select(func.count())
                .select_from(ApiSpecModel)
                .where(ApiSpecModel.target_id == target_id)
            )
            or 0
        )

    def create(self, new_spec: NewApiSpec, *, version: int) -> ApiSpec:
        """新增規格與它的 inventory；version 重複時拋出 ConstraintViolationError。"""
        spec = new_spec.spec
        model = ApiSpecModel(
            target_id=new_spec.target_id,
            version=version,
            source_format=spec.source_format.value,
            source_size_bytes=spec.source_size,
            source_sha256=spec.source_sha256,
            document=spec.document,
            document_sha256=spec.document_sha256,
            openapi_version=spec.openapi_version,
            base_path=spec.base_path,
            operation_count=len(spec.operations),
            uploaded_by_key_id=new_spec.uploaded_by_key_id,
        )
        self._session.add(model)
        flush_or_raise(self._session)
        if spec.operations:
            rows = [
                {
                    "spec_id": model.id,
                    "ordinal": ordinal,
                    "method": operation.method,
                    "path": operation.path,
                    "operation_id": operation.operation_id,
                }
                for ordinal, operation in enumerate(spec.operations)
            ]
            self._session.execute(insert(ApiSpecOperationModel), rows)
            flush_or_raise(self._session)
        # FK 保證 target 存在（不存在時 flush 就已失敗），one() 不會找不到。
        project_id, canonical_origin = self._session.execute(
            select(TargetModel.project_id, TargetModel.canonical_origin).where(
                TargetModel.id == new_spec.target_id
            )
        ).one()
        return _to_domain(model, project_id, canonical_origin)

    def get(self, spec_id: UUID) -> ApiSpec | None:
        row = self._session.execute(_with_target().where(ApiSpecModel.id == spec_id)).first()
        return _from_row(row) if row is not None else None

    def list_by_target(self, target_id: UUID, page: PageRequest) -> Page[ApiSpec]:
        """新版本在前。"""
        total = self.count_for_target(target_id)
        rows = self._session.execute(
            _with_target()
            .where(ApiSpecModel.target_id == target_id)
            .order_by(ApiSpecModel.version.desc())
            .offset(page.offset)
            .limit(page.limit)
        )
        return Page(items=tuple(_from_row(row) for row in rows), total=total, request=page)

    def stored_document(self, spec_id: UUID) -> tuple[bytes, str] | None:
        """正規化文件與 base path（只有 runner 經由佇列讀取，交給工具；docs/DECISIONS.md §18.6）。

        document_sha256 由 DB 的 CHECK 保證和內容一致，文件建立之後不能修改（trigger）。
        """
        row = self._session.execute(
            select(ApiSpecModel.document, ApiSpecModel.base_path).where(ApiSpecModel.id == spec_id)
        ).first()
        return (row.document, row.base_path) if row is not None else None

    def all_operations(self, spec_id: UUID) -> tuple[SpecOperation, ...]:
        """整個 inventory（最多 MAX_OPERATIONS 個），依 inventory 的順序；建立 scan 時凍結用。"""
        models = self._session.scalars(
            select(ApiSpecOperationModel)
            .where(ApiSpecOperationModel.spec_id == spec_id)
            .order_by(ApiSpecOperationModel.ordinal)
        )
        return tuple(
            SpecOperation(method=model.method, path=model.path, operation_id=model.operation_id)
            for model in models
        )

    def list_operations(self, spec_id: UUID, page: PageRequest) -> Page[SpecOperation]:
        """inventory 的順序（依 path、method 排序後的位置）。"""
        of_spec = ApiSpecOperationModel.spec_id == spec_id
        total = (
            self._session.scalar(
                select(func.count()).select_from(ApiSpecOperationModel).where(of_spec)
            )
            or 0
        )
        models = self._session.scalars(
            select(ApiSpecOperationModel)
            .where(of_spec)
            .order_by(ApiSpecOperationModel.ordinal)
            .offset(page.offset)
            .limit(page.limit)
        )
        items = tuple(
            SpecOperation(method=model.method, path=model.path, operation_id=model.operation_id)
            for model in models
        )
        return Page(items=items, total=total, request=page)


def _with_target() -> Select[ApiSpecModel, UUID, str]:
    return select(ApiSpecModel, TargetModel.project_id, TargetModel.canonical_origin).join(
        TargetModel, TargetModel.id == ApiSpecModel.target_id
    )


def _from_row(row: Row[ApiSpecModel, UUID, str]) -> ApiSpec:
    model, project_id, canonical_origin = row
    return _to_domain(model, project_id, canonical_origin)


def _to_domain(model: ApiSpecModel, project_id: UUID, canonical_origin: str) -> ApiSpec:
    # 讀回的值再經過 domain 的規則：DB 中不合規則的資料會讓讀取失敗（fail closed）。
    return ApiSpec(
        id=model.id,
        target_id=model.target_id,
        project_id=project_id,
        origin=parse_origin(canonical_origin),
        version=model.version,
        source_format=SpecFormat(model.source_format),
        source_size=model.source_size_bytes,
        source_sha256=model.source_sha256,
        document_sha256=model.document_sha256,
        openapi_version=model.openapi_version,
        base_path=model.base_path,
        operation_count=model.operation_count,
        uploaded_by_key_id=model.uploaded_by_key_id,
        created_at=model.created_at,
    )
