"""api_keys 的資料存取；回傳 frozen domain model。key 的產生與驗證規則在 service。"""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from secscan.api_keys.domain import ApiKey, NewApiKey, Revocation, Role
from secscan.api_keys.models import ApiKeyModel
from secscan.core.db import flush_or_raise


class ApiKeyRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, new_key: NewApiKey) -> ApiKey:
        """新增 key；prefix 或 hash 重複時拋出 ConstraintViolationError。"""
        model = ApiKeyModel(
            project_id=new_key.project_id,
            role=new_key.role.value,
            name=new_key.name,
            prefix=new_key.prefix,
            key_hash=new_key.key_hash,
            expires_at=new_key.expires_at,
        )
        self._session.add(model)
        flush_or_raise(self._session)
        return _to_domain(model)

    def get(self, key_id: UUID) -> ApiKey | None:
        model = self._session.get(ApiKeyModel, key_id)
        return _to_domain(model) if model is not None else None

    def get_by_prefix(self, prefix: str) -> ApiKey | None:
        """驗證請求時以 prefix 查詢（unique index），再由 service 以常數時間比對 hash。"""
        model = self._session.scalar(select(ApiKeyModel).where(ApiKeyModel.prefix == prefix))
        return _to_domain(model) if model is not None else None

    def revoke(self, key_id: UUID) -> Revocation | None:
        """撤銷而非刪除（稽核仍可追溯）。已撤銷的 key 保留第一次撤銷的時間；不存在時回 None。

        以 SELECT ... FOR UPDATE 鎖住該列，並用 DB 的最新值覆蓋已載入的物件（populate_existing），
        同時撤銷同一把 key 時只有一個請求算是「這次撤銷」。
        """
        model = self._session.get(ApiKeyModel, key_id, with_for_update=True, populate_existing=True)
        if model is None:
            return None
        newly_revoked = model.revoked_at is None
        if newly_revoked:
            model.revoked_at = func.now()
            flush_or_raise(self._session)
        return Revocation(key=_to_domain(model), newly_revoked=newly_revoked)


def _to_domain(model: ApiKeyModel) -> ApiKey:
    return ApiKey(
        id=model.id,
        project_id=model.project_id,
        role=Role(model.role),
        name=model.name,
        prefix=model.prefix,
        key_hash=model.key_hash,
        created_at=model.created_at,
        expires_at=model.expires_at,
        revoked_at=model.revoked_at,
    )
