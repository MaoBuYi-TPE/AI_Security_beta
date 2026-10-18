"""平台 API key 的驗證、建立與撤銷（docs/DECISIONS.md §9.1）。

- 驗證：格式不符直接拒絕，不查 DB；以 prefix 查詢後以常數時間比對 hash，再檢查撤銷與到期。
- 建立：完整 key 只出現在回傳的 IssuedApiKey；DB 只存 prefix 與 SHA-256，audit 只記摘要。
- 撤銷：只標記 revoked_at，不刪除資料列；audit 只記第一次撤銷。
"""

from collections.abc import Callable
from datetime import datetime
from http import HTTPStatus
from uuid import UUID

from sqlalchemy.orm import Session

from secscan.api_keys.access import authorize
from secscan.api_keys.domain import (
    KEY_HASH_BYTES,
    ApiKey,
    ApiKeyRejectedError,
    IssuedApiKey,
    NewApiKey,
    Permission,
    Principal,
    RejectionReason,
    Role,
    resolve_expiry,
)
from secscan.api_keys.repository import ApiKeyRepository
from secscan.audit.service import AuditTrail
from secscan.core.db import ConstraintViolationError
from secscan.core.errors import AppError, ErrorCode, not_found_error
from secscan.core.json_types import JsonObject
from secscan.security.api_key_tokens import (
    GeneratedKey,
    generate_key,
    hash_key,
    key_matches,
    parse_prefix,
)

KEY_CREATE_ATTEMPTS = 3
# prefix 不存在時仍比對一次（結果必定不符），讓「不存在」與「secret 錯誤」的運算量相近。
_UNKNOWN_KEY_HASH = bytes(KEY_HASH_BYTES)
# 新產生的 key 撞到既有的 prefix 或 hash：機率極低，重新產生即可。
_REGENERATE_ON = frozenset({"uq_api_keys_prefix", "uq_api_keys_key_hash"})


class ApiKeyService:
    """generate 可替換，用來測試 prefix 碰撞時的重試。"""

    def __init__(
        self, session: Session, *, generate: Callable[[], GeneratedKey] = generate_key
    ) -> None:
        self._session = session
        self._keys = ApiKeyRepository(session)
        self._audit = AuditTrail(session)
        self._generate = generate

    def authenticate(self, value: str, *, now: datetime) -> Principal:
        """回傳呼叫者；失敗時拋出 ApiKeyRejectedError（只帶原因，不帶 key）。"""
        prefix = parse_prefix(value)
        if prefix is None:
            raise ApiKeyRejectedError(RejectionReason.MALFORMED)
        key = self._keys.get_by_prefix(prefix)
        if key is None:
            key_matches(value, _UNKNOWN_KEY_HASH)
            raise ApiKeyRejectedError(RejectionReason.UNKNOWN_KEY)
        if not key_matches(value, key.key_hash):
            raise ApiKeyRejectedError(RejectionReason.HASH_MISMATCH, key.id)
        if key.revoked_at is not None:
            raise ApiKeyRejectedError(RejectionReason.REVOKED, key.id)
        # 沒有到期時間的 key 只可能經由直接寫 DB 產生，一律視為過期（fail closed）。
        if key.expires_at is None or key.expires_at <= now:
            raise ApiKeyRejectedError(RejectionReason.EXPIRED, key.id)
        return Principal.of(key)

    def issue_project_key(
        self,
        principal: Principal,
        project_id: UUID,
        *,
        name: str,
        role: Role,
        expires_at: datetime | None,
        now: datetime,
        request_id: str | None,
    ) -> IssuedApiKey:
        """platform_admin 為 project 建立 operator 或 viewer key。

        project 不存在時回 404（由 FK 判斷，不 import projects；docs/DECISIONS.md §8）。
        """
        authorize(principal, Permission.PLATFORM_MANAGE, project_id)
        issued = self._insert(
            role=role, name=name, project_id=project_id, expires_at=_expiry(expires_at, now)
        )
        self._audit.record(
            action="api_key.create",
            object_type="api_key",
            object_id=issued.key.id,
            actor_key_id=principal.key_id,
            project_id=project_id,
            request_id=request_id,
            changes=_summary(issued.key),
        )
        return issued

    def issue_admin_key(
        self, *, name: str, expires_at: datetime | None, now: datetime
    ) -> IssuedApiKey:
        """本機 CLI 建立 platform_admin key（API 不能建立）；audit 的 actor 為 None。"""
        issued = self._insert(
            role=Role.PLATFORM_ADMIN,
            name=name,
            project_id=None,
            expires_at=_expiry(expires_at, now),
        )
        self._audit.record(
            action="api_key.create",
            object_type="api_key",
            object_id=issued.key.id,
            actor_key_id=None,
            project_id=None,
            request_id=None,
            changes={**_summary(issued.key), "source": "cli"},
        )
        return issued

    def revoke(self, principal: Principal, key_id: UUID, *, request_id: str | None) -> None:
        """撤銷 key；重複撤銷不算錯誤，但只有第一次寫 audit。"""
        authorize(principal, Permission.PLATFORM_MANAGE)
        revocation = self._keys.revoke(key_id)
        if revocation is None:
            raise not_found_error()
        if not revocation.newly_revoked:
            return
        key = revocation.key
        self._audit.record(
            action="api_key.revoke",
            object_type="api_key",
            object_id=key.id,
            actor_key_id=principal.key_id,
            project_id=key.project_id,
            request_id=request_id,
            changes={"role": key.role.value, "prefix": key.prefix},
        )

    def _insert(
        self, *, role: Role, name: str, project_id: UUID | None, expires_at: datetime
    ) -> IssuedApiKey:
        """在 savepoint 內新增；撞到唯一約束時只回滾 savepoint，外層 transaction 仍可使用。"""
        for _ in range(KEY_CREATE_ATTEMPTS):
            generated = self._generate()
            new_key = NewApiKey(
                role=role,
                name=name,
                prefix=generated.prefix,
                key_hash=hash_key(generated.value),
                project_id=project_id,
                expires_at=expires_at,
            )
            try:
                with self._session.begin_nested():
                    stored = self._keys.create(new_key)
            except ConstraintViolationError as violation:
                if violation.constraint in _REGENERATE_ON:
                    continue
                raise _constraint_error(violation) from None
            return IssuedApiKey(key=stored, value=generated.value)
        raise RuntimeError(f"連續 {KEY_CREATE_ATTEMPTS} 次產生的 key 都與既有的 key 重複")


def _expiry(requested: datetime | None, now: datetime) -> datetime:
    try:
        return resolve_expiry(requested, now=now)
    except ValueError as exc:
        raise AppError(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            code=ErrorCode.INVALID_REQUEST,
            message=f"{exc}。",
        ) from None


def _constraint_error(violation: ConstraintViolationError) -> Exception:
    """約束名稱對應成穩定錯誤碼（不回傳約束名稱）；不認得的約束原樣拋出（→ 500）。"""
    if violation.constraint == "fk_api_keys_project_id_projects":
        return not_found_error()
    if violation.constraint == "ck_api_keys_expires_after_created":
        # 應用程式時鐘落後 DB 時鐘時才會發生：resolve_expiry 已要求晚於應用程式的現在。
        return AppError(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            code=ErrorCode.INVALID_REQUEST,
            message="expires_at 必須晚於建立時間。",
        )
    return violation


def _summary(key: ApiKey) -> JsonObject:
    """audit 用的摘要：prefix 是公開的識別碼；完整 key、secret 與 hash 都不記。"""
    return {
        "role": key.role.value,
        "name": key.name,
        "prefix": key.prefix,
        "expires_at": key.expires_at.isoformat() if key.expires_at is not None else None,
    }
