"""認證設定的業務規則（docs/DECISIONS.md §12）：

- 建立：PROJECT_WRITE。先檢查權限再驗證；以 FOR UPDATE 鎖住 target，再檢查數量上限，
  然後建立 profile 與版本 1（secret 以 profile 為 context 加密）。
- 新版本（PATCH）：PROJECT_WRITE。以 FOR UPDATE 鎖住 profile（version 依 commit 的先後遞增）；
  沿用 secret 時再鎖住目前的版本列讀出密文，直接複製。先清除上一版的密文，再寫入新版本。
- 查詢：PROJECT_READ。其他 project 一律和不存在的一樣回 404。
- secret 只加密、不解密：API 沒有解密的路徑。audit 不含 secret，也不含 preflight 的期望值。
- 金鑰換版（reencrypt_secrets）：只給本機 CLI 使用，沒有呼叫者身分可以檢查。
"""

from http import HTTPStatus
from uuid import UUID

from sqlalchemy.orm import Session

from secscan.api_keys.access import authorize
from secscan.api_keys.domain import Permission, Principal
from secscan.audit.service import AuditTrail
from secscan.auth_profiles.domain.errors import InvalidAuthProfileError
from secscan.auth_profiles.domain.model import (
    AuthProfile,
    ChangeInput,
    NewProfileVersion,
    ProfileInput,
    ProfileVersion,
    VersionPlan,
    build_profile,
    plan_version,
    secret_context,
)
from secscan.auth_profiles.domain.preflight import Preflight
from secscan.auth_profiles.repository import AuthProfileRepository
from secscan.core.db import ConstraintViolationError
from secscan.core.errors import AppError, ErrorCode, not_found_error
from secscan.core.json_types import JsonObject
from secscan.core.pagination import Page, PageRequest
from secscan.security.secret_cipher import SecretCipher, SecretUnreadableError
from secscan.targets.domain import Target
from secscan.targets.repository import TargetRepository

# 不能刪除：數量要有上限，一把外洩的 operator key 才不能無限寫入（docs/DECISIONS.md §12.6）。
# 舊版本不含密文，只有定義；lab 的 token 很快過期，版本數放寬一些。
MAX_PROFILES_PER_TARGET = 10
MAX_VERSIONS_PER_PROFILE = 100
ROLE_CONFLICT_CONSTRAINT = "uq_auth_profiles_target_id_role_label"


class SecretRotationError(Exception):
    """有密文解不開（金鑰不對，或密文被搬到其他 profile）；什麼都沒有寫入。只帶 profile id。"""

    def __init__(self, profile_ids: tuple[UUID, ...]) -> None:
        super().__init__(f"{len(profile_ids)} 份 secret 無法以目前的金鑰解開")
        self.profile_ids = profile_ids


class AuthProfileService:
    def __init__(self, session: Session, *, cipher: SecretCipher | None = None) -> None:
        """查詢用不到加密元件（最小權限）：只有建立、新版本與金鑰換版需要 cipher。"""
        self._profiles = AuthProfileRepository(session)
        self._targets = TargetRepository(session)
        self._audit = AuditTrail(session)
        self._optional_cipher = cipher

    @property
    def _cipher(self) -> SecretCipher:
        if self._optional_cipher is None:
            raise RuntimeError("這個操作需要加密元件：建立 AuthProfileService 時要傳入 cipher")
        return self._optional_cipher

    def create(
        self,
        principal: Principal,
        target_id: UUID,
        request: ProfileInput,
        *,
        request_id: str | None,
    ) -> AuthProfile:
        """建立 profile 與版本 1；不合規則時回 422，什麼都不寫入。"""
        cipher = self._cipher  # 在動到 DB 之前確認有加密元件
        self._target(principal, target_id, Permission.PROJECT_WRITE)
        try:
            new_profile, definition = build_profile(
                request, target_id=target_id, created_by_key_id=principal.key_id
            )
        except InvalidAuthProfileError as exc:
            raise _invalid_request(exc) from None
        # FOR UPDATE：同時建立時，數量上限是精確的。
        if self._targets.lock(target_id) is None:
            raise not_found_error()
        if self._profiles.count_for_target(target_id) >= MAX_PROFILES_PER_TARGET:
            raise _quota_error(f"每個 target 最多 {MAX_PROFILES_PER_TARGET} 個認證設定。")
        try:
            profile_id = self._profiles.create(new_profile)
        except ConstraintViolationError as violation:
            if violation.constraint == ROLE_CONFLICT_CONSTRAINT:
                raise AppError(
                    status_code=HTTPStatus.CONFLICT,
                    code=ErrorCode.AUTH_ROLE_CONFLICT,
                    message="這個 target 已有相同 role_label 的認證設定。",
                ) from None
            raise
        context = secret_context(profile_id, definition.credential)
        token = cipher.seal(request.secret.value, context=context)
        self._profiles.add_version(
            profile_id,
            version=1,
            new_version=NewProfileVersion(
                definition=definition, encrypted_secret=token, created_by_key_id=principal.key_id
            ),
        )
        profile = self._existing(profile_id)
        self._record(profile, "auth_profile.create", principal, request_id, _created(profile))
        return profile

    def update(
        self,
        principal: Principal,
        profile_id: UUID,
        request: ChangeInput,
        *,
        request_id: str | None,
    ) -> AuthProfile:
        """產生新版本；上一版的密文清除。不合規則時回 422，數量已滿回 409。"""
        cipher = self._cipher  # 在動到 DB 之前確認有加密元件
        self._profile(principal, profile_id, Permission.PROJECT_WRITE)
        try:
            change = request.build()
        except InvalidAuthProfileError as exc:
            raise _invalid_request(exc) from None
        locked = self._profiles.lock(profile_id)
        if locked is None:
            raise not_found_error()
        current = locked.current
        try:
            plan = plan_version(current.definition, change)
        except InvalidAuthProfileError as exc:
            raise _invalid_request(exc) from None
        if current.version >= MAX_VERSIONS_PER_PROFILE:
            raise _quota_error(f"每個認證設定最多 {MAX_VERSIONS_PER_PROFILE} 個版本。")
        token = self._token_for(cipher, plan, current)
        self._profiles.erase_secret(profile_id, version=current.version)
        self._profiles.add_version(
            profile_id,
            version=current.version + 1,
            new_version=NewProfileVersion(
                definition=plan.definition,
                encrypted_secret=token,
                created_by_key_id=principal.key_id,
            ),
        )
        updated = self._existing(profile_id)
        self._record(
            updated, "auth_profile.update", principal, request_id, _updated(updated, plan, current)
        )
        return updated

    def get(self, principal: Principal, profile_id: UUID) -> AuthProfile:
        return self._profile(principal, profile_id, Permission.PROJECT_READ)

    def list_for_target(
        self, principal: Principal, target_id: UUID, page: PageRequest
    ) -> Page[AuthProfile]:
        self._target(principal, target_id, Permission.PROJECT_READ)
        return self._profiles.list_by_target(target_id, page)

    def versions(
        self, principal: Principal, profile_id: UUID, page: PageRequest
    ) -> Page[ProfileVersion]:
        """版本的歷史，新版本在前；被取代的版本 secret_configured 為 False。"""
        self._profile(principal, profile_id, Permission.PROJECT_READ)
        return self._profiles.list_versions(profile_id, page)

    def reencrypt_secrets(self) -> int:
        """把所有還在的密文改用第一個金鑰重新加密，回傳份數（本機 CLI：secscan-admin
        rotate-secret-keys）。

        先全部算好再寫入：有任何一份解不開（金鑰不對，或密文不屬於這個 profile）時拋出
        SecretRotationError，什麼都不寫；呼叫端的 transaction 也應回滾。
        """
        cipher = self._cipher
        stored = self._profiles.secrets_for_update()
        rotated: list[tuple[UUID, int, bytes]] = []
        unreadable: list[UUID] = []
        for secret in stored:
            try:
                token = cipher.rotate(secret.token, context=secret.context)
            except SecretUnreadableError:
                unreadable.append(secret.profile_id)
                continue
            rotated.append((secret.profile_id, secret.version, token))
        if unreadable:
            raise SecretRotationError(tuple(unreadable))
        for profile_id, version, token in rotated:
            self._profiles.replace_secret(profile_id, version=version, token=token)
        self._audit.record(
            action="auth_secrets.reencrypt",
            object_type="auth_profile_version",
            object_id=None,
            actor_key_id=None,
            project_id=None,
            request_id=None,
            changes={"reencrypted": len(rotated)},
        )
        return len(rotated)

    def _token_for(self, cipher: SecretCipher, plan: VersionPlan, current: ProfileVersion) -> bytes:
        """新版本的密文：有新的 secret 就加密；否則鎖住目前的版本列，直接複製它的密文。"""
        profile_id = current.profile_id
        if plan.new_secret is not None:
            context = secret_context(profile_id, plan.definition.credential)
            return cipher.seal(plan.new_secret.value, context=context)
        token = self._profiles.current_secret_for_update(profile_id, version=current.version)
        if token is None:
            # 只有直接改了 DB 才會發生（trigger 允許清除）：沒有可以沿用的 secret。
            raise AppError(
                status_code=HTTPStatus.CONFLICT,
                code=ErrorCode.INVALID_STATE_TRANSITION,
                message="目前的版本已經沒有 secret：請在這次的變更中附上新的 secret。",
            )
        return token

    def _target(self, principal: Principal, target_id: UUID, permission: Permission) -> Target:
        """先取出所屬的 project 再檢查權限：其他 project 與不存在的一樣回 404。"""
        target = self._targets.get(target_id)
        if target is None:
            raise not_found_error()
        authorize(principal, permission, target.project_id)
        return target

    def _profile(
        self, principal: Principal, profile_id: UUID, permission: Permission
    ) -> AuthProfile:
        profile = self._profiles.get(profile_id)
        if profile is None:
            raise not_found_error()
        authorize(principal, permission, profile.project_id)
        return profile

    def _existing(self, profile_id: UUID) -> AuthProfile:
        # 剛在同一個 transaction 寫入：一定讀得到。
        profile = self._profiles.get(profile_id)
        if profile is None:
            raise RuntimeError("剛建立的認證設定讀不到")
        return profile

    def _record(
        self,
        profile: AuthProfile,
        action: str,
        principal: Principal,
        request_id: str | None,
        changes: JsonObject,
    ) -> None:
        self._audit.record(
            action=action,
            object_type="auth_profile",
            object_id=profile.id,
            actor_key_id=principal.key_id,
            project_id=profile.project_id,
            request_id=request_id,
            changes=changes,
        )


def _invalid_request(exc: InvalidAuthProfileError) -> AppError:
    return AppError(
        status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
        code=ErrorCode.INVALID_REQUEST,
        message=f"{exc}。",
    )


def _quota_error(message: str) -> AppError:
    return AppError(status_code=HTTPStatus.CONFLICT, code=ErrorCode.QUOTA_EXCEEDED, message=message)


def _preflight_summary(preflight: Preflight) -> JsonObject:
    """只列 JSON Pointer，不含期望值（可能是帳號或 email）。"""
    return {
        "method": preflight.method,
        "path": preflight.path,
        "expected_status": preflight.expected_status,
        "pointers": [str(pointer) for pointer in sorted(preflight.expected_json)],
    }


def _created(profile: AuthProfile) -> JsonObject:
    definition = profile.current.definition
    return {
        "target_id": str(profile.target_id),
        "name": profile.name,
        "role_label": profile.role_label,
        "version": profile.current.version,
        "type": definition.credential.type.value,
        "header_name": definition.credential.header_name,
        "preflight": _preflight_summary(definition.preflight),
    }


def _updated(profile: AuthProfile, plan: VersionPlan, previous: ProfileVersion) -> JsonObject:
    """新版本的摘要：哪些欄位改了、清除了哪一版的密文，以及改變後的定義（不含 secret）。"""
    definition = profile.current.definition
    changes: JsonObject = {
        "version": profile.current.version,
        "erased_version": previous.version,
        "changed": list(plan.changed),
    }
    if "type" in plan.changed:
        changes["type"] = definition.credential.type.value
    if "header_name" in plan.changed:
        changes["header_name"] = definition.credential.header_name
    if "preflight" in plan.changed:
        changes["preflight"] = _preflight_summary(definition.preflight)
    return changes
