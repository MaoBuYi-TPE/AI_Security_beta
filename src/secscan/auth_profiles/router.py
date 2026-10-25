"""認證設定的端點（docs/API_CONTRACT.md §16）。只做輸入驗證與呼叫 service。

secret 只寫不讀：沒有任何端點回傳 secret 或由它衍生的值。
"""

from http import HTTPStatus
from uuid import UUID

from fastapi import APIRouter, Request

from secscan.api_keys.dependencies import CurrentPrincipal
from secscan.auth_profiles.dependencies import CurrentCipher
from secscan.auth_profiles.schemas import (
    AuthProfileCreate,
    AuthProfileOut,
    AuthProfilePatch,
    AuthProfileVersionOut,
)
from secscan.auth_profiles.service import AuthProfileService
from secscan.core.api import PageQuery, ok_page
from secscan.core.db import DbSession
from secscan.core.envelope import Envelope, ok
from secscan.core.request_id import request_id_of

router = APIRouter(tags=["auth-profiles"])


@router.post("/targets/{target_id}/auth-profiles", status_code=HTTPStatus.CREATED)
def create_profile(
    target_id: UUID,
    body: AuthProfileCreate,
    principal: CurrentPrincipal,
    session: DbSession,
    cipher: CurrentCipher,
    request: Request,
) -> Envelope[AuthProfileOut]:
    """建立認證設定（operator、admin）；secret 加密保存，不會出現在任何回應中。"""
    profile = AuthProfileService(session, cipher=cipher).create(
        principal, target_id, body.to_input(), request_id=request_id_of(request)
    )
    return ok(AuthProfileOut.of(profile))


@router.get("/targets/{target_id}/auth-profiles")
def list_profiles(
    target_id: UUID,
    principal: CurrentPrincipal,
    session: DbSession,
    cipher: CurrentCipher,
    page: PageQuery,
) -> Envelope[list[AuthProfileOut]]:
    """target 的認證設定，依建立時間由舊到新；每個 profile 顯示目前的版本。"""
    profiles = AuthProfileService(session, cipher=cipher).list_for_target(
        principal, target_id, page
    )
    return ok_page(profiles, AuthProfileOut.of)


@router.get("/auth-profiles/{profile_id}")
def get_profile(
    profile_id: UUID, principal: CurrentPrincipal, session: DbSession, cipher: CurrentCipher
) -> Envelope[AuthProfileOut]:
    """其他 project 的認證設定與不存在的一樣回 404。"""
    return ok(
        AuthProfileOut.of(AuthProfileService(session, cipher=cipher).get(principal, profile_id))
    )


@router.patch("/auth-profiles/{profile_id}")
def update_profile(
    profile_id: UUID,
    body: AuthProfilePatch,
    principal: CurrentPrincipal,
    session: DbSession,
    cipher: CurrentCipher,
    request: Request,
) -> Envelope[AuthProfileOut]:
    """產生新版本（operator、admin）；上一版的密文清除，舊的 scan 快照不受影響。"""
    profile = AuthProfileService(session, cipher=cipher).update(
        principal, profile_id, body.to_change(), request_id=request_id_of(request)
    )
    return ok(AuthProfileOut.of(profile))


@router.get("/auth-profiles/{profile_id}/versions")
def list_versions(
    profile_id: UUID,
    principal: CurrentPrincipal,
    session: DbSession,
    cipher: CurrentCipher,
    page: PageQuery,
) -> Envelope[list[AuthProfileVersionOut]]:
    """版本的歷史，新版本在前；只有目前的版本還有 secret。"""
    versions = AuthProfileService(session, cipher=cipher).versions(principal, profile_id, page)
    return ok_page(versions, AuthProfileVersionOut.of)
