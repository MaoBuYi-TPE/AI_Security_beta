"""平台 API key 的身分驗證（FastAPI 依賴）；main.create_app 在 /api/v1 的 router 層強制使用。

- `Authorization: Bearer <key>`。缺少、scheme 不對、格式不對、不存在、secret 錯誤、已撤銷：
  一律回 401 UNAUTHENTICATED，回應完全相同；只有 secret 驗證成功但已過期，才回 API_KEY_EXPIRED。
- 失敗原因與 request_id 記在伺服器日誌，client 送來的值一律不記（docs/DECISIONS.md §9.1）。
"""

import logging
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from secscan.api_keys.domain import ApiKeyRejectedError, Principal, RejectionReason
from secscan.api_keys.service import ApiKeyService
from secscan.core.db import DbSession
from secscan.core.errors import AppError, ErrorCode
from secscan.core.request_id import request_id_of

logger = logging.getLogger(__name__)

UNAUTHENTICATED_MESSAGE = "需要有效的平台 API key（Authorization: Bearer）。"
EXPIRED_MESSAGE = "平台 API key 已過期，請改用新的 key。"
_CHALLENGE = {"WWW-Authenticate": "Bearer"}

# auto_error=False：由這裡回 envelope 格式的 401，不用框架的預設回應。
_bearer = HTTPBearer(
    auto_error=False,
    scheme_name="PlatformApiKey",
    description="平台 API key（secscan_…）。只授權使用本平台，不可送往被測網站。",
)


def current_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    session: DbSession,
) -> Principal:
    """通過驗證的呼叫者；失敗時拋出 401 的 AppError。"""
    try:
        if credentials is None:
            raise ApiKeyRejectedError(RejectionReason.MISSING)
        return ApiKeyService(session).authenticate(credentials.credentials, now=datetime.now(UTC))
    except ApiKeyRejectedError as rejected:
        log_rejection(rejected.reason, rejected.key_id, request_id_of(request))
        raise rejection_error(rejected.reason) from None


CurrentPrincipal = Annotated[Principal, Depends(current_principal)]


def authenticated_router(*, prefix: str) -> APIRouter:
    """整個 router 都要平台 API key。

    之後新增的路由即使忘了宣告 CurrentPrincipal，也不會變成公開端點。
    """
    return APIRouter(prefix=prefix, dependencies=[Depends(current_principal)])


def log_rejection(reason: RejectionReason, key_id: UUID | None, request_id: str) -> None:
    """記下拒絕的原因與 request_id；client 送來的值一律不記。api_keys.middleware 也用這個函式。"""
    logger.warning(
        "api key rejected: reason=%s key_id=%s request_id=%s",
        reason.value,
        key_id or "-",
        request_id,
    )


def rejection_error(reason: RejectionReason) -> AppError:
    """401 的回應：只有 EXPIRED 不同，其他原因完全相同（不洩漏 key 是否存在）。"""
    if reason is RejectionReason.EXPIRED:
        return AppError(
            status_code=HTTPStatus.UNAUTHORIZED,
            code=ErrorCode.API_KEY_EXPIRED,
            message=EXPIRED_MESSAGE,
            headers=_CHALLENGE,
        )
    return AppError(
        status_code=HTTPStatus.UNAUTHORIZED,
        code=ErrorCode.UNAUTHENTICATED,
        message=UNAUTHENTICATED_MESSAGE,
        headers=_CHALLENGE,
    )
