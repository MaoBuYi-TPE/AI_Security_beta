"""把權限規則（domain.decide）的結果轉成對外的錯誤；service 在執行操作之前呼叫。

被拒絕的存取記在伺服器日誌（誰、要做什麼、對哪個 project、request_id），方便發現有人逐一
嘗試其他 project 的 UUID；不記 request body。
"""

import logging
from http import HTTPStatus
from uuid import UUID

from secscan.api_keys.domain import AccessDecision, Permission, Principal, decide
from secscan.core.errors import AppError, ErrorCode, not_found_error
from secscan.core.request_id import current_request_id

logger = logging.getLogger(__name__)

ROLE_NOT_ALLOWED_MESSAGE = "目前的角色不能執行這個操作。"


def authorize(principal: Principal, permission: Permission, project_id: UUID | None = None) -> None:
    """不允許時拋出 AppError：其他 project 回 404（與不存在相同），角色不足回 403。"""
    decision = decide(principal, permission, project_id)
    if decision is AccessDecision.ALLOWED:
        return
    logger.warning(
        "access denied: decision=%s key_id=%s role=%s permission=%s project_id=%s request_id=%s",
        decision.value,
        principal.key_id,
        principal.role.value,
        permission.value,
        project_id or "-",
        current_request_id() or "-",
    )
    if decision is AccessDecision.NOT_FOUND:
        raise not_found_error()
    raise AppError(
        status_code=HTTPStatus.FORBIDDEN,
        code=ErrorCode.ROLE_NOT_ALLOWED,
        message=ROLE_NOT_ALLOWED_MESSAGE,
    )
