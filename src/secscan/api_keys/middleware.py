"""驗證之前的 key 格式檢查（pure ASGI，docs/DECISIONS.md §11.1）。

FastAPI 在執行依賴（包括驗證 key）之前，就會先讀完並解析 JSON body。這個 middleware 在路由之前
先看 `Authorization`：`/api/v1` 的請求沒有 Bearer，或 key 的格式不符，就直接回與
current_principal 完全相同的 401，一個 byte 的 body 都不讀。

判斷與 current_principal 一致：Bearer 的取法同 FastAPI 的 HTTPBearer，格式同 parse_prefix；
格式正確的 key 交給 current_principal 查 DB。
"""

from fastapi.security.utils import get_authorization_scheme_param
from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.types import ASGIApp, Receive, Scope, Send

from secscan.api_keys.dependencies import log_rejection, rejection_error
from secscan.api_keys.domain import RejectionReason
from secscan.core.api import API_V1_PREFIX
from secscan.core.errors import error_response
from secscan.core.request_id import request_id_of
from secscan.security.api_key_tokens import parse_prefix

BEARER_SCHEME = "bearer"


def credential_problem(authorization: str | None) -> RejectionReason | None:
    """`Authorization` 的值有什麼問題；None 代表格式正確（是否有效要查 DB）。

    與 HTTPBearer（auto_error=False）相同：沒有值、沒有憑證或 scheme 不是 Bearer（不分大小寫）
    都是 MISSING；憑證不是平台 key 的格式是 MALFORMED。
    """
    scheme, credentials = get_authorization_scheme_param(authorization)
    if not (authorization and scheme and credentials) or scheme.lower() != BEARER_SCHEME:
        return RejectionReason.MISSING
    if parse_prefix(credentials) is None:
        return RejectionReason.MALFORMED
    return None


class BearerKeyFormatMiddleware:
    def __init__(self, app: ASGIApp, *, prefix: str = API_V1_PREFIX) -> None:
        self._app = app
        self._prefix = prefix

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self._covers(scope["path"]):
            await self._app(scope, receive, send)
            return
        problem = credential_problem(Headers(scope=scope).get("authorization"))
        if problem is None:
            await self._app(scope, receive, send)
            return
        request = Request(scope)
        log_rejection(problem, None, request_id_of(request))
        response = error_response(request, rejection_error(problem))
        await response(scope, receive, send)

    def _covers(self, path: str) -> bool:
        return path == self._prefix or path.startswith(f"{self._prefix}/")
