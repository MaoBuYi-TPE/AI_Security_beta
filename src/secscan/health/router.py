"""健康檢查路由；不在 /api/v1 之下，方便部署探針使用（docs/API_CONTRACT.md §2）。"""

from typing import Annotated

from fastapi import APIRouter, Depends

from secscan.core.db import DatabaseResources, DatabaseStatus, database_resources, probe_database
from secscan.core.envelope import Envelope, ok
from secscan.core.errors import AppError, ErrorCode
from secscan.health.schemas import LiveStatus, ReadyStatus

router = APIRouter(prefix="/health", tags=["health"])

SERVICE_UNAVAILABLE = 503
_NOT_READY_MESSAGES = {
    DatabaseStatus.UNAVAILABLE: "資料庫目前無法連線。",
    DatabaseStatus.SCHEMA_OUTDATED: "資料庫 schema 不是目前版本，請先執行 migration。",
}


@router.get("/live")
async def live() -> Envelope[LiveStatus]:
    """程序存活檢查：只代表程序在執行，不檢查 DB 等依賴。"""
    return ok(LiveStatus(status="ok"))


@router.get("/ready")
def ready(
    resources: Annotated[DatabaseResources, Depends(database_resources)],
) -> Envelope[ReadyStatus]:
    """可接受請求的檢查：DB 能連線，且 schema 正好在程式預期的 migration 版本。

    runner heartbeat 等其他依賴在 M2 加入。同步函式：FastAPI 會在 threadpool 執行 DB 查詢。
    """
    status = probe_database(resources.engine, resources.schema_revision)
    if status is not DatabaseStatus.READY:
        raise AppError(
            status_code=SERVICE_UNAVAILABLE,
            code=ErrorCode.DEPENDENCY_UNAVAILABLE,
            message=_NOT_READY_MESSAGES[status],
        )
    return ok(ReadyStatus(status="ready"))
