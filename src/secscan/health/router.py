"""健康檢查路由；不在 /api/v1 之下，方便部署探針使用（docs/API_CONTRACT.md §2）。"""

from fastapi import APIRouter

from secscan.core.envelope import Envelope, ok
from secscan.health.schemas import LiveStatus

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live")
async def live() -> Envelope[LiveStatus]:
    """程序存活檢查：只代表程序在執行，不檢查 DB 等依賴。"""
    return ok(LiveStatus(status="ok"))
