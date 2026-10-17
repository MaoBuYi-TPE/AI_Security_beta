"""FastAPI 應用程式組裝。以 factory 建立，不在 import 時就產生 app。"""

from fastapi import FastAPI

from secscan.core.config import Settings
from secscan.health.router import router as health_router


def create_app(settings: Settings | None = None) -> FastAPI:
    """建立 API 應用程式；API 文件端點只在開發環境開啟。"""
    resolved = settings if settings is not None else Settings()
    docs_enabled = resolved.docs_enabled
    app = FastAPI(
        title="secscan",
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )
    app.include_router(health_router)
    return app
