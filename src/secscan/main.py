"""FastAPI 應用程式組裝。以 factory 建立，不在 import 時就產生 app。"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

# 載入所有 ORM model：跨功能的 FK（例如 api_keys → projects）以資料表名稱引用，
# 被引用的 model 必須已在 metadata 裡。每個使用 ORM 的程序入口（API、CLI、worker、runner）
# 都要這樣做；tests/unit/test_entrypoint_registry.py 在新程序裡檢查。
import secscan.migrations.metadata  # noqa: F401
from secscan.core.config import Settings
from secscan.core.db import DatabaseResources, create_db_engine
from secscan.core.errors import register_error_handlers
from secscan.core.request_id import RequestIdMiddleware
from secscan.health.router import router as health_router
from secscan.migrations import head_revision


def create_app(settings: Settings | None = None) -> FastAPI:
    """建立 API 應用程式；API 文件端點只在開發環境開啟。

    DB engine 在這裡建立但不會立即連線，關閉時釋放連線池。
    """
    resolved = settings if settings is not None else Settings()
    engine = create_db_engine(resolved)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            engine.dispose()

    docs_enabled = resolved.docs_enabled
    app = FastAPI(
        title="secscan",
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
        lifespan=lifespan,
    )
    app.state.db = DatabaseResources(engine=engine, schema_revision=head_revision())
    app.add_middleware(RequestIdMiddleware)
    register_error_handlers(app)
    app.include_router(health_router)
    return app
