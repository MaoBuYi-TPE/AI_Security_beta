"""FastAPI 應用程式組裝。以 factory 建立，不在 import 時就產生 app。"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI
from pydantic import SecretStr

# 載入所有 ORM model：跨功能的 FK（例如 api_keys → projects）以資料表名稱引用，
# 被引用的 model 必須已在 metadata 裡。每個使用 ORM 的程序入口（API、CLI、worker、runner）
# 都要這樣做；tests/unit/test_entrypoint_registry.py 在新程序裡檢查。
import secscan.migrations.metadata  # noqa: F401
from secscan.api_keys.dependencies import authenticated_router
from secscan.api_keys.middleware import BearerKeyFormatMiddleware
from secscan.api_keys.router import router as api_keys_router
from secscan.auth_profiles.router import router as auth_profiles_router
from secscan.comparisons.router import router as comparisons_router
from secscan.core.api import API_V1_PREFIX
from secscan.core.body_limit import BodyLimitMiddleware
from secscan.core.config import Settings
from secscan.core.db import DatabaseResources, create_db_engine
from secscan.core.errors import register_error_handlers
from secscan.core.request_id import RequestIdMiddleware
from secscan.findings.router import router as findings_router
from secscan.grants.router import router as grants_router
from secscan.health.router import router as health_router
from secscan.migrations import head_revision
from secscan.projects.router import audit_router
from secscan.projects.router import router as projects_router
from secscan.reports.router import router as reports_router
from secscan.scanners.router import profiles_router as scan_profiles_router
from secscan.scanners.router import router as scanners_router
from secscan.scans.router import router as scans_router
from secscan.security.key_rings import CONTENT_SETTING, SECRET_SETTING, check_held, content_cipher
from secscan.security.secret_cipher import SecretCipher
from secscan.specs.router import router as specs_router
from secscan.targets.domain import LabNetwork
from secscan.targets.router import router as targets_router
from secscan.triage.router import router as triage_router


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
        # FastAPI 內建的 OpenTelemetry 會匯出驗證錯誤與例外（可能含請求中的 secret）。平台不使用，
        # 一律關閉：不隨環境中的 provider 或 FASTAPI_OTEL_AUTO_CONFIGURE 開啟（DECISIONS §12.2）。
        telemetry={"tracing": False, "metrics": False, "logs": False, "auto_configure": False},
    )
    app.state.db = DatabaseResources(engine=engine, schema_revision=head_revision())
    # LAB_ONLY 時 target 與 grant 的 IP 必須在這個網段內（docs/DECISIONS.md §10.1）。
    app.state.lab = LabNetwork(resolved.lab_cidr)
    # 目標 secret 的加密（docs/DECISIONS.md §12.1）與報告內容、人工複測摘錄的加密（§30.2）：
    # 沒有或不合法的金鑰、兩組共用金鑰時，啟動就失敗。API 沒有原始證據的金鑰。
    secret_keys = _setting(resolved.secret_encryption_keys)
    content_keys = _setting(resolved.content_encryption_keys)
    app.state.secret_cipher = SecretCipher.from_setting(secret_keys)
    app.state.content_cipher = content_cipher(content_keys)
    check_held({SECRET_SETTING: secret_keys, CONTENT_SETTING: content_keys})
    # 後加入的在外層。順序：request_id → key 格式 → 大小上限（docs/DECISIONS.md §11.1）：
    # 沒有 key 的請求連 body 都不讀；錯誤回應也都帶 request_id。
    app.add_middleware(BodyLimitMiddleware)
    app.add_middleware(BearerKeyFormatMiddleware)
    app.add_middleware(RequestIdMiddleware)
    register_error_handlers(app)
    app.include_router(health_router)
    app.include_router(_api_v1())
    return app


def _setting(value: SecretStr | None) -> str | None:
    return value.get_secret_value() if value is not None else None


def _api_v1() -> APIRouter:
    """業務 API：整個 router 都要平台 API key，之後新增的路由不會意外變成公開端點。"""
    api_v1 = authenticated_router(prefix=API_V1_PREFIX)
    api_v1.include_router(projects_router)
    api_v1.include_router(audit_router)
    api_v1.include_router(api_keys_router)
    api_v1.include_router(targets_router)
    api_v1.include_router(grants_router)
    api_v1.include_router(specs_router)
    api_v1.include_router(auth_profiles_router)
    api_v1.include_router(scans_router)
    api_v1.include_router(findings_router)
    api_v1.include_router(triage_router)
    api_v1.include_router(reports_router)
    api_v1.include_router(comparisons_router)
    api_v1.include_router(scanners_router)
    api_v1.include_router(scan_profiles_router)
    return api_v1
