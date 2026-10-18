"""應用程式設定：從環境變數與 .env 載入，建立後不可修改。"""

from typing import Literal, Self

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

AppEnv = Literal["dev", "test", "prod"]

# 相對於工作目錄的 .env；測試會關閉它（tests/conftest.py），避免讀到真實的本機密碼。
ENV_FILE = ".env"

# 預設值對應本機開發用的 db（compose.yaml，只綁 127.0.0.1）。
DEFAULT_DB_HOST = "127.0.0.1"
DEFAULT_DB_PORT = 55432
DEFAULT_DB_NAME = "secscan"
DEFAULT_DB_USER = "secscan_app"
DEFAULT_DB_CONNECT_TIMEOUT_SECONDS = 5
MAX_DB_CONNECT_TIMEOUT_SECONDS = 60
MAX_TCP_PORT = 65535


class Settings(BaseSettings):
    """執行期設定。未設定 APP_ENV 時採 prod，預設關閉 API 文件（fail-safe）。"""

    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    app_env: AppEnv = "prod"

    # PostgreSQL 連線（環境變數 DB_HOST、DB_PORT…）。密碼以 SecretStr 保存，repr 不會顯示。
    db_host: str = Field(default=DEFAULT_DB_HOST, min_length=1)
    db_port: int = Field(default=DEFAULT_DB_PORT, ge=1, le=MAX_TCP_PORT)
    db_name: str = Field(default=DEFAULT_DB_NAME, min_length=1)
    db_user: str = Field(default=DEFAULT_DB_USER, min_length=1)
    db_password: SecretStr | None = None
    db_connect_timeout_seconds: int = Field(
        default=DEFAULT_DB_CONNECT_TIMEOUT_SECONDS, ge=1, le=MAX_DB_CONNECT_TIMEOUT_SECONDS
    )

    @property
    def docs_enabled(self) -> bool:
        """API 文件端點只在開發環境開啟（docs/API_CONTRACT.md §2）。"""
        return self.app_env == "dev"

    @model_validator(mode="after")
    def _require_db_password_in_prod(self) -> Self:
        """prod 缺少 DB 密碼時啟動就失敗，不等到第一個請求才發現。"""
        missing = self.db_password is None or not self.db_password.get_secret_value().strip()
        if self.app_env == "prod" and missing:
            raise ValueError("prod 環境必須設定 DB_PASSWORD")
        return self
