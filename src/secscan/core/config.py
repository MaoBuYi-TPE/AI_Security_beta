"""應用程式設定：從環境變數與 .env 載入，建立後不可修改。"""

from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

AppEnv = Literal["dev", "test", "prod"]


class Settings(BaseSettings):
    """執行期設定。未設定 APP_ENV 時採 prod，預設關閉 API 文件（fail-safe）。"""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    app_env: AppEnv = "prod"

    @property
    def docs_enabled(self) -> bool:
        """API 文件端點只在開發環境開啟（docs/API_CONTRACT.md §2）。"""
        return self.app_env == "dev"
