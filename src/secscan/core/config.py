"""應用程式設定：從環境變數與 .env 載入，建立後不可修改。"""

from ipaddress import IPv4Network
from typing import Literal, Self

from pydantic import Field, SecretStr, field_validator, model_validator
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

# 靶場網段（docs/DECISIONS.md §10.1）：預設是 compose.lab.yaml 的 lab_net。只接受 RFC 1918
# 私有網段內、前綴 /16 到 /30 的網段：太寬（例如 10.0.0.0/8）可能涵蓋校園網路，/31、/32 沒有
# 一般意義的網段與廣播位址。
DEFAULT_LAB_CIDR = IPv4Network("10.89.7.0/24")
RFC1918_NETWORKS = (
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
)
MIN_LAB_PREFIX_LENGTH = 16
MAX_LAB_PREFIX_LENGTH = 30


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

    # 掃描範圍的上限（環境變數 LAB_ONLY、LAB_CIDR）。P0 只掃 lab，LAB_ONLY 不能關閉。
    lab_only: bool = True
    lab_cidr: IPv4Network = DEFAULT_LAB_CIDR

    @property
    def docs_enabled(self) -> bool:
        """API 文件端點只在開發環境開啟（docs/API_CONTRACT.md §2）。"""
        return self.app_env == "dev"

    @field_validator("lab_cidr")
    @classmethod
    def _lab_cidr_is_a_narrow_private_network(cls, value: IPv4Network) -> IPv4Network:
        if not any(value.subnet_of(network) for network in RFC1918_NETWORKS):
            raise ValueError("LAB_CIDR 必須在 RFC 1918 私有網段內（10/8、172.16/12、192.168/16）")
        if not MIN_LAB_PREFIX_LENGTH <= value.prefixlen <= MAX_LAB_PREFIX_LENGTH:
            raise ValueError(
                f"LAB_CIDR 的前綴長度必須介於 /{MIN_LAB_PREFIX_LENGTH} 與 /{MAX_LAB_PREFIX_LENGTH}"
            )
        return value

    @model_validator(mode="after")
    def _require_lab_only(self) -> Self:
        """要掃描 lab 以外的目標，必須先完成 docs/DECISIONS.md §6 的條件；P0 不提供這個開關。"""
        if not self.lab_only:
            raise ValueError("P0 只支援 LAB_ONLY=true（見 docs/DECISIONS.md §10.1）")
        return self

    @model_validator(mode="after")
    def _require_db_password_in_prod(self) -> Self:
        """prod 缺少 DB 密碼時啟動就失敗，不等到第一個請求才發現。"""
        missing = self.db_password is None or not self.db_password.get_secret_value().strip()
        if self.app_env == "prod" and missing:
            raise ValueError("prod 環境必須設定 DB_PASSWORD")
        return self
