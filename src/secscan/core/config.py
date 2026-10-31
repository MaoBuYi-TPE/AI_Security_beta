"""應用程式設定：從環境變數與 .env 載入，建立後不可修改。"""

from ipaddress import IPv4Network
from typing import Literal, Self

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from secscan.core.network import lab_cidr_problem

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
# 每個連線的逾時（docs/DECISIONS.md §13.8）。PostgreSQL 預設都關閉（0），這裡不允許關閉。
DEFAULT_DB_STATEMENT_TIMEOUT_SECONDS = 30
MAX_DB_STATEMENT_TIMEOUT_SECONDS = 600
DEFAULT_DB_LOCK_TIMEOUT_SECONDS = 5
MAX_DB_LOCK_TIMEOUT_SECONDS = 60
DEFAULT_DB_IDLE_IN_TRANSACTION_TIMEOUT_SECONDS = 60
MAX_DB_IDLE_IN_TRANSACTION_TIMEOUT_SECONDS = 3_600
MAX_TCP_PORT = 65535

# 靶場網段（docs/DECISIONS.md §10.1）：預設是 lab_net（make lab-net）。規則在 core/network.py，
# egress guard 也用同一個函式檢查。
DEFAULT_LAB_CIDR = IPv4Network("10.89.7.0/24")


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
    # 一個 statement 最長執行多久、每次等鎖最長多久、transaction 中閒置多久就終止 session。
    db_statement_timeout_seconds: int = Field(
        default=DEFAULT_DB_STATEMENT_TIMEOUT_SECONDS, ge=1, le=MAX_DB_STATEMENT_TIMEOUT_SECONDS
    )
    db_lock_timeout_seconds: int = Field(
        default=DEFAULT_DB_LOCK_TIMEOUT_SECONDS, ge=1, le=MAX_DB_LOCK_TIMEOUT_SECONDS
    )
    db_idle_in_transaction_timeout_seconds: int = Field(
        default=DEFAULT_DB_IDLE_IN_TRANSACTION_TIMEOUT_SECONDS,
        ge=1,
        le=MAX_DB_IDLE_IN_TRANSACTION_TIMEOUT_SECONDS,
    )

    # 目標 secret 的加密金鑰（環境變數 SECRET_ENCRYPTION_KEYS，docs/DECISIONS.md §12.1）：逗號分隔的
    # Fernet 金鑰，第一個用來加密。這裡只讀入；API 與金鑰換版的 CLI 在啟動時檢查格式，
    # 建立 admin key 的 CLI 不需要它。
    secret_encryption_keys: SecretStr | None = None

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
        problem = lab_cidr_problem(value)
        if problem is not None:
            raise ValueError(problem)
        return value

    @model_validator(mode="after")
    def _require_lab_only(self) -> Self:
        """要掃描 lab 以外的目標，必須先完成 docs/DECISIONS.md §6 的條件；P0 不提供這個開關。"""
        if not self.lab_only:
            raise ValueError("P0 只支援 LAB_ONLY=true（見 docs/DECISIONS.md §10.1）")
        return self

    @model_validator(mode="after")
    def _lock_timeout_is_shorter_than_statement_timeout(self) -> Self:
        """等鎖的上限不比 statement 的上限短，就永遠先被 statement_timeout 中止，等於沒有設定。"""
        if self.db_lock_timeout_seconds >= self.db_statement_timeout_seconds:
            raise ValueError("DB_LOCK_TIMEOUT_SECONDS 必須小於 DB_STATEMENT_TIMEOUT_SECONDS")
        return self

    @model_validator(mode="after")
    def _require_db_password_in_prod(self) -> Self:
        """prod 缺少 DB 密碼時啟動就失敗，不等到第一個請求才發現。"""
        missing = self.db_password is None or not self.db_password.get_secret_value().strip()
        if self.app_env == "prod" and missing:
            raise ValueError("prod 環境必須設定 DB_PASSWORD")
        return self
