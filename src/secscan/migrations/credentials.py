"""migration 專用的 DB 角色與密碼（T23b-b1；docs/DECISIONS.md §31）。

- schema 由 owner 角色（DB_OWNER_USER，預設 secscan_owner）擁有，只有 migration 以它連線；
  api、worker、runner 只有應用程式角色（DB_USER）的逐表 DML 權限。
- 從環境變數或 .env 讀取；密碼必填，沒有時停止，**不退回**應用程式角色的帳密。
- 只有 env.py（make migrate、Live 的 recipe）與主機上的 migrate-db-roles 使用；compose 只把密碼交給
  db（initdb 建立角色），不交給 api、worker、runner。
"""

import re

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from secscan.core.config import ENV_FILE, Settings

DEFAULT_OWNER_USER = "secscan_owner"
MAX_ROLE_NAME_LENGTH = 63
# 角色名稱的規則（和 v0025 的應用程式角色相同）：小寫英數與底線，不可用保留的 pg_ 開頭。
ROLE_NAME = re.compile(r"[a-z_][a-z0-9_]{0,62}")


def valid_role_name(name: str) -> bool:
    return ROLE_NAME.fullmatch(name) is not None and not name.startswith("pg_")


class MissingOwnerPasswordError(RuntimeError):
    """沒有設定 DB_OWNER_PASSWORD。"""


class OwnerIsAppRoleError(RuntimeError):
    """owner 與應用程式角色相同（等於沒有分權）。"""


class MigrationConnectionError(RuntimeError):
    """連不上 owner 角色；不帶驅動程式的訊息（含主機與帳號）。"""


class MigrationCredentials(BaseSettings):
    """owner 角色的帳密（環境變數 DB_OWNER_USER、DB_OWNER_PASSWORD）。"""

    model_config = SettingsConfigDict(
        env_prefix="DB_OWNER_",
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    user: str = Field(default=DEFAULT_OWNER_USER, min_length=1, max_length=MAX_ROLE_NAME_LENGTH)
    password: SecretStr | None = None

    @field_validator("user")
    @classmethod
    def _valid_role_name(cls, value: str) -> str:
        if not valid_role_name(value):
            raise ValueError("DB_OWNER_USER 只接受小寫英數與底線，不可以 pg_ 開頭")
        return value

    def required_password(self, settings: Settings) -> SecretStr:
        """owner 的密碼；沒有設定，或 owner 和應用程式角色相同時停止。"""
        if self.password is None or not self.password.get_secret_value().strip():
            raise MissingOwnerPasswordError(
                "缺少 DB_OWNER_PASSWORD：請先執行 make env（migration 以 owner 角色執行，"
                "不使用應用程式的帳密）"
            )
        if self.user == settings.db_user:
            raise OwnerIsAppRoleError(
                "DB_OWNER_USER 不可與 DB_USER 相同：schema 的擁有者和應用程式必須是不同的角色"
            )
        return self.password

    def owner_settings(self, settings: Settings) -> Settings:
        """以 owner 連線的 Settings：主機、port、資料庫與逾時沿用 settings。"""
        password = self.required_password(settings)
        return settings.model_copy(update={"db_user": self.user, "db_password": password})
