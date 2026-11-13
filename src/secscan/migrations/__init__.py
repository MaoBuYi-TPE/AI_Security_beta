"""Alembic migration（CLAUDE.md §11：schema 一律以 migration 建立，不用 create_all）。

`alembic` CLI 讀 pyproject.toml 的 [tool.alembic]；程式與測試用 alembic_config()。
兩者都指向這個目錄（tests/unit/test_migrations_layout.py 會檢查）。
"""

from functools import cache
from pathlib import Path
from typing import Literal

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import Connection

from secscan.core.db import UtcDateTime

MIGRATIONS_DIR = Path(__file__).resolve().parent


# v0022 讀取 CONTENT_ENCRYPTION_KEYS 的位置（env.py 由 Settings 放入；測試直接傳入）。
CONTENT_KEYS_ATTRIBUTE = "content_encryption_keys"
# 應用程式角色的名稱（T23b-b1；docs/DECISIONS.md §31）：env.py 每次 migration 之前以它檢查角色，
# v0025 依它授予逐表權限。env.py 取自 DB_USER；測試直接傳入；offline 用 `-x app_role=…`。
APP_ROLE_ATTRIBUTE = "app_role"


def alembic_config(
    *,
    connection: Connection | None = None,
    content_encryption_keys: str | None = None,
    app_role: str | None = None,
) -> Config:
    """不讀設定檔的 Alembic Config；傳入 connection 時，env.py 會直接使用它。

    content_encryption_keys：v0022 加密既有的報告與摘錄時用的金鑰（只有已經有資料時才需要）。
    app_role：應用程式角色。傳入 connection 時，有 app_role 才檢查角色（env.py）；升級到 v0025
    以後一定要有。connection 必須以 owner 角色連線。
    """
    config = Config()
    # Config 以 configparser 讀值，路徑中的 % 必須跳脫。
    config.set_main_option("script_location", str(MIGRATIONS_DIR).replace("%", "%%"))
    if connection is not None:
        config.attributes["connection"] = connection
    if content_encryption_keys is not None:
        config.attributes[CONTENT_KEYS_ATTRIBUTE] = content_encryption_keys
    if app_role is not None:
        config.attributes[APP_ROLE_ATTRIBUTE] = app_role
    return config


@cache
def head_revision() -> str:
    """目前程式預期的 schema 版本；有分支（多個 head）時直接失敗。"""
    heads = ScriptDirectory.from_config(alembic_config()).get_heads()
    if len(heads) != 1:
        raise RuntimeError(f"migration 必須只有一個 head，目前為 {heads}")
    return heads[0]


def render_item(type_: str, obj: object, _autogen_context: object) -> str | Literal[False]:
    """autogenerate 時把 UtcDateTime 寫成 sa.DateTime(timezone=True)。

    migration 是當時 schema 的快照，不 import 應用程式的型別，日後改程式也不會影響重播。
    """
    if type_ == "type" and isinstance(obj, UtcDateTime):
        return "sa.DateTime(timezone=True)"
    return False
