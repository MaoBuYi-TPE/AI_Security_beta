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


def alembic_config(*, connection: Connection | None = None) -> Config:
    """不讀設定檔的 Alembic Config；傳入 connection 時，env.py 會直接使用它。"""
    config = Config()
    # Config 以 configparser 讀值，路徑中的 % 必須跳脫。
    config.set_main_option("script_location", str(MIGRATIONS_DIR).replace("%", "%%"))
    if connection is not None:
        config.attributes["connection"] = connection
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
