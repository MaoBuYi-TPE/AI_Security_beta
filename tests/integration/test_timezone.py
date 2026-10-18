"""時間一律以 UTC 讀寫，不受伺服器或角色時區設定影響（CLAUDE.md §11）。

測試角色刻意設成 Asia/Taipei（tests/integration/database.py），才驗得出 engine 的 UTC 設定有作用。
"""

from datetime import timedelta

import psycopg
import pytest
from sqlalchemy import Engine, text

from tests.integration.database import ProvisionedDatabase

pytestmark = pytest.mark.integration

TAIPEI_OFFSET = timedelta(hours=8)


def test_role_default_timezone_is_not_utc(migrated_database: ProvisionedDatabase) -> None:
    """對照組：不經應用程式 engine 的連線，會拿到角色預設的 +08:00。"""
    with psycopg.connect(
        host=migrated_database.host,
        port=migrated_database.port,
        dbname=migrated_database.name,
        user=migrated_database.name,
        password=migrated_database.password,
        connect_timeout=5,
    ) as connection:
        row = connection.execute("SELECT now()").fetchone()

    assert row is not None
    assert row[0].utcoffset() == TAIPEI_OFFSET


def test_app_engine_reads_timestamps_in_utc(db_engine: Engine) -> None:
    with db_engine.connect() as connection:
        now = connection.execute(text("SELECT now()")).scalar()

    assert now is not None
    assert now.utcoffset() == timedelta(0)
