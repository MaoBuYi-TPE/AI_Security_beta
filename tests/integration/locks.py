"""併發測試的共用工具：以獨立連線在背景執行操作，並以 pg_stat_activity 確認它正在等列鎖。

資料要真正 commit，對手的連線才看得到，所以這些測試使用 api_database。
"""

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

import pytest
from sqlalchemy.orm import Session

from secscan.core.db import create_db_engine
from tests.integration.api_support import Seeder
from tests.integration.database import ProvisionedDatabase

LOCK_WAIT_TIMEOUT_SECONDS = 10.0
POLL_INTERVAL_SECONDS = 0.05


def wait_until_waiting_for_a_lock(seed: Seeder, application_name: str) -> None:
    """以 pg_stat_activity 確認對手的連線正在等列鎖，不靠固定時間的 sleep 猜測。"""
    deadline = time.monotonic() + LOCK_WAIT_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        [row] = seed.query(
            "SELECT count(*) AS n FROM pg_stat_activity "
            "WHERE application_name = :name AND wait_event_type = 'Lock'",
            name=application_name,
        )
        if row.n:
            return
        time.sleep(POLL_INTERVAL_SECONDS)
    pytest.fail(f"{application_name} 沒有在等待列鎖")


@dataclass
class Race[T]:
    """在背景執行緒以獨立連線執行 work（在自己的 transaction 內），結果或例外留給測試檢查。"""

    database: ProvisionedDatabase
    application_name: str
    work: Callable[[Session], T]
    results: list[T] = field(default_factory=list)
    errors: list[Exception] = field(default_factory=list)
    _thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run)
        self._thread.start()

    def join(self) -> None:
        """等背景的 transaction 結束；逾時代表它一直卡在鎖上。"""
        assert self._thread is not None
        self._thread.join(timeout=LOCK_WAIT_TIMEOUT_SECONDS)
        assert not self._thread.is_alive(), f"{self.application_name} 沒有在時限內結束"

    def _run(self) -> None:
        engine = create_db_engine(
            self.database.app_settings(), application_name=self.application_name, pooled=False
        )
        try:
            with Session(engine, expire_on_commit=False) as session, session.begin():
                self.results.append(self.work(session))
        except Exception as exc:  # noqa: BLE001 - 例外交給測試檢查（例如預期中的 409）
            self.errors.append(exc)
        finally:
            engine.dispose()
