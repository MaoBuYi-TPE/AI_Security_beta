"""guard 的 status（docs/DECISIONS.md §15.3）：每 5 秒原子寫入 status.json。

enforcing 由注入的自我檢查決定（addon 已開始監聽、路由仍然只有 scan 與 lab、policy 目錄可讀）；
檢查拋出例外就是 false。寫入失敗只記下來，下一輪再試：runner 看到 status 過期就不再認領。
"""

import asyncio
import time
from collections.abc import Callable
from pathlib import Path
from uuid import UUID, uuid4

from secscan.guard.domain.policy import POLICY_SCHEMA
from secscan.guard.domain.status import (
    STATUS_FILE_NAME,
    STATUS_INTERVAL_SECONDS,
    GuardStatus,
    encode_status,
)
from secscan.guard.events import GuardLog
from secscan.guard.files import AtomicWriteError, write_atomic


class StatusWriter:
    def __init__(
        self,
        directory: Path,
        *,
        listen: str,
        enforcing: Callable[[], bool],
        boot_id: UUID | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._directory = directory
        self._listen = listen
        self._enforcing = enforcing
        self._clock = clock
        self.boot_id = boot_id if boot_id is not None else uuid4()
        self._started_at = int(clock())

    def write(self, *, enforcing: bool | None = None) -> GuardStatus:
        status = GuardStatus(
            boot_id=self.boot_id,
            started_at=self._started_at,
            updated_at=int(self._clock()),
            listen=self._listen,
            policy_schema=POLICY_SCHEMA,
            enforcing=self._check() if enforcing is None else enforcing,
        )
        write_atomic(self._directory, STATUS_FILE_NAME, encode_status(status))
        return status

    async def run(
        self,
        stop: asyncio.Event,
        *,
        interval: float = STATUS_INTERVAL_SECONDS,
        log: GuardLog | None = None,
        wake: asyncio.Event | None = None,
    ) -> None:
        """每 interval 秒寫一次；wake 被設定時立刻再寫（例如 mitmproxy 開始監聽）。"""
        while not stop.is_set():
            try:
                self.write()
            except AtomicWriteError as exc:
                if log is not None:
                    log.refused("status_write_failed", error=str(exc))
            await _wait_any(stop, wake, interval)
            if wake is not None:
                wake.clear()

    def _check(self) -> bool:
        try:
            return bool(self._enforcing())
        except Exception:  # noqa: BLE001 - 自我檢查失敗就是不能保證流量受控
            return False


async def _wait_any(stop: asyncio.Event, wake: asyncio.Event | None, timeout: float) -> None:
    waiters = [asyncio.ensure_future(event.wait()) for event in (stop, wake) if event is not None]
    try:
        await asyncio.wait(waiters, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for waiter in waiters:
            waiter.cancel()
