"""guard 的啟動流程（docs/DECISIONS.md §15.1）；mitmproxy 的部分由 deploy/guard/run_guard.py 注入。

依序：
1. 路由只有 scan 與 lab 兩條直連的路由（沒有預設路由）。
2. 在 event loop 內以核心 options 建立 master（DumpMaster 載入預設 addon）。
3. 設定 addon 的 options，逐一讀回核對。
4. 最後才加入 guard 的 addon；status 在 mitmproxy 開始監聽之後才標 enforcing。
執行期間每一輪把拒絕的計數寫進 telemetry 的 summary、刪掉過期的檔案（§16）；結束時再寫一次。
任何一步失敗都以非 0 結束，不會變成沒有檢查的 proxy（`mitmdump -s` 載入失敗時仍會繼續當 proxy）。
綁不到位址時，mitmproxy 的 errorcheck 會讓程序以 1 結束（§15 實測 1）。
"""

import asyncio
import os
import signal
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Protocol
from uuid import uuid4

from secscan.guard.addon import GuardAddon
from secscan.guard.config import (
    GuardConfig,
    addon_options,
    core_options,
    expected_options,
    option_problems,
)
from secscan.guard.domain.routes import route_problem
from secscan.guard.domain.status import (
    STATUS_FILE_NAME,
    STATUS_INTERVAL_SECONDS,
    StatusError,
    decode_status,
    status_issue,
)
from secscan.guard.events import GuardLog
from secscan.guard.files import AtomicWriteError
from secscan.guard.flows import ResponseFactory
from secscan.guard.heartbeat import StatusWriter
from secscan.guard.resolver import BoundedResolver
from secscan.guard.store import PolicyStore
from secscan.guard.telemetry import TelemetryRecorder

EXIT_OK = 0
EXIT_UNHEALTHY = 1
EXIT_ROUTES = 3
EXIT_OPTIONS = 4
STOP_SIGNALS = (signal.SIGTERM, signal.SIGINT)


class Options(Protocol):
    def update(self, **values: object) -> None: ...


class Addons(Protocol):
    def add(self, *addons: object) -> None: ...


class Master(Protocol):
    @property
    def options(self) -> Options: ...

    @property
    def addons(self) -> Addons: ...

    async def run(self) -> None: ...

    def shutdown(self) -> None: ...


MasterFactory = Callable[[Mapping[str, object]], Master]


async def serve(
    config: GuardConfig,
    *,
    create_master: MasterFactory,
    make_response: ResponseFactory,
    routes: Callable[[], str],
    log: GuardLog,
    signals: Sequence[int] = STOP_SIGNALS,
    status_interval: float | None = None,
) -> int:
    if not _routes_ok(config, routes, log):
        return EXIT_ROUTES
    master = create_master(core_options(config))
    master.options.update(**addon_options())
    problems = option_problems(lambda name: getattr(master.options, name), expected_options(config))
    if problems:
        log.refused("options_check_failed", options=list(problems))
        return EXIT_OPTIONS
    wake = asyncio.Event()
    boot_id = uuid4()
    addon = GuardAddon(
        store=PolicyStore(config.policies_dir),
        resolve=BoundedResolver(),
        lab=config.lab,
        scan_network=config.scan_network,
        guard_ips=config.guard_ips,
        make_response=make_response,
        recorder=TelemetryRecorder(config.telemetry_dir, boot_id=boot_id),
        log=log,
        on_ready=wake.set,
    )
    master.addons.add(addon)
    writer = StatusWriter(
        config.status_dir,
        listen=config.listen,
        enforcing=lambda: addon.ready and _self_check(config, routes),
        boot_id=boot_id,
        log=log,
    )
    for number in signals:
        asyncio.get_running_loop().add_signal_handler(number, master.shutdown)
    interval = STATUS_INTERVAL_SECONDS if status_interval is None else status_interval
    await _run_with_status(master, writer, addon, wake, log, interval)
    return EXIT_OK


async def _run_with_status(
    master: Master,
    writer: StatusWriter,
    addon: GuardAddon,
    wake: asyncio.Event,
    log: GuardLog,
    interval: float,
) -> None:
    """mitmproxy 執行期間持續寫 status 與 telemetry；結束時標成不再檢查。"""
    stop = asyncio.Event()
    status = asyncio.create_task(writer.run(stop, log=log, wake=wake, interval=interval))
    flusher = asyncio.create_task(_flush_telemetry(addon, stop, interval))
    log.info("guard_started", listen=writer.listen, boot_id=str(writer.boot_id))
    try:
        await master.run()
    finally:
        stop.set()
        await status
        await flusher
        addon.flush_telemetry()
        _final_status(writer, log)


async def _flush_telemetry(addon: GuardAddon, stop: asyncio.Event, interval: float) -> None:
    while not stop.is_set():
        addon.flush_telemetry()
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except TimeoutError:
            continue


def check_status(config: GuardConfig, *, clock: Callable[[], float] = time.time) -> int:
    """healthcheck：status 是新的、正在檢查時回 0。"""
    try:
        raw = (config.status_dir / STATUS_FILE_NAME).read_bytes()
        status = decode_status(raw)
    except (OSError, StatusError):
        return EXIT_UNHEALTHY
    if status_issue(status, now=clock(), listen=config.listen) is not None:
        return EXIT_UNHEALTHY
    return EXIT_OK


def _routes_ok(config: GuardConfig, routes: Callable[[], str], log: GuardLog) -> bool:
    try:
        problem = route_problem(routes(), expected=(config.scan_network, config.lab.cidr))
    except OSError:
        problem = "讀不到路由表"
    if problem is not None:
        log.refused("route_check_failed", problem=problem)
        return False
    return True


def _self_check(config: GuardConfig, routes: Callable[[], str]) -> bool:
    expected = (config.scan_network, config.lab.cidr)
    return (
        route_problem(routes(), expected=expected) is None
        and os.access(config.policies_dir, os.R_OK | os.X_OK)
        and os.access(config.telemetry_dir, os.W_OK | os.X_OK)
    )


def _final_status(writer: StatusWriter, log: GuardLog) -> None:
    """結束時標成不再檢查：runner 不必等 status 過期。"""
    try:
        writer.write(enforcing=False)
    except AtomicWriteError as exc:
        log.refused("status_write_failed", error=str(exc))
