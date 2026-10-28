"""guard 的 status 寫入與啟動流程（docs/DECISIONS.md §15.1、§15.3）。

以假的 master 驅動 serve()：路由或 options 不安全時不加入 addon、以非 0 結束；正常時 addon 是最後
加入的，status 在 mitmproxy 開始監聽（running）之後才標 enforcing，結束時改成 false。
"""

import asyncio
import io
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from uuid import UUID

import pytest

from secscan.guard.addon import GuardAddon
from secscan.guard.bootstrap import (
    EXIT_OK,
    EXIT_OPTIONS,
    EXIT_ROUTES,
    check_status,
    serve,
)
from secscan.guard.config import GuardConfig, config_from_env, expected_options
from secscan.guard.domain.status import (
    STATUS_FILE_NAME,
    GuardStatus,
    decode_status,
    encode_status,
)
from secscan.guard.events import GuardLog, guard_logger
from secscan.guard.files import write_atomic
from secscan.guard.heartbeat import StatusWriter
from tests.unit.guard.flows import make_response

NOW = 1_767_598_800.0
ROUTES = (
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
    "eth0\t0008590A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
    "eth1\t0007590A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
)
DEFAULT_ROUTE = "eth0\t00000000\t0108590A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"


@pytest.fixture
def config(tmp_path: Path) -> GuardConfig:
    for name in ("policies", "status", "conf"):
        (tmp_path / name).mkdir()
    return config_from_env(
        {
            "LAB_CIDR": "10.89.7.0/24",
            "GUARD_SCAN_CIDR": "10.89.8.0/24",
            "GUARD_SCAN_IP": "10.89.8.254",
            "GUARD_LAB_IP": "10.89.7.254",
            "GUARD_POLICIES_DIR": str(tmp_path / "policies"),
            "GUARD_STATUS_DIR": str(tmp_path / "status"),
            "GUARD_CONFDIR": str(tmp_path / "conf"),
        }
    )


def _status(config: GuardConfig) -> GuardStatus:
    return decode_status((config.status_dir / STATUS_FILE_NAME).read_bytes())


# --- StatusWriter -----------------------------------------------------------------------------


def test_writer_records_the_boot_and_enforcement(config: GuardConfig) -> None:
    boot = UUID(int=7)
    writer = StatusWriter(
        config.status_dir,
        listen=config.listen,
        enforcing=lambda: True,
        boot_id=boot,
        clock=lambda: NOW,
    )

    status = writer.write()

    assert status == GuardStatus(
        boot_id=boot,
        started_at=int(NOW),
        updated_at=int(NOW),
        listen=config.listen,
        policy_schema=1,
        enforcing=True,
    )
    assert _status(config) == status


def test_failing_self_checks_mean_not_enforcing(config: GuardConfig) -> None:
    def broken() -> bool:
        raise OSError("route table")

    writer = StatusWriter(config.status_dir, listen=config.listen, enforcing=broken)

    assert writer.write().enforcing is False
    assert writer.write(enforcing=True).enforcing is True


def test_each_start_gets_a_new_boot_id(config: GuardConfig) -> None:
    first = StatusWriter(config.status_dir, listen=config.listen, enforcing=lambda: True)
    second = StatusWriter(config.status_dir, listen=config.listen, enforcing=lambda: True)

    assert first.boot_id != second.boot_id


def test_writer_loop_keeps_writing_until_stopped(config: GuardConfig) -> None:
    ticks: list[float] = []

    def clock() -> float:
        ticks.append(NOW + 5 * len(ticks))
        return ticks[-1]

    writer = StatusWriter(
        config.status_dir, listen=config.listen, enforcing=lambda: True, clock=clock
    )

    async def scenario() -> None:
        stop = asyncio.Event()
        task = asyncio.create_task(writer.run(stop, interval=0.001))
        for _ in range(1000):
            await asyncio.sleep(0.001)
            if len(ticks) >= 4:
                break
        stop.set()
        await task

    asyncio.run(scenario())

    assert _status(config).updated_at >= NOW + 10
    assert _status(config).started_at == int(NOW)


def test_waking_the_writer_writes_immediately(config: GuardConfig) -> None:
    ready = [False]
    writer = StatusWriter(config.status_dir, listen=config.listen, enforcing=lambda: ready[0])

    async def scenario() -> bool:
        stop, wake = asyncio.Event(), asyncio.Event()
        task = asyncio.create_task(writer.run(stop, interval=60, wake=wake))
        await asyncio.sleep(0.01)
        ready[0] = True
        wake.set()
        for _ in range(500):
            await asyncio.sleep(0.001)
            if _status(config).enforcing:
                break
        stop.set()
        await task
        return _status(config).enforcing

    assert asyncio.run(scenario()) is True


def test_writer_loop_survives_write_errors(config: GuardConfig, tmp_path: Path) -> None:
    writer = StatusWriter(tmp_path / "missing", listen=config.listen, enforcing=lambda: True)
    stream = io.StringIO()

    async def scenario() -> None:
        stop = asyncio.Event()
        task = asyncio.create_task(
            writer.run(stop, interval=0.001, log=GuardLog(guard_logger("w-errors", stream)))
        )
        await asyncio.sleep(0.01)
        stop.set()
        await task

    asyncio.run(scenario())

    assert '"event": "status_write_failed"' in stream.getvalue()


# --- serve() ----------------------------------------------------------------------------------


class FakeOptions:
    def __init__(self, values: Mapping[str, object]) -> None:
        self._values = dict(values)
        self.overrides: dict[str, object] = {}

    def update(self, **values: object) -> None:
        self._values.update(values)
        self._values.update(self.overrides)

    def __getattr__(self, name: str) -> object:
        try:
            return self.__dict__["_values"][name]
        except KeyError:
            raise AttributeError(name) from None


@dataclass
class FakeAddons:
    added: list[object] = field(default_factory=list)

    def add(self, *addons: object) -> None:
        self.added.extend(addons)


class FakeMaster:
    def __init__(self, core: Mapping[str, object], config: GuardConfig) -> None:
        self.core = dict(core)
        self.options = FakeOptions(core)
        self.addons = FakeAddons()
        self.config = config
        self.status_while_running: GuardStatus | None = None
        self.shutdowns = 0

    async def run(self) -> None:
        # mitmproxy 先建立 server（期間 status 已寫過一次，還不是 enforcing），才呼叫 running。
        await asyncio.sleep(0.02)
        for addon in self.addons.added:
            if hasattr(addon, "running"):
                addon.running()
        for _ in range(200):
            await asyncio.sleep(0.001)
            path = self.config.status_dir / STATUS_FILE_NAME
            if path.exists() and _status(self.config).enforcing:
                break
        self.status_while_running = _status(self.config)

    def shutdown(self) -> None:
        self.shutdowns += 1


def _serve(
    config: GuardConfig,
    *,
    routes: str = ROUTES,
    overrides: Mapping[str, object] | None = None,
    status_interval: float | None = 0.001,
) -> tuple[int, list[FakeMaster], str]:
    masters: list[FakeMaster] = []
    stream = io.StringIO()

    def create(core: Mapping[str, object]) -> FakeMaster:
        master = FakeMaster(core, config)
        master.options.overrides = dict(overrides or {})
        masters.append(master)
        return master

    code = asyncio.run(
        serve(
            config,
            create_master=create,
            make_response=make_response,
            routes=lambda: routes,
            log=GuardLog(guard_logger(f"serve-{id(stream)}", stream)),
            signals=(),
            status_interval=status_interval,
        )
    )
    return code, masters, stream.getvalue()


def test_serve_adds_the_addon_last_and_reports_enforcing(config: GuardConfig) -> None:
    code, [master], _ = _serve(config)

    assert code == EXIT_OK
    assert master.core["mode"] == [f"regular@{config.listen}"]
    assert [type(addon) for addon in master.addons.added] == [GuardAddon]
    assert master.status_while_running is not None
    assert master.status_while_running.enforcing is True
    assert _status(config).enforcing is False  # 結束時改成 false


def test_status_turns_enforcing_as_soon_as_mitmproxy_listens(config: GuardConfig) -> None:
    """不等下一輪（5 秒）：running hook 一到就寫入 enforcing 的 status。"""
    code, [master], _ = _serve(config, status_interval=None)

    assert code == EXIT_OK
    assert master.status_while_running is not None
    assert master.status_while_running.enforcing is True


def test_unsafe_routes_stop_before_mitmproxy_starts(config: GuardConfig) -> None:
    code, masters, output = _serve(config, routes=ROUTES + DEFAULT_ROUTE)

    assert code == EXIT_ROUTES
    assert masters == []
    assert '"event": "route_check_failed"' in output


def test_unreadable_routes_stop_the_guard(config: GuardConfig) -> None:
    def broken() -> str:
        raise OSError("no /proc")

    code = asyncio.run(
        serve(
            config,
            create_master=lambda core: pytest.fail("不應該建立 master"),
            make_response=make_response,
            routes=broken,
            log=GuardLog(guard_logger("serve-broken-routes", io.StringIO())),
            signals=(),
        )
    )

    assert code == EXIT_ROUTES


def test_option_mismatches_stop_before_the_addon_is_added(config: GuardConfig) -> None:
    code, [master], output = _serve(config, overrides={"rawtcp": True})

    assert code == EXIT_OPTIONS
    assert master.addons.added == []
    assert "rawtcp" in output
    assert not (config.status_dir / STATUS_FILE_NAME).exists()


def test_every_expected_option_is_applied(config: GuardConfig) -> None:
    _, [master], _ = _serve(config)

    for name, value in expected_options(config).items():
        assert getattr(master.options, name) == value


# --- --check（healthcheck）-------------------------------------------------------------------


def test_check_passes_with_a_fresh_enforcing_status(config: GuardConfig) -> None:
    status = GuardStatus(UUID(int=1), int(NOW), int(NOW), config.listen, 1, True)
    write_atomic(config.status_dir, STATUS_FILE_NAME, encode_status(status))

    assert check_status(config, clock=lambda: NOW) == 0
    assert check_status(config, clock=lambda: NOW + 60) == 1


@pytest.mark.parametrize("content", [None, b"{}", json.dumps({"x": 1}).encode()])
def test_check_fails_without_a_valid_status(config: GuardConfig, content: bytes | None) -> None:
    if content is not None:
        write_atomic(config.status_dir, STATUS_FILE_NAME, content)

    assert check_status(config, clock=lambda: NOW) == 1
