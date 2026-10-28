"""guard 的錯誤路徑：讀不到檔案、寫入失敗、hook 中的例外、不合格式的輸入。

這些情形都必須是拒絕或中止（fail closed），而且不讓例外的內容進入 log。
"""

import asyncio
import base64
import io
import os
import signal
import stat
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from secscan.guard.addon import GuardAddon
from secscan.guard.bootstrap import EXIT_OK, serve
from secscan.guard.config import GuardConfigError, config_from_env
from secscan.guard.domain.credentials import parse_proxy_authorization
from secscan.guard.domain.policy import policy_file_name
from secscan.guard.domain.requests import Reason, RequestView, request_reason
from secscan.guard.domain.routes import route_problem
from secscan.guard.events import GuardLog, guard_logger, safe_text
from secscan.guard.files import AtomicWriteError, write_atomic
from secscan.guard.heartbeat import StatusWriter
from secscan.guard.store import PolicyStore, _read_regular
from secscan.targets.domain import LabNetwork
from tests.unit.guard.flows import (
    FakeClient,
    FakeFlow,
    FakeServer,
    FakeServerConnection,
    make_response,
)
from tests.unit.guard.test_requests import POLICY
from tests.unit.guard.test_runtime import ROUTES, FakeMaster

RUN_ID = UUID("6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b")
ENV = {
    "LAB_CIDR": "10.89.7.0/24",
    "GUARD_SCAN_CIDR": "10.89.8.0/24",
    "GUARD_SCAN_IP": "10.89.8.254",
    "GUARD_LAB_IP": "10.89.7.254",
}


def _addon(directory: Path, stream: io.StringIO) -> GuardAddon:
    async def resolve(_: str) -> tuple[str, ...]:
        return ("10.89.7.20",)

    return GuardAddon(
        store=PolicyStore(directory),
        resolve=resolve,
        lab=LabNetwork(IPv4Network("10.89.7.0/24")),
        scan_network=IPv4Network("10.89.8.0/24"),
        guard_ips=frozenset({IPv4Address("10.89.8.254")}),
        make_response=make_response,
        log=GuardLog(guard_logger(f"edges-{uuid4().hex}", stream)),
    )


# --- addon ------------------------------------------------------------------------------------


class _ExplodingClient:
    id = "explodes"
    error: str | None = None

    @property
    def peername(self) -> tuple[object, ...]:
        raise RuntimeError("peername")


def test_client_check_errors_kill_the_connection(tmp_path: Path) -> None:
    stream = io.StringIO()
    client = _ExplodingClient()

    _addon(tmp_path, stream).client_connected(client)

    assert client.error is not None
    assert '"hook": "client_connected"' in stream.getvalue()


def test_unparsable_peer_addresses_are_refused(tmp_path: Path) -> None:
    client = FakeClient(peername=("not-an-ip", 1))

    _addon(tmp_path, io.StringIO()).client_connected(client)

    assert client.error is not None


def test_server_connect_with_a_corrupt_policy_is_killed(tmp_path: Path) -> None:
    addon = _addon(tmp_path, io.StringIO())
    addon._approved["client-1"] = {("10.89.7.20", 8080): RUN_ID}
    write_atomic(tmp_path, policy_file_name(RUN_ID), b"{broken")
    server = FakeServer(address=("10.89.7.20", 8080))

    addon.server_connect(FakeServerConnection(client=FakeClient(), server=server))

    assert server.error is not None


def test_denying_a_flow_without_a_request_still_responds(tmp_path: Path) -> None:
    stream = io.StringIO()
    flow = FakeFlow(request=None)  # type: ignore[arg-type]

    _addon(tmp_path, stream).http_connect(flow)

    assert flow.response is not None
    assert '"decision": "deny"' in stream.getvalue()


class _Unkillable:
    def kill(self) -> None:
        raise RuntimeError("not killable")


def test_kill_failures_are_logged(tmp_path: Path) -> None:
    stream = io.StringIO()

    _addon(tmp_path, stream).tcp_start(_Unkillable())

    assert '"hook": "tcp_start"' in stream.getvalue()


def test_logging_errors_on_responses_are_contained(tmp_path: Path) -> None:
    stream = io.StringIO()

    _addon(tmp_path, stream).response(object())  # type: ignore[arg-type]

    assert '"hook": "response"' in stream.getvalue()


# --- events -----------------------------------------------------------------------------------


def test_logger_is_configured_once() -> None:
    name = f"once-{uuid4().hex}"

    first = guard_logger(name, io.StringIO())
    second = guard_logger(name, io.StringIO())

    assert first is second
    assert len(first.handlers) == 1
    assert first.propagate is False


@pytest.mark.parametrize(
    ("text", "expected"),
    [("/api", "/api"), ("a" * 300, "a" * 10), ("", "?"), ("/a b", "?"), ("/é", "?"), ("\n", "?")],
)
def test_safe_text(text: str, expected: str) -> None:
    assert safe_text(text, 10 if len(text) > 10 else 100) == expected


def test_decisions_without_a_request_are_logged() -> None:
    stream = io.StringIO()

    GuardLog(guard_logger(f"no-view-{uuid4().hex}", stream)).decision(
        allowed=False, reason="X", run_id=None, view=None
    )

    assert '"decision": "deny"' in stream.getvalue()
    assert '"path"' not in stream.getvalue()


# --- domain -----------------------------------------------------------------------------------


def _non_canonical_base64() -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    encoded = base64.b64encode(f"{RUN_ID}:{'A' * 43}".encode()).decode()
    data, padding = encoded.rstrip("="), "=" * (len(encoded) - len(encoded.rstrip("=")))
    assert padding, "需要有 padding 才有沒用到的 bit"
    last = alphabet[alphabet.index(data[-1]) | 1]
    return data[:-1] + last + padding


@pytest.mark.parametrize("value", ["Basic é", "Basic " + _non_canonical_base64()])
def test_non_canonical_base64_is_rejected(value: str) -> None:
    assert parse_proxy_authorization([value]) is None


def test_deeply_encoded_method_overrides_fail_closed() -> None:
    view = RequestView(
        method="GET",
        scheme="http",
        host="lab-target",
        port=8080,
        target="/api/items/7?%2525252525255Fmethod=DELETE",
        headers=(("Host", "lab-target:8080"),),
    )

    assert request_reason(view, POLICY) is Reason.OVERRIDE_HEADER


def test_route_addresses_must_be_eight_hex_digits() -> None:
    table = (
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
        "eth0\t0FA590A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
    )

    assert route_problem(table, expected=(IPv4Network("10.89.250.0/24"),)) is not None


def test_config_rejects_non_canonical_networks() -> None:
    with pytest.raises(GuardConfigError, match="canonical"):
        config_from_env({**ENV, "LAB_CIDR": "10.89.7.0/255.255.255.0"})


# --- 檔案 -------------------------------------------------------------------------------------


def test_write_failures_before_the_temp_file_exists_leave_nothing(tmp_path: Path) -> None:
    os.chmod(tmp_path, stat.S_IRUSR | stat.S_IXUSR)
    try:
        with pytest.raises(AtomicWriteError, match="EACCES"):
            write_atomic(tmp_path, "a.json", b"{}")
    finally:
        os.chmod(tmp_path, stat.S_IRWXU)
    assert list(tmp_path.iterdir()) == []


def test_store_reports_unusable_directories(tmp_path: Path) -> None:
    not_a_directory = tmp_path / "file"
    not_a_directory.write_bytes(b"")

    with pytest.raises(Exception, match="讀不到"):
        PolicyStore(not_a_directory).load(RUN_ID)


def test_store_notices_a_file_swapped_after_stat(tmp_path: Path) -> None:
    first, second = tmp_path / "a", tmp_path / "b"
    first.write_bytes(b"1")
    second.write_bytes(b"2")

    with pytest.raises(Exception, match="換掉"):
        _read_regular(first, os.stat(second))


def test_store_read_errors_are_policy_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "a"
    path.write_bytes(b"1")

    def broken(*_: object) -> bytes:
        raise OSError(5, "EIO")

    monkeypatch.setattr(os, "read", broken)

    with pytest.raises(Exception, match="讀不到"):
        _read_regular(path, os.stat(path))


# --- status 與啟動 ----------------------------------------------------------------------------


def test_status_write_errors_without_a_log_are_ignored(tmp_path: Path) -> None:
    writer = StatusWriter(tmp_path / "missing", listen="10.89.8.254:8080", enforcing=lambda: True)

    async def scenario() -> None:
        stop = asyncio.Event()
        task = asyncio.create_task(writer.run(stop, interval=0.001))
        await asyncio.sleep(0.005)
        stop.set()
        await task

    asyncio.run(scenario())


def test_serve_installs_stop_signals_and_survives_a_missing_status_directory(
    tmp_path: Path,
) -> None:
    (tmp_path / "policies").mkdir()
    config = config_from_env(
        {
            **ENV,
            "GUARD_POLICIES_DIR": str(tmp_path / "policies"),
            "GUARD_STATUS_DIR": str(tmp_path / "missing-status"),
            "GUARD_CONFDIR": str(tmp_path / "conf"),
        }
    )
    stream = io.StringIO()

    class _Quick(FakeMaster):
        async def run(self) -> None:
            await asyncio.sleep(0.01)

    code = asyncio.run(
        serve(
            config,
            create_master=lambda core: _Quick(core, config),
            make_response=make_response,
            routes=lambda: ROUTES,
            log=GuardLog(guard_logger(f"signals-{uuid4().hex}", stream)),
            signals=(signal.SIGUSR1,),
        )
    )

    assert code == EXIT_OK
    assert '"event": "status_write_failed"' in stream.getvalue()
