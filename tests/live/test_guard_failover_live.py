"""egress guard 的故障與取消（docs/DECISIONS.md §15.7；SEC-10、SEC-19、DoD 3：fail closed）。

這些測試會停掉 guard、重啟 guard、kill runner，所以放在 make test-live-runner 的最後執行，
每個測試結束時恢復 stack（runner 被 kill 之後由 compose 的 restart policy 重新啟動）。
掃描期間的收包證據：以掃描容器拿到的 proxy-url 從探針送出請求（fake 引擎本身不送流量）。
"""

import base64
import subprocess
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import pytest

from tests.live.guard_support import (
    Receiver,
    guard_log,
    probe,
    raw_request,
    start_receiver,
    stop_receiver,
    watch,
)
from tests.live.support import (
    GUARD_IMAGE,
    LAB_IP,
    SCAN_NET,
    Api,
    Scannable,
    admin_key,
    container,
    docker,
    inspect,
    scan_containers,
    scannable,
    wait_for,
)

pytestmark = [pytest.mark.live, pytest.mark.enable_socket]

LEASE_SECONDS = 30


@dataclass(frozen=True)
class Borrowed:
    """執行中的掃描容器的 proxy 帳密（測試借來從探針送請求）。"""

    run_id: str
    token: str
    container: str

    def request(self, origin: str, path: str) -> bytes:
        credentials = base64.b64encode(f"{self.run_id}:{self.token}".encode()).decode()
        host = urlsplit(origin).netloc
        return raw_request(f"{origin}{path}", host=host, authorization=f"Basic {credentials}")


@pytest.fixture(scope="module")
def admin() -> Api:
    return Api(admin_key())


@pytest.fixture
def target(admin: Api) -> Iterator[tuple[Scannable, Receiver, str]]:
    """可以掃描的 target，以及在它的 IP 上回應的接收端。"""
    item = scannable(admin, f"canary-{uuid.uuid4().hex[:12]}")
    origin = str(item.operator.data("GET", f"/targets/{item.target_id}")["canonical_origin"])
    host = urlsplit(origin).hostname
    assert host is not None
    receiver = start_receiver(f"scan-target-{host}", ip=LAB_IP, aliases=(host,), port=5000)
    yield item, receiver, origin
    stop_receiver(receiver)


def _running(scan_id: str) -> str:
    def find() -> str | None:
        names = scan_containers(scan_id)
        return names[0] if names else None

    return wait_for(find, timeout=60)


def _borrow(name: str) -> Borrowed:
    url = docker("exec", name, "cat", "/scan/secret/proxy-url").strip()
    parts = urlsplit(url)
    assert parts.username is not None
    assert parts.password is not None
    return Borrowed(run_id=parts.username, token=parts.password, container=name)


def _engine(item: Scannable, scan_id: str) -> dict[str, object]:
    [engine] = item.operator.data("GET", f"/scans/{scan_id}")["engines"]
    return dict(engine)


def _scanners(admin: Api) -> dict[str, dict[str, Any]]:
    data = admin.data("GET", "/scanners")
    return {item["engine"]: item for item in data["engines"]}


# --- 不安全的設定不會變成 proxy（SEC-10）------------------------------------------------------


def test_a_misconfigured_guard_exits_without_listening() -> None:
    no_settings = _exit_code("run", "--rm", GUARD_IMAGE)
    single_network = _exit_code(
        "run",
        "--rm",
        "--network",
        SCAN_NET,
        "-e",
        "LAB_CIDR=10.89.10.0/24",
        "-e",
        "GUARD_SCAN_CIDR=10.89.9.0/24",
        "-e",
        "GUARD_SCAN_IP=10.89.9.254",
        "-e",
        "GUARD_LAB_IP=10.89.10.254",
        GUARD_IMAGE,
    )
    broken_module = _exit_code(
        "run",
        "--rm",
        "--network",
        "none",
        "--tmpfs",
        "/tmp",  # noqa: S108 - 一次性容器內的 tmpfs
        "--entrypoint",
        "sh",
        GUARD_IMAGE,
        "-c",
        "cp -r /opt/secscan-guard /tmp/g && rm /tmp/g/secscan/guard/addon.py "
        "&& exec python3 -I -B /tmp/g/run_guard.py",
    )

    assert no_settings == 2  # 設定錯誤
    assert single_network == 3  # 路由不是正好 scan 與 lab：在建立 mitmproxy 之前就結束
    assert broken_module != 0


def _exit_code(*arguments: str) -> int:
    result = subprocess.run(  # noqa: S603 - 固定的 docker 指令與測試自己組的參數
        ["docker", *arguments],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    return result.returncode


# --- 取消：先封鎖 guard，再停止容器（SEC-19）-------------------------------------------------


def test_a_cancel_blocks_the_run_before_the_container_is_killed(
    target: tuple[Scannable, Receiver, str],
) -> None:
    """取消：guard 先拒絕這個 run 的請求，容器才收到 kill；之後接收端不再收到任何請求。

    fake 的容器收到 SIGTERM 就結束，封鎖到 policy 被刪除之間不到一秒：以每 20 ms 送一次請求的
    背景探針記下整個過程（之後 policy 已刪除，回 407）。
    """
    item, receiver, origin = target
    scan_id = item.scan()
    name = _running(scan_id)
    borrowed = _borrow(name)
    request = borrowed.request(origin, "/users/v1")
    assert probe([("before", request)])["before"]["status"] == 200
    watcher = watch(request, seconds=20)
    time.sleep(1)
    cancelled_at = time.time()

    status, _ = item.operator.call("POST", f"/scans/{scan_id}/cancel")
    assert status == 202
    results = watcher.results()
    wait_for(lambda: item.status(scan_id) == "cancelled", timeout=60)

    allowed = [result for result in results if result["status"] == 200]
    denied = [result for result in results if result["status"] != 200]
    assert allowed
    assert denied
    first_denied = min(result["t"] for result in denied)
    # 一旦開始拒絕就不再放行；取消之後 10 秒內開始拒絕（心跳每 5 秒）。
    assert max(result["t"] for result in allowed) < first_denied
    assert first_denied - cancelled_at < 10
    assert {(result["status"], result["reason"]) for result in denied} <= {
        (403, "RUN_BLOCKED"),
        (407, "PROXY_AUTH_REQUIRED"),
    }
    assert len(receiver.records()) == 1 + len(allowed)
    blocked = [
        entry["ts"]
        for entry in guard_log()
        if entry.get("reason") == "RUN_BLOCKED" and entry.get("run_id") == borrowed.run_id
    ]
    assert blocked, "封鎖到刪除 policy 之間應該有 RUN_BLOCKED"
    events = docker(
        "events",
        "--since",
        str(int(cancelled_at) - 1),
        "--until",
        str(int(time.time()) + 1),
        "--filter",
        f"container={name}",
        "--format",
        "{{.TimeNano}} {{.Action}}",
    ).splitlines()
    stops = [int(line.split()[0]) / 1e9 for line in events if line.split()[1] in {"kill", "die"}]
    assert stops
    assert min(blocked) <= min(stops)


# --- guard 中斷 -------------------------------------------------------------------------------


def test_a_guard_restart_interrupts_the_running_scan(
    target: tuple[Scannable, Receiver, str],
) -> None:
    """guard 重啟過（boot_id 改變）可能漏掉請求：run 標成 interrupted（GUARD_UNAVAILABLE）。"""
    item, _, _ = target
    scan_id = item.scan()
    _running(scan_id)

    docker("restart", container("guard"))

    wait_for(lambda: _engine(item, scan_id)["status"] == "interrupted", timeout=60)
    assert _engine(item, scan_id)["error_code"] == "GUARD_UNAVAILABLE"
    wait_for(
        lambda: inspect(container("guard"))["State"]["Health"]["Status"] == "healthy", timeout=60
    )


def test_a_stopped_guard_fails_closed_and_nothing_is_claimed(
    admin: Api, target: tuple[Scannable, Receiver, str]
) -> None:
    item, receiver, origin = target
    docker("stop", container("guard"))
    try:
        wait_for(
            lambda: _scanners(admin)["fake"]["unavailable_reason"] == "GUARD_UNAVAILABLE",
            timeout=30,
        )
        scan_id = item.scan()
        time.sleep(6)
        queued = item.status(scan_id)
        refused = probe([("down", raw_request(f"{origin}/users/v1", host=urlsplit(origin).netloc))])
    finally:
        docker("start", container("guard"))

    assert queued == "queued"
    assert scan_containers(scan_id) == []
    assert refused["down"]["status"] is None
    assert receiver.records() == []
    wait_for(lambda: item.status(scan_id) == "completed", timeout=90)


# --- runner 被 kill：renew_until 讓出站最晚在 lease 到期時停止（dead-man switch）---------------


def test_a_killed_runner_stops_the_orphans_traffic_within_the_lease(
    admin: Api, target: tuple[Scannable, Receiver, str]
) -> None:
    item, receiver, origin = target
    scan_id = item.scan()
    borrowed = _borrow(_running(scan_id))
    assert probe([("alive", borrowed.request(origin, "/users/v1"))])["alive"]["status"] == 200

    docker("kill", "--signal", "KILL", container("runner"))
    killed = time.time()

    def stale() -> float | None:
        result = probe([("orphan", borrowed.request(origin, "/users/v1"))])["orphan"]
        return time.time() if result["reason"] == "POLICY_STALE" else None

    stopped_at = wait_for(stale, timeout=LEASE_SECONDS + 15, interval=1)
    count = len(receiver.records())
    after = probe([("later", borrowed.request(origin, "/users/v1"))])["later"]

    assert stopped_at - killed <= LEASE_SECONDS + 5
    assert after["reason"] == "POLICY_STALE"
    assert len(receiver.records()) == count
    # docker kill 算是手動停止，restart policy 不會重啟：恢復 stack（孤兒容器與 run 留給 T13）。
    docker("start", container("runner"))
    wait_for(lambda: inspect(container("runner"))["State"]["Running"], timeout=60)
    wait_for(lambda: admin.data("GET", "/scanners")["runner"]["alive"], timeout=60)
