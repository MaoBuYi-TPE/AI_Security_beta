"""T10 的 live 測試：真的 Docker、socket-proxy 與 fake 容器（docs/DECISIONS.md §14）。

只在 make test-live-runner 建立的獨立 stack 上執行（ENABLE_LIVE_LAB_TESTS=1）：不連 lab，fake
容器不送任何流量。驗證 TASKS T10 的 DoD：
1. api、worker、掃描容器都沒有 Docker socket，也不是 privileged。
2. socket-proxy 只開放容器需要的區段（SEC-21）。
3. host bind 等未核准的設定在 proxy 被拒絕，也沒有產生容器。
"""

import json
import secrets
from pathlib import Path
from typing import Any

import pytest

from tests.live.guard_support import start_receiver, stop_receiver
from tests.live.support import (
    BUSYBOX,
    GUARD_LAB_IP,
    LAB_IP,
    SCAN_NET,
    SECRETS_VOLUME,
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

PROBE = Path(__file__).with_name("proxy_probe.py").read_text(encoding="utf-8")
CANARY = f"canary-live-{secrets.token_hex(8)}"


@pytest.fixture(scope="module")
def admin() -> Api:
    return Api(admin_key())


@pytest.fixture
def target(admin: Api) -> Scannable:
    return scannable(admin, CANARY)


def _mounts(info: dict[str, Any]) -> list[dict[str, Any]]:
    return list(info["Mounts"])


@pytest.mark.parametrize("service", ["api", "runner", "worker"])
def test_app_containers_have_no_docker_socket_and_no_privileges(service: str) -> None:
    info = inspect(container(service))
    host = info["HostConfig"]

    assert not [mount for mount in _mounts(info) if "docker.sock" in str(mount.get("Source"))]
    assert host["Privileged"] is False
    assert host["CapDrop"] == ["ALL"]
    assert host["CapAdd"] in (None, [])
    assert host["ReadonlyRootfs"] is True
    assert "no-new-privileges:true" in host["SecurityOpt"]
    assert info["Config"]["User"] == "10001:10001"


def test_only_the_socket_proxy_has_the_socket_and_read_only() -> None:
    info = inspect(container("socket-proxy"))

    [socket] = [mount for mount in _mounts(info) if "docker.sock" in str(mount.get("Source"))]
    assert socket["RW"] is False
    assert info["HostConfig"]["Privileged"] is False
    assert info["Config"]["User"] == "65534:0"
    assert list(info["NetworkSettings"]["Networks"]) == [
        f"{container('socket-proxy')[: -len('-socket-proxy-1')]}_docker_net"
    ]


def _all_containers() -> set[str]:
    return set(docker("ps", "-a", "--format", "{{.ID}}").split())


def test_the_proxy_refuses_everything_but_the_container_api() -> None:
    before = _all_containers()

    results: dict[str, Any] = json.loads(
        docker("exec", "-i", container("runner"), "python", "-I", "-", stdin=PROBE)
    )

    assert results.pop("version") == 200
    assert results, "探針沒有回報任何結果"
    for label, status in results.items():
        assert status in (403, 405), (label, status)
    # 被拒絕的 create 沒有在 daemon 上產生任何容器（不只看狀態碼）。
    assert _all_containers() == before


@pytest.mark.parametrize("service", ["api", "worker"])
def test_only_the_runner_can_reach_the_proxy(service: str) -> None:
    script = (
        "import http.client\n"
        "try:\n"
        "    c = http.client.HTTPConnection('socket-proxy', 2375, timeout=5)\n"
        "    c.request('GET', '/v1.45/version')\n"
        "    print(c.getresponse().status)\n"
        "except OSError as error:\n"
        "    print(type(error).__name__)\n"
    )

    output = docker("exec", "-i", container(service), "python", "-I", "-", stdin=script).strip()

    assert output in ("gaierror", "ConnectionRefusedError", "TimeoutError", "403")


def test_the_scanners_endpoint_sees_the_runner(admin: Api) -> None:
    data = admin.data("GET", "/scanners")

    fake = next(item for item in data["engines"] if item["engine"] == "fake")
    assert (fake["available"], fake["image"]) == (True, BUSYBOX)
    assert data["runner"]["alive"] is True
    assert data["worker"]["alive"] is True


def _running_container(scan_id: str, engine: str = "fake") -> str:
    """綁定 auth profile 的 scan 先跑 preflight（§16.5）：預設等 fake 的容器。"""

    def find() -> str | None:
        names = scan_containers(scan_id, engine)
        return names[0] if names else None

    return wait_for(find, timeout=60)


def test_a_fake_scan_runs_in_a_hardened_isolated_container(target: Scannable) -> None:
    scan_id = target.scan()
    name = _running_container(scan_id)
    info = inspect(name)
    host = info["HostConfig"]

    assert info["Config"]["User"] == "10001:10001"
    assert info["Config"]["Image"] == BUSYBOX
    assert host["Privileged"] is False
    assert host["ReadonlyRootfs"] is True
    assert host["CapDrop"] == ["ALL"]
    assert host["SecurityOpt"] == ["no-new-privileges:true"]
    assert host["NetworkMode"] == SCAN_NET
    assert host["Binds"] in (None, [])
    assert host["PidsLimit"] == 64
    assert host["Memory"] == host["MemorySwap"] == 64 * 1024 * 1024
    assert sorted(
        (mount["Type"], mount["Destination"], mount["RW"]) for mount in _mounts(info)
    ) == [
        ("volume", "/scan/in", False),
        ("volume", "/scan/out", True),
        ("volume", "/scan/secret", False),
    ]
    assert CANARY not in json.dumps(info)
    # proxy 的 token 只在 0400 的檔案中：不在掃描容器的設定、argv、env 與 log（DECISIONS §15.4）。
    token = (
        docker("exec", name, "cat", "/scan/secret/proxy-url").strip().split("@")[0].split(":")[-1]
    )
    assert len(token) == 43
    assert token not in json.dumps(info)
    assert token not in docker("logs", name, check=False)
    # subpath 確實生效：容器只看得到自己的 in/ 與 out/，看不到其他 run 的目錄（審查建議）。
    listing = docker("exec", name, "sh", "-c", "ls -A /scan; echo ---; ls -A /scan/in /scan/secret")
    assert listing.split() == [
        "in",
        "out",
        "secret",
        "---",
        "/scan/in:",
        "run.json",
        "/scan/secret:",
        "auth-header",
        "proxy-url",
        "target-auth",
    ]
    assert host["IpcMode"] == "private"
    assert host["CgroupnsMode"] == "private"
    checks = docker(
        "exec",
        name,
        "sh",
        "-c",
        "stat -c '%a %u' /scan/secret/target-auth /scan/secret/auth-header "
        "/scan/secret/proxy-url; "
        "test -e /var/run/docker.sock && echo socket || echo no-socket; "
        "for host in socket-proxy db api runner; do "
        "nslookup $host >/dev/null 2>&1 && echo resolved || echo unresolved; done; "
        "touch /written 2>/dev/null && echo writable || echo read-only; "
        "ip route | grep -c default",
        check=False,
    ).split()
    assert checks == [
        "400",
        "10001",
        "400",
        "10001",
        "400",
        "10001",
        "no-socket",
        "unresolved",
        "unresolved",
        "unresolved",
        "unresolved",
        "read-only",
        "0",
    ]

    # egress guard（docs/DECISIONS.md §15.7）：執行中有這個 run 的 policy，結束之後刪除。
    run_id = info["Config"]["Labels"]["secscan.run_id"]
    assert f"{run_id}.json" in docker("exec", container("runner"), "ls", "/guard/policies").split()

    wait_for(lambda: target.status(scan_id) == "completed", timeout=60)
    assert scan_containers(scan_id) == []
    assert f"{run_id}.json" not in docker("exec", container("runner"), "ls", "/guard/policies")
    leftover = docker(
        "run",
        "--rm",
        "--network",
        "none",
        "-v",
        f"{SECRETS_VOLUME}:/s:ro",
        BUSYBOX,
        "ls",
        "-A",
        "/s",
    )
    assert leftover.strip() == ""


def test_an_authenticated_scan_runs_the_preflight_through_the_guard(target: Scannable) -> None:
    """preflight 的執行路徑（§16.5）：帶認證與匿名各一次，經 guard 送到 target；收包證據以接收端的
    紀錄為準。用量是 guard 的計數；preflight 的請求不算 coverage。"""
    receiver = start_receiver("preflight", ip=LAB_IP, aliases=(target.host,), port=5000)
    try:
        scan_id = target.scan()
        wait_for(lambda: target.status(scan_id) == "completed", timeout=120)
        scan = target.operator.data("GET", f"/scans/{scan_id}")
        records = receiver.records()
        receiver_logs = docker("logs", receiver.container)
    finally:
        stop_receiver(receiver)

    assert scan["auth"]["preflight"] == "passed"
    assert [(record["method"], record["path"]) for record in records] == [("GET", "/me")] * 2
    assert ["Authorization" in record["header_names"] for record in records] == [True, False]
    assert all(record["host"] == [f"{target.host}:5000"] for record in records)
    assert not any(record["proxy_authorization"] for record in records)
    assert all(record["peer"] == GUARD_LAB_IP for record in records)
    assert CANARY not in receiver_logs
    assert (scan["budget_usage"]["requests_sent"], scan["budget_usage"]["requests_denied"]) == (
        2,
        0,
    )
    coverage = scan["coverage"]
    assert coverage["coverage_measured"] is True
    # preflight 的請求不算 coverage（審查發現）：有量測依據，涵蓋 0 個。
    assert (coverage["observed_operations"], coverage["authenticated_operations"]) == (0, 0)


def test_a_cancel_removes_the_container(target: Scannable) -> None:
    scan_id = target.scan()
    _running_container(scan_id)

    status, _ = target.operator.call("POST", f"/scans/{scan_id}/cancel")

    assert status == 202
    wait_for(lambda: scan_containers(scan_id) == [], timeout=30)
    wait_for(lambda: target.status(scan_id) == "cancelled", timeout=30)


def test_the_canary_secret_never_reaches_logs_or_container_settings() -> None:
    names = docker(
        "ps",
        "-a",
        "--filter",
        f"label=com.docker.compose.project={container('db')[: -len('-db-1')]}",
        "--format",
        "{{.Names}}",
    ).split()

    assert names
    for name in names:
        logs = docker("logs", name, check=False)
        assert CANARY not in logs
        assert CANARY not in json.dumps(inspect(name))


def test_the_secrets_volume_is_in_memory() -> None:
    """secret 的 volume 是 tmpfs：刪除之後不會留在磁碟上。"""
    [volume] = json.loads(docker("volume", "inspect", SECRETS_VOLUME))

    assert volume["Options"]["type"] == "tmpfs"
