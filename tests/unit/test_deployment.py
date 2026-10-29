"""部署設定的靜態檢查（TASKS T10 的 DoD、docs/DECISIONS.md §14.1、§14.8）。

- api、worker（與 runner）沒有 Docker socket、不是 privileged；只有 socket-proxy 掛 docker.sock。
- socket-proxy 只放行掃描容器需要的 API：以相同的語意（自動加 ^$、只比對 path）核對對照表。
- 映像都以 digest 鎖定；只發布 127.0.0.1 的 port；網路是 internal。
實際的行為另以 live 測試確認（tests/live/）。
"""

import re
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Any

import pytest
import yaml

from secscan.guard.config import GUARD_PORT
from secscan.runner.config import RunnerSettings
from secscan.runner.domain.policy import ENGINE_POLICIES, ContainerPolicy
from secscan.targets.domain import LabNetwork
from secscan.worker.config import WorkerSettings

ROOT = Path(__file__).resolve().parents[2]
COMPOSE: dict[str, Any] = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
SERVICES: dict[str, dict[str, Any]] = COMPOSE["services"]
APP_SERVICES = ("api", "runner", "worker")
HARDENED = (*APP_SERVICES, "socket-proxy", "guard")
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")
RUN = "secscan-run-6f1c2d3e-4b5a-4c6d-8e7f-001122334455"
IMAGE = "busybox:1.38.0@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e"
_DEFAULT = re.compile(r"\$\{[A-Z_]+:-([^}]*)\}")


def _volumes(service: dict[str, Any]) -> list[str]:
    return [str(volume) for volume in service.get("volumes", [])]


def test_only_the_socket_proxy_mounts_the_docker_socket() -> None:
    mounts = {
        name: [volume for volume in _volumes(service) if "docker.sock" in volume]
        for name, service in SERVICES.items()
    }

    assert {name for name, found in mounts.items() if found} == {"socket-proxy"}
    assert mounts["socket-proxy"] == ["/var/run/docker.sock:/var/run/docker.sock:ro"]


@pytest.mark.parametrize("name", sorted(SERVICES))
def test_no_service_is_privileged(name: str) -> None:
    service = SERVICES[name]

    assert service.get("privileged", False) is False
    for key in ("cap_add", "devices", "network_mode", "pid", "ipc", "userns_mode"):
        assert key not in service


@pytest.mark.parametrize("name", HARDENED)
def test_app_services_are_hardened(name: str) -> None:
    service = SERVICES[name]

    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in service["security_opt"]
    uid, _gid = str(service["user"]).split(":")
    assert int(uid) != 0
    assert "mem_limit" in service
    assert "pids_limit" in service


@pytest.mark.parametrize("name", [*APP_SERVICES, "guard"])
def test_app_services_have_no_host_paths(name: str) -> None:
    for volume in _volumes(SERVICES[name]):
        assert not volume.startswith(("/", ".", "~"))


@pytest.mark.parametrize("name", sorted(SERVICES))
def test_images_are_pinned_or_built_here(name: str) -> None:
    service = SERVICES[name]
    if str(service["image"]).startswith(("secscan:", "secscan-guard:")):
        # 本機建立的映像：不從 registry pull（同名的映像不會被換成別人的）。
        assert service["pull_policy"] == "never"
    else:
        assert "@sha256:" in service["image"]


def test_only_the_app_and_the_guard_images_are_built_here() -> None:
    builders = {name: service["build"] for name, service in SERVICES.items() if "build" in service}

    assert set(builders) == {"api", "guard"}
    assert builders["guard"] == {"context": ".", "dockerfile": "deploy/guard/Dockerfile"}
    assert str(SERVICES["guard"]["image"]).startswith("secscan-guard:")


def test_networks_separate_the_processes() -> None:
    networks = COMPOSE["networks"]

    assert networks["control_net"]["internal"] is True
    assert networks["docker_net"]["internal"] is True
    assert networks["scan_net"]["external"] is True
    assert SERVICES["socket-proxy"]["networks"] == ["docker_net"]
    assert SERVICES["runner"]["networks"] == ["control_net", "docker_net"]
    assert SERVICES["worker"]["networks"] == ["control_net"]
    assert SERVICES["api"]["networks"] == ["default", "control_net"]
    # 掃描容器與靶機的網路上，只有 egress guard（docs/DECISIONS.md §15.6）。
    for network in ("scan_net", "lab_net"):
        assert networks[network]["external"] is True
        users = {
            name for name, service in SERVICES.items() if network in service.get("networks", [])
        }
        assert users == {"guard"}


def test_published_ports_are_loopback_only() -> None:
    published = {
        name: [str(port) for port in service.get("ports", [])]
        for name, service in SERVICES.items()
        if service.get("ports")
    }

    assert set(published) == {"db", "db-test", "api"}
    assert all(port.startswith("127.0.0.1:") for ports in published.values() for port in ports)


def _allowlist() -> dict[str, re.Pattern[str]]:
    rules: dict[str, re.Pattern[str]] = {}
    for argument in SERVICES["socket-proxy"]["command"]:
        flag, _, value = str(argument).partition("=")
        if flag.startswith("-allow") and flag[len("-allow") :].isupper():
            # compose 以預設值展開 ${VAR:-default}；socket-proxy 自動加上 ^ 與 $。
            rules[flag[len("-allow") :]] = re.compile(_DEFAULT.sub(r"\1", value))
    return rules


ALLOWED = [
    ("GET", "/v1.45/version"),
    ("GET", f"/v1.45/containers/{RUN}/json"),
    ("GET", f"/v1.45/images/{IMAGE}/json"),
    ("GET", "/v1.45/networks/secscan_scan_net"),
    ("GET", "/v1.45/volumes/secscan_runs"),
    ("GET", "/v1.45/volumes/secscan_run_secrets"),
    ("POST", "/v1.45/containers/create"),
    ("POST", f"/v1.45/containers/{RUN}/start"),
    ("POST", f"/v1.45/containers/{RUN}/stop"),
    ("DELETE", f"/v1.45/containers/{RUN}"),
]
DENIED = [
    ("GET", "/v1.45/info"),
    ("GET", "/v1.45/containers/json"),
    ("GET", "/v1.45/containers/secscan-db-1/json"),
    ("POST", "/v1.45/containers/secscan-db-1/stop"),
    ("DELETE", "/v1.45/containers/secscan-api-1"),
    ("POST", f"/v1.45/containers/{RUN}/exec"),
    ("POST", "/v1.45/exec/abc/start"),
    ("PUT", f"/v1.45/containers/{RUN}/archive"),
    ("GET", f"/v1.45/containers/{RUN}/archive"),
    ("GET", f"/v1.45/containers/{RUN}/logs"),
    ("POST", f"/v1.45/containers/{RUN}/kill"),
    ("POST", f"/v1.45/containers/{RUN}/restart"),
    ("POST", "/v1.45/images/create"),
    ("POST", "/v1.45/build"),
    ("POST", "/v1.45/networks/create"),
    ("POST", "/v1.45/networks/secscan_scan_net/connect"),
    ("POST", "/v1.45/volumes/create"),
    ("GET", "/v1.45/volumes"),
    ("GET", "/v1.45/volumes/secscan_db_data"),
    ("GET", "/v1.45/networks/bridge"),
    ("GET", "/v1.45/images/busybox:latest/json"),
    ("GET", "/v1.45/secrets"),
    ("GET", "/v1.45/swarm"),
    ("GET", "/v1.45/system/df"),
    ("GET", "/v1.45/events"),
    ("GET", "/v1.45/version/../info"),
    # 路徑穿越：映像的規則不能讓 /、.. 通過（審查發現：原本放行到 /distribution、/exec）。
    ("GET", f"/v1.45/images/x/../../distribution/evil.example/y:t@sha256:{'0' * 64}/json"),
    ("GET", f"/v1.45/images/a/../../exec/abc:t@sha256:{'0' * 64}/json"),
    ("GET", f"/v1.45/images/busybox:1.38.0@sha256:{'0' * 64}/json"),
    ("GET", "/v1.45/images/busybox:1x38x0@sha256:" + IMAGE.split("@sha256:")[1] + "/json"),
    ("GET", f"/v1.45/containers/{RUN}/../secscan-db-1/json"),
    ("POST", "/v1.45/containers/secscan-run-x/start"),
    ("HEAD", "/v1.45/version"),
]


@pytest.mark.parametrize(("method", "path"), ALLOWED)
def test_the_proxy_allows_what_the_runner_needs(method: str, path: str) -> None:
    assert _allowlist()[method].fullmatch(path)


@pytest.mark.parametrize(("method", "path"), DENIED)
def test_the_proxy_denies_everything_else(method: str, path: str) -> None:
    rule = _allowlist().get(method)

    assert rule is None or rule.fullmatch(path) is None


def test_the_proxy_rejects_host_binds_and_unknown_clients() -> None:
    command = [str(argument) for argument in SERVICES["socket-proxy"]["command"]]

    assert "-allowfrom=runner" in command
    [binds] = [argument for argument in command if argument.startswith("-allowbindmountfrom=")]
    assert binds.startswith("-allowbindmountfrom=/nonexistent")
    assert "-stoponwatchdog" in command
    assert set(_allowlist()) == {"GET", "POST", "DELETE"}


def test_the_makefile_pulls_exactly_the_approved_images() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    [line] = [line for line in makefile.splitlines() if line.startswith("SCANNER_IMAGES :=")]
    # fake 與 preflight 共用同一個 busybox：每個映像只 pull 一次。
    approved = sorted({image for policy in ENGINE_POLICIES.values() for image in policy.images})

    assert sorted(line.split(":=", 1)[1].split()) == approved


def test_the_image_runs_as_non_root_from_pinned_bases() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines()
    bases = [line for line in dockerfile if line.startswith("FROM ")]

    assert bases
    assert all("@sha256:" in line for line in bases)
    assert [line for line in dockerfile if line.startswith("USER ")] == ["USER 10001:10001"]


def test_the_build_context_excludes_everything_but_the_source() -> None:
    lines = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    rules = [line for line in lines if line and not line.startswith("#")]

    assert rules[0] == "*"
    assert {"!pyproject.toml", "!uv.lock", "!src/"} <= set(rules)
    assert not any(".env" in rule for rule in rules if rule.startswith("!"))


def test_the_proxy_allows_exactly_the_approved_images() -> None:
    """映像的規則是核准清單的逐字比對（. 已跳脫），不是通式。"""
    approved = sorted(image for policy in ENGINE_POLICIES.values() for image in policy.images)
    rule = _allowlist()["GET"]

    for image in approved:
        assert rule.fullmatch(f"/v1.45/images/{image}/json")
    assert all(re.escape(image) in rule.pattern for image in approved)


def test_names_in_the_proxy_rules_are_literal() -> None:
    """compose 內插到 regex 的名稱（scan_net、兩個 volume）不能有 regex 的特殊字元。"""
    command = " ".join(str(argument) for argument in SERVICES["socket-proxy"]["command"])
    defaults = _DEFAULT.findall(command)

    assert defaults
    for name in defaults:
        assert ContainerPolicy(scan_network=name, runs_volume=name, secrets_volume=name)
        assert re.escape(name) == name


def test_secrets_live_only_in_memory() -> None:
    """secret 的 volume 是 tmpfs：刪除檔案之後不會留在磁碟上（審查建議）。"""
    volume = COMPOSE["volumes"]["run_secrets"]

    assert volume["driver_opts"]["type"] == "tmpfs"
    assert volume["driver_opts"]["device"] == "tmpfs"
    options = dict(item.split("=", 1) for item in volume["driver_opts"]["o"].split(","))
    assert options == {"size": "1m", "uid": "10001", "gid": "10001", "mode": "0700"}


# --- egress guard（docs/DECISIONS.md §15）---------------------------------------------------


def _default(value: object) -> str:
    """compose 的 ${VAR:-default} 以預設值展開。"""
    return _DEFAULT.sub(r"\1", str(value))


def _make(name: str) -> str:
    [line] = [line for line in MAKEFILE.splitlines() if re.match(rf"{name}\s*\??:?=", line)]
    return line.split("=", 1)[1].strip()


def test_the_guard_sits_only_on_the_scan_and_lab_networks_at_fixed_addresses() -> None:
    guard = SERVICES["guard"]
    networks = guard["networks"]

    assert set(networks) == {"scan_net", "lab_net"}
    scan_ip = IPv4Address(_default(networks["scan_net"]["ipv4_address"]))
    lab_ip = IPv4Address(_default(networks["lab_net"]["ipv4_address"]))
    scan_net, lab_net = IPv4Network(_make("SCAN_SUBNET")), IPv4Network(_make("LAB_SUBNET"))
    assert scan_ip == scan_net.broadcast_address - 1
    assert lab_ip == LabNetwork(lab_net).guard_address
    assert scan_ip not in IPv4Network(_make("SCAN_IP_RANGE"))
    assert lab_ip not in IPv4Network(_make("LAB_IP_RANGE"))
    environment = {key: _default(value) for key, value in guard["environment"].items()}
    assert environment == {
        "LAB_CIDR": str(lab_net),
        "GUARD_SCAN_CIDR": str(scan_net),
        "GUARD_SCAN_IP": str(scan_ip),
        "GUARD_LAB_IP": str(lab_ip),
    }
    assert "ports" not in guard
    assert "expose" not in guard


def test_the_runner_points_at_the_guard() -> None:
    runner = {key: _default(value) for key, value in SERVICES["runner"]["environment"].items()}
    guard_ip = _default(SERVICES["guard"]["networks"]["scan_net"]["ipv4_address"])
    defaults = RunnerSettings()

    assert runner["RUNNER_GUARD_PROXY"] == f"{guard_ip}:{GUARD_PORT}"
    assert defaults.guard_proxy == runner["RUNNER_GUARD_PROXY"]
    assert str(defaults.guard_policies_dir) in _volumes(SERVICES["runner"])[2]
    assert str(defaults.guard_status_dir) in _volumes(SERVICES["runner"])[3]
    assert str(defaults.guard_telemetry_dir) in _volumes(SERVICES["runner"])[4]


def test_policies_flow_from_the_runner_to_the_guard_and_status_back() -> None:
    """policy：runner 讀寫、guard 唯讀；status：guard 讀寫、runner 唯讀；telemetry：guard 讀寫、
    runner 與 worker 唯讀；其他服務（含掃描容器）都不掛。"""
    mounts = {
        name: [volume for volume in _volumes(service) if volume.startswith("guard_")]
        for name, service in SERVICES.items()
    }

    assert {name for name, found in mounts.items() if found} == {"runner", "guard", "worker"}
    assert mounts["runner"] == [
        "guard_policies:/guard/policies",
        "guard_status:/guard/status:ro",
        "guard_telemetry:/guard/telemetry:ro",
    ]
    assert mounts["guard"] == [
        "guard_policies:/guard/policies:ro",
        "guard_status:/guard/status",
        "guard_telemetry:/guard/telemetry",
    ]
    assert mounts["worker"] == ["guard_telemetry:/guard/telemetry:ro"]


def test_the_guard_writes_telemetry_where_the_runner_reads_it() -> None:
    guard = {key: _default(value) for key, value in SERVICES["guard"]["environment"].items()}

    assert guard.get("GUARD_TELEMETRY_DIR", "/guard/telemetry") == "/guard/telemetry"
    assert str(RunnerSettings().guard_telemetry_dir) == "/guard/telemetry"


@pytest.mark.parametrize("volume", ["guard_policies", "guard_status", "guard_telemetry"])
def test_guard_volumes_live_only_in_memory(volume: str) -> None:
    options = COMPOSE["volumes"][volume]["driver_opts"]

    assert (options["type"], options["device"]) == ("tmpfs", "tmpfs")
    items = options["o"].split(",")
    parsed = dict(item.split("=", 1) for item in items if "=" in item)
    assert (parsed["uid"], parsed["gid"], parsed["mode"]) == ("10001", "10001", "0700")
    if volume == "guard_telemetry":  # 只有資料，不需要執行、setuid 或裝置檔（審查建議）
        assert {"noexec", "nosuid", "nodev"} <= set(items)


def test_the_guard_keeps_its_scratch_space_in_memory_and_is_health_checked() -> None:
    guard = SERVICES["guard"]

    targets = [str(entry).split(":", 1)[0] for entry in guard["tmpfs"]]
    assert targets == ["/tmp", "/home/mitmproxy/.mitmproxy"]  # noqa: S108
    assert guard["healthcheck"]["test"] == [
        "CMD",
        "python3",
        "-I",
        "-B",
        "/opt/secscan-guard/run_guard.py",
        "--check",
    ]
    assert guard["restart"] == "unless-stopped"


@pytest.mark.parametrize(
    ("network", "subnet", "ip_range"),
    [
        ("SCAN_NET", "SCAN_SUBNET", "SCAN_IP_RANGE"),
        ("LAB_NET", "LAB_SUBNET", "LAB_IP_RANGE"),
        ("LIVE_SCAN_NET", "LIVE_SCAN_SUBNET", "LIVE_SCAN_IP_RANGE"),
        ("LIVE_LAB_NET", "LIVE_LAB_SUBNET", "LIVE_LAB_IP_RANGE"),
    ],
)
def test_networks_reserve_the_upper_half_for_fixed_addresses(
    network: str, subnet: str, ip_range: str
) -> None:
    """動態配發只在下半段：guard 停機時，掃描容器也拿不到 guard 的 IP（§15.6）。"""
    whole, dynamic = IPv4Network(_make(subnet)), IPv4Network(_make(ip_range))

    assert _make(network)
    assert dynamic.subnet_of(whole)
    assert dynamic.prefixlen == whole.prefixlen + 1
    assert dynamic.network_address == whole.network_address


def test_networks_are_created_internal_isolated_and_with_an_ip_range() -> None:
    [create] = [line for line in MAKEFILE.splitlines() if "docker network create" in line]

    for flag in ("--internal", "gateway_mode_ipv4=isolated", "--subnet", "--ip-range"):
        assert flag in create
    for target in ("scan-net:", "lab-net:"):
        assert any(line.startswith(target) for line in MAKEFILE.splitlines())


def test_the_lab_compose_file_uses_the_shared_lab_network() -> None:
    lab: dict[str, Any] = yaml.safe_load((ROOT / "compose.lab.yaml").read_text(encoding="utf-8"))

    assert lab["networks"]["lab_net"] == {
        "name": "${SECSCAN_LAB_NET:-secscan_lab_net}",
        "external": True,
    }


def test_the_guard_build_context_is_allowed() -> None:
    lines = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()

    assert "!deploy/guard/" in lines


def test_guard_logs_are_rotated() -> None:
    """每個請求一行 log：被拒的請求不計預算，log 必須有大小上限（審查發現）。"""
    logging = SERVICES["guard"]["logging"]

    assert logging["driver"] == "json-file"
    assert logging["options"] == {"max-size": "10m", "max-file": "3"}


def test_the_worker_reads_collected_runs_read_only() -> None:
    """preflight 的回應由 worker 判斷（DECISIONS §16.5）：runs 唯讀，不碰 secret 與 guard。"""
    worker = SERVICES["worker"]

    assert _volumes(worker) == ["runs:/runs:ro", "guard_telemetry:/guard/telemetry:ro"]
    assert str(WorkerSettings().runs_dir) == "/runs"
    assert str(WorkerSettings().telemetry_dir) == "/guard/telemetry"
    assert worker["networks"] == ["control_net"]
