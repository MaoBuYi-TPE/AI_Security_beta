"""部署設定的靜態檢查（TASKS T10 的 DoD、docs/DECISIONS.md §14.1、§14.8）。

- api、worker（與 runner）沒有 Docker socket、不是 privileged；只有 socket-proxy 掛 docker.sock。
- socket-proxy 只放行掃描容器需要的 API：以相同的語意（自動加 ^$、只比對 path）核對對照表。
- 映像都以 digest 鎖定；只發布 127.0.0.1 的 port；網路是 internal。
實際的行為另以 live 測試確認（tests/live/）。
"""

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from secscan.runner.domain.policy import ENGINE_POLICIES

ROOT = Path(__file__).resolve().parents[2]
COMPOSE: dict[str, Any] = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
SERVICES: dict[str, dict[str, Any]] = COMPOSE["services"]
APP_SERVICES = ("api", "runner", "worker")
HARDENED = (*APP_SERVICES, "socket-proxy")
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


@pytest.mark.parametrize("name", APP_SERVICES)
def test_app_services_have_no_host_paths(name: str) -> None:
    for volume in _volumes(SERVICES[name]):
        assert not volume.startswith(("/", ".", "~"))


@pytest.mark.parametrize("name", sorted(SERVICES))
def test_images_are_pinned_or_built_here(name: str) -> None:
    service = SERVICES[name]
    if "build" in service:
        assert str(service["image"]).startswith("secscan:")
    else:
        assert "@sha256:" in service["image"]


def test_networks_separate_the_processes() -> None:
    networks = COMPOSE["networks"]

    assert networks["control_net"]["internal"] is True
    assert networks["docker_net"]["internal"] is True
    assert networks["scan_net"]["external"] is True
    assert SERVICES["socket-proxy"]["networks"] == ["docker_net"]
    assert SERVICES["runner"]["networks"] == ["control_net", "docker_net"]
    assert SERVICES["worker"]["networks"] == ["control_net"]
    assert SERVICES["api"]["networks"] == ["default", "control_net"]
    # 掃描容器的網路上沒有任何常駐服務（T11 的 guard 之前）。
    assert all("scan_net" not in service.get("networks", []) for service in SERVICES.values())


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
    approved = sorted(image for policy in ENGINE_POLICIES.values() for image in policy.images)

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
