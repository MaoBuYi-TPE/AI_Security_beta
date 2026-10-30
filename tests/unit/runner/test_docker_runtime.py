"""經 socket-proxy 操作容器（docs/DECISIONS.md §14.2）：送出的請求逐一正確、從不 pull。

以假的 adapter 取代 Docker SDK 的 HTTP 傳輸，確認實際的 method、path、query 與 body。
"""

from collections.abc import Callable
from uuid import UUID

import pytest
import requests

from secscan.runner.docker_runtime import API_VERSION, DockerRuntime
from secscan.runner.domain.admission import build_container
from secscan.runner.domain.runtime import (
    ContainerConflictError,
    ContainerState,
    EngineVersion,
    NetworkState,
    RuntimeUnavailableError,
)
from tests.unit.runner.docker_stub import StubDocker
from tests.unit.runner.plans import POLICY, RUN_ID, fake_plan

NAME = f"secscan-run-{RUN_ID}"
PREFIX = f"/v{API_VERSION}"
IMAGE = str(fake_plan().image)


@pytest.fixture
def docker_api() -> StubDocker:
    return StubDocker()


@pytest.fixture
def runtime(docker_api: StubDocker) -> DockerRuntime:
    return DockerRuntime.connect("tcp://socket-proxy.invalid:2375", adapter=docker_api)


def test_the_api_version_is_pinned() -> None:
    assert API_VERSION == "1.45"


def test_create_sends_the_checked_body_as_is(
    runtime: DockerRuntime, docker_api: StubDocker
) -> None:
    spec = build_container(fake_plan(target_auth=True), policy=POLICY)
    docker_api.reply("POST", f"{PREFIX}/containers/create", 201, {"Id": "abc", "Warnings": []})

    runtime.create(spec)

    (request,) = docker_api.requests_seen
    assert (request.method, request.path) == ("POST", f"{PREFIX}/containers/create")
    assert request.query == {"name": NAME}
    assert request.body == spec.body


def test_a_name_conflict_is_reported(runtime: DockerRuntime, docker_api: StubDocker) -> None:
    docker_api.reply("POST", f"{PREFIX}/containers/create", 409, {"message": "Conflict"})

    with pytest.raises(ContainerConflictError):
        runtime.create(build_container(fake_plan(), policy=POLICY))


def test_a_missing_image_is_not_pulled(runtime: DockerRuntime, docker_api: StubDocker) -> None:
    docker_api.reply("POST", f"{PREFIX}/containers/create", 404, {"message": "No such image"})

    with pytest.raises(RuntimeUnavailableError):
        runtime.create(build_container(fake_plan(), policy=POLICY))

    assert docker_api.paths == [("POST", f"{PREFIX}/containers/create")]


def test_start_stop_and_remove_address_the_container_by_name(
    runtime: DockerRuntime, docker_api: StubDocker
) -> None:
    docker_api.reply("POST", f"{PREFIX}/containers/{NAME}/start", 204)
    docker_api.reply("POST", f"{PREFIX}/containers/{NAME}/stop", 204)
    docker_api.reply("DELETE", f"{PREFIX}/containers/{NAME}", 204)

    runtime.start(NAME)
    runtime.stop(NAME, grace_seconds=5)
    runtime.remove(NAME)

    assert docker_api.paths == [
        ("POST", f"{PREFIX}/containers/{NAME}/start"),
        ("POST", f"{PREFIX}/containers/{NAME}/stop"),
        ("DELETE", f"{PREFIX}/containers/{NAME}"),
    ]
    assert docker_api.requests_seen[1].query == {"t": "5"}
    # 強制刪除，連同映像宣告的匿名 volume（審查建議：M3 的映像可能有 VOLUME）。
    assert docker_api.requests_seen[2].query["force"] == "True"
    assert docker_api.requests_seen[2].query["v"] == "True"


@pytest.mark.parametrize("status", [304, 404])
def test_stopping_a_stopped_or_missing_container_is_fine(
    runtime: DockerRuntime, docker_api: StubDocker, status: int
) -> None:
    docker_api.reply("POST", f"{PREFIX}/containers/{NAME}/stop", status)

    runtime.stop(NAME, grace_seconds=5)


def test_removing_a_missing_container_is_fine(runtime: DockerRuntime) -> None:
    runtime.remove(NAME)


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        ({"Status": "created"}, ContainerState(running=True, exit_code=None, oom_killed=False)),
        ({"Status": "running"}, ContainerState(running=True, exit_code=None, oom_killed=False)),
        (
            {"Status": "exited", "ExitCode": 0, "OOMKilled": False},
            ContainerState(running=False, exit_code=0, oom_killed=False),
        ),
        (
            {"Status": "exited", "ExitCode": 137, "OOMKilled": True},
            ContainerState(running=False, exit_code=137, oom_killed=True),
        ),
        (
            {"Status": "dead", "ExitCode": 1, "OOMKilled": False},
            ContainerState(running=False, exit_code=1, oom_killed=False),
        ),
    ],
)
def test_state(
    runtime: DockerRuntime,
    docker_api: StubDocker,
    state: dict[str, object],
    expected: ContainerState,
) -> None:
    payload = {"State": state, "Config": {"Labels": {}}}
    docker_api.reply("GET", f"{PREFIX}/containers/{NAME}/json", 200, payload)

    assert runtime.state(NAME) == expected


LABELED_RUN = "6f1c2d3e-4b5a-4c6d-8e7f-001122334455"


@pytest.mark.parametrize(
    ("config", "run_label"),
    [
        ({"Labels": {"secscan.managed": "true", "secscan.run_id": LABELED_RUN}}, LABELED_RUN),
        ({"Labels": {"secscan.managed": "false", "secscan.run_id": LABELED_RUN}}, None),
        ({"Labels": {"secscan.run_id": LABELED_RUN}}, None),
        ({"Labels": {"secscan.managed": "true", "secscan.run_id": "not-a-uuid"}}, None),
        ({"Labels": {"secscan.managed": "true", "secscan.run_id": LABELED_RUN.upper()}}, None),
        ({"Labels": {"secscan.managed": "true", "secscan.run_id": 7}}, None),
        ({"Labels": None}, None),
        ({}, None),
    ],
)
def test_state_reads_the_run_label(
    runtime: DockerRuntime, docker_api: StubDocker, config: object, run_label: str | None
) -> None:
    """對帳以 label 核對容器是不是這個 run 的（docs/DECISIONS.md §17.2）；格式不符就是 None。"""
    payload = {"State": {"Status": "running"}, "Config": config}
    docker_api.reply("GET", f"{PREFIX}/containers/{NAME}/json", 200, payload)

    state = runtime.state(NAME)

    assert state is not None
    assert state.run_label == (UUID(run_label) if run_label is not None else None)


@pytest.mark.parametrize(
    "payload", [{"State": {"Status": "running"}}, {"State": {"Status": "running"}, "Config": None}]
)
def test_state_without_the_config_is_a_malformed_reply(
    runtime: DockerRuntime, docker_api: StubDocker, payload: dict[str, object]
) -> None:
    """真的 Docker 一定回傳 Config：缺少時不能當成「不是我們的容器」而結算。"""
    docker_api.reply("GET", f"{PREFIX}/containers/{NAME}/json", 200, payload)

    with pytest.raises(RuntimeUnavailableError):
        runtime.state(NAME)


def test_state_of_a_missing_container(runtime: DockerRuntime) -> None:
    assert runtime.state(NAME) is None


def test_version(runtime: DockerRuntime, docker_api: StubDocker) -> None:
    docker_api.reply(
        "GET",
        f"{PREFIX}/version",
        200,
        {"ApiVersion": "1.54", "MinAPIVersion": "1.40", "Os": "linux", "Arch": "arm64"},
    )

    assert runtime.version() == EngineVersion(
        api_version="1.54", min_api_version="1.40", os="linux", arch="arm64"
    )


def test_image_architecture(runtime: DockerRuntime, docker_api: StubDocker) -> None:
    docker_api.reply("GET", f"{PREFIX}/images/{IMAGE}/json", 200, {"Architecture": "arm64"})

    assert runtime.image_architecture(IMAGE) == "arm64"
    assert runtime.image_architecture("busybox:9.9@sha256:" + "0" * 64) is None


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (
            {
                "Internal": True,
                "Options": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"},
            },
            NetworkState(internal=True, isolated_gateway=True),
        ),
        ({"Internal": True, "Options": {}}, NetworkState(internal=True, isolated_gateway=False)),
        ({"Internal": False}, NetworkState(internal=False, isolated_gateway=False)),
    ],
)
def test_network(
    runtime: DockerRuntime,
    docker_api: StubDocker,
    payload: dict[str, object],
    expected: NetworkState,
) -> None:
    docker_api.reply("GET", f"{PREFIX}/networks/secscan_scan_net", 200, payload)

    assert runtime.network("secscan_scan_net") == expected
    assert runtime.network("other_net") is None


def test_volume_exists(runtime: DockerRuntime, docker_api: StubDocker) -> None:
    docker_api.reply("GET", f"{PREFIX}/volumes/secscan_runs", 200, {"Name": "secscan_runs"})

    assert runtime.volume_exists("secscan_runs")
    assert not runtime.volume_exists("secscan_run_secrets")


@pytest.mark.parametrize("status", [403, 500])
def test_refusals_and_errors_become_runtime_unavailable(
    runtime: DockerRuntime, docker_api: StubDocker, status: int
) -> None:
    docker_api.reply("POST", f"{PREFIX}/containers/{NAME}/start", status, {"message": "secret?"})

    with pytest.raises(RuntimeUnavailableError) as caught:
        runtime.start(NAME)

    assert "secret?" not in str(caught.value)
    assert str(status) in str(caught.value)


@pytest.mark.parametrize(
    "error", [requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout]
)
def test_connection_failures_become_runtime_unavailable(
    runtime: DockerRuntime, docker_api: StubDocker, error: type[Exception]
) -> None:
    docker_api.fail_with = error

    with pytest.raises(RuntimeUnavailableError):
        runtime.state(NAME)
    with pytest.raises(RuntimeUnavailableError):
        runtime.version()


def test_proxies_from_the_environment_are_ignored(
    monkeypatch: pytest.MonkeyPatch, docker_api: StubDocker
) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://attacker.invalid:3128")
    runtime = DockerRuntime.connect("tcp://socket-proxy.invalid:2375", adapter=docker_api)

    assert runtime.state(NAME) is None
    assert not runtime.trusts_environment


@pytest.mark.parametrize("url", ["tcp://socket-proxy:2375", "unix:///var/run/docker.sock"])
def test_connecting_does_not_call_the_daemon(url: str) -> None:
    """版本固定：建立 client 不呼叫 daemon（unit 測試連不到任何 daemon）。"""
    runtime = DockerRuntime.connect(url)

    assert not runtime.trusts_environment


@pytest.mark.parametrize(
    "url",
    [
        "",
        "http://socket-proxy:2375",
        "ssh://host",
        "npipe:////./pipe/docker",
        "tcp://",
        "tcp://host",
        "tcp://host:port",
        "tcp://a/b:1",
        "unix:///",
        "unix://relative.sock",
    ],
)
def test_only_tcp_and_unix_urls_are_accepted(url: str) -> None:
    with pytest.raises(ValueError, match="tcp"):
        DockerRuntime.connect(url)


@pytest.mark.parametrize(
    ("method", "path", "payload", "call"),
    [
        ("GET", f"{PREFIX}/version", {"ApiVersion": "1.54"}, "version"),
        ("GET", f"{PREFIX}/containers/{NAME}/json", {"Id": "x"}, "state"),
        ("GET", f"{PREFIX}/containers/{NAME}/json", {"State": {"Status": "exited"}}, "state"),
        ("GET", f"{PREFIX}/containers/{NAME}/json", {"State": "running"}, "state"),
        ("GET", f"{PREFIX}/images/{IMAGE}/json", {"Os": "linux"}, "image"),
        ("GET", f"{PREFIX}/networks/secscan_scan_net", ["not", "an", "object"], "network"),
    ],
)
def test_malformed_responses_become_runtime_unavailable(
    runtime: DockerRuntime,
    docker_api: StubDocker,
    method: str,
    path: str,
    payload: object,
    call: str,
) -> None:
    """格式不符的回應不會變成未攔截的 KeyError，讓 runner 結束（審查發現）。"""
    docker_api.reply(method, path, 200, payload)
    calls: dict[str, Callable[[], object]] = {
        "version": runtime.version,
        "state": lambda: runtime.state(NAME),
        "image": lambda: runtime.image_architecture(IMAGE),
        "network": lambda: runtime.network("secscan_scan_net"),
    }

    with pytest.raises(RuntimeUnavailableError, match="格式"):
        calls[call]()
