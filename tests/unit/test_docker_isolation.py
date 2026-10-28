"""測試程序連不到 Docker daemon（TASKS T10 的 DoD、docs/DECISIONS.md §14.9）。

pytest-socket 必須整個放行 AF_UNIX（asyncio 需要），所以另外限制 AF_UNIX 的 connect、把 DOCKER_HOST
指向不存在的 socket，並禁止沒有標記 live 的測試使用 enable_socket。
"""

import os
import shutil
import socket
import subprocess
from pathlib import Path

import docker
import pytest

from tests.isolation import BLOCKED_DOCKER_HOST, LIVE_SWITCH, UnixSocketBlockedError

DOCKER_SOCKET = "/var/run/docker.sock"
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _unix_client() -> socket.socket:
    return socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)


@pytest.mark.parametrize("address", [DOCKER_SOCKET, DOCKER_SOCKET.encode(), "\0secscan-abstract"])
def test_unix_socket_outside_the_test_directory_is_blocked(address: str | bytes) -> None:
    with _unix_client() as client, pytest.raises(UnixSocketBlockedError):
        client.connect(address)


def test_connect_ex_is_blocked_too() -> None:
    with _unix_client() as client, pytest.raises(UnixSocketBlockedError):
        client.connect_ex(DOCKER_SOCKET)


def test_a_relative_path_out_of_the_test_directory_is_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    with _unix_client() as client, pytest.raises(UnixSocketBlockedError):
        client.connect("../../outside.sock")


def test_a_symlink_out_of_the_test_directory_is_blocked(tmp_path: Path) -> None:
    link = tmp_path / "d.sock"
    link.symlink_to(DOCKER_SOCKET)

    with _unix_client() as client, pytest.raises(UnixSocketBlockedError):
        client.connect(str(link))


def test_unix_socket_inside_the_test_directory_works(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    # 短的目錄名稱：macOS 的 AF_UNIX 路徑最多 104 bytes，tmp_path 含測試名稱會超過。
    path = str(tmp_path_factory.mktemp("u") / "s.sock")
    with _unix_client() as server:
        server.bind(path)
        server.listen(1)
        with _unix_client() as client:
            client.connect(path)
            accepted, _ = server.accept()
            accepted.close()


def test_docker_settings_point_nowhere() -> None:
    assert os.environ["DOCKER_HOST"] == BLOCKED_DOCKER_HOST
    for name in ("DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
        assert name not in os.environ


def test_the_docker_sdk_cannot_reach_a_daemon() -> None:
    with pytest.raises(docker.errors.DockerException):
        docker.from_env()


def test_the_docker_cli_cannot_reach_a_daemon() -> None:
    cli = shutil.which("docker")
    if cli is None:
        pytest.skip("沒有安裝 docker CLI")
    # 執行的是固定的指令，沒有外部輸入；環境變數沿用測試的（DOCKER_HOST 指向不存在的 socket）。
    result = subprocess.run(  # noqa: S603
        [cli, "version", "--format", "{{.Server.Version}}"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert result.returncode != 0
    assert result.stdout.strip() == ""


_ENABLE_SOCKET_MARKER = """
import pytest

@pytest.mark.enable_socket
def test_wants_the_network():
    pass
"""

_SOCKET_ENABLED_FIXTURE = """
def test_wants_the_network(socket_enabled):
    pass
"""

_LIVE_TEST = """
import pytest

@pytest.mark.live
@pytest.mark.enable_socket
def test_live(tmp_path):
    import socket
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        try:
            client.connect("/nonexistent/secscan-live.sock")
        except FileNotFoundError:
            pass
"""


_INNER_ARGS = (
    "-p",
    "tests.isolation",
    "-p",
    "no:cacheprovider",
    "--disable-socket",
    "--allow-unix-socket",
)


def _run(pytester: pytest.Pytester) -> pytest.RunResult:
    return pytester.runpytest_inprocess(*_INNER_ARGS)


@pytest.mark.parametrize("source", [_ENABLE_SOCKET_MARKER, _SOCKET_ENABLED_FIXTURE])
def test_enable_socket_without_live_stops_the_session(
    pytester: pytest.Pytester, source: str
) -> None:
    pytester.makepyfile(source)

    result = _run(pytester)

    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.fnmatch_lines(["*live*"])


def test_live_tests_are_skipped_without_the_switch(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(LIVE_SWITCH, raising=False)
    pytester.makepyfile(_LIVE_TEST)

    result = _run(pytester)

    result.assert_outcomes(skipped=1)


def test_live_tests_run_unguarded_with_the_switch(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 另起程序：這個測試本身（不是 live）的防護在同一個程序裡還有效。
    monkeypatch.setenv(LIVE_SWITCH, "1")
    monkeypatch.setenv("PYTHONPATH", str(PROJECT_ROOT))
    pytester.makepyfile(_LIVE_TEST)

    result = pytester.runpytest_subprocess(*_INNER_ARGS)

    result.assert_outcomes(passed=1)


def test_the_switch_must_be_exactly_one(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(LIVE_SWITCH, "true")
    pytester.makepyfile(_LIVE_TEST)

    result = _run(pytester)

    result.assert_outcomes(skipped=1)


_SESSION_FIXTURE = """
import os
import socket

import pytest


@pytest.fixture(scope="session")
def early_connection():
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect("/nonexistent/secscan-session.sock")


def test_uses_a_session_fixture(early_connection):
    pass


def test_docker_host_is_blocked_for_the_whole_session():
    assert os.environ["DOCKER_HOST"].startswith("unix:///nonexistent/")
"""


def test_session_fixtures_are_guarded_too(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    """防護在整個 session 生效，不只在每個測試的 fixture 裡（審查建議）。"""
    monkeypatch.delenv(LIVE_SWITCH, raising=False)
    monkeypatch.setenv("PYTHONPATH", str(PROJECT_ROOT))
    pytester.makepyfile(_SESSION_FIXTURE)

    result = pytester.runpytest_subprocess(*_INNER_ARGS)

    result.assert_outcomes(passed=1, errors=1)
    result.stdout.fnmatch_lines(["*UnixSocketBlockedError*"])
