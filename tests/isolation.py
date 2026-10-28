"""測試程序連不到 Docker daemon（TASKS T10 的 DoD、docs/DECISIONS.md §14.9）。

pytest-socket 封鎖 TCP/UDP，但 AF_UNIX 必須整個放行（asyncio 需要 socketpair），Docker daemon 的
Unix socket 因此連得到。這個 plugin（由 tests/conftest.py 載入）：

- 只允許 connect 到 pytest 暫存目錄底下的 AF_UNIX 路徑（解析 symlink 與相對路徑之後判斷）；
- 把 DOCKER_HOST 指向不存在的 socket，清掉其他 Docker 設定（子程序的 docker CLI 也連不到）；
- 沒有標記 live 的測試不能用 enable_socket；live 測試要 ENABLE_LIVE_LAB_TESTS=1 才執行（否則在
  收集時就 skip），只有它們解除上述限制（CLAUDE.md §12）。

沒有開關時（例如 make test），防護在 pytest_configure 就套用到整個 session：session 與 module
範圍的 fixture 也受限制（審查建議）。開關打開時只在每個非 live 的測試套用，live 測試不受限。
"""

import os
import socket
import tempfile
from collections.abc import Callable
from pathlib import Path

import pytest

BLOCKED_DOCKER_HOST = "unix:///nonexistent/secscan-tests-docker-blocked.sock"
LIVE_SWITCH = "ENABLE_LIVE_LAB_TESTS"
LIVE_MARKER = "live"
# 這些設定會讓 Docker SDK 或 CLI 改連其他 daemon，測試時一律清掉。
DOCKER_ENV_KEYS = ("DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")
_SOCKET_FIXTURES = frozenset({"socket_enabled", "enable_socket"})

# 在 pytest-socket 替換 socket.socket 之前取得原本的類別；它的子類別也會用到這裡的 connect。
_SOCKET_CLASS = socket.socket
_REAL_CONNECT = _SOCKET_CLASS.connect
_REAL_CONNECT_EX = _SOCKET_CLASS.connect_ex


class UnixSocketBlockedError(RuntimeError):
    """測試嘗試 connect 到暫存目錄以外的 Unix socket（例如 Docker daemon）。"""


_SESSION_GUARD = pytest.StashKey[pytest.MonkeyPatch]()


def pytest_configure(config: pytest.Config) -> None:
    if os.environ.get(LIVE_SWITCH) == "1":
        return
    patch = pytest.MonkeyPatch()
    _block_docker(patch, Path(tempfile.gettempdir()).resolve())
    config.stash[_SESSION_GUARD] = patch


def pytest_unconfigure(config: pytest.Config) -> None:
    patch = config.stash.get(_SESSION_GUARD, None)
    if patch is not None:
        patch.undo()


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """沒有標記 live 卻要求開放網路的測試：整個 session 以使用錯誤結束。

    沒有開關時，live 測試在收集時就標成 skip（連它們的 fixture 都不執行，不會碰到 Docker）。
    """
    offenders = [
        item.nodeid
        for item in items
        if item.get_closest_marker(LIVE_MARKER) is None and _wants_socket(item)
    ]
    if offenders:
        raise pytest.UsageError(
            f"只有標記 {LIVE_MARKER} 的測試可以使用 enable_socket：" + "、".join(offenders)
        )
    if os.environ.get(LIVE_SWITCH) == "1":
        return
    skip = pytest.mark.skip(reason=f"live 測試要設定 {LIVE_SWITCH}=1")
    for item in items:
        if item.get_closest_marker(LIVE_MARKER) is not None:
            item.add_marker(skip)


def _wants_socket(item: pytest.Item) -> bool:
    if item.get_closest_marker("enable_socket") is not None:
        return True
    names = getattr(item, "fixturenames", ())
    return any(name in _SOCKET_FIXTURES for name in names)


@pytest.fixture(autouse=True)
def _isolate_from_docker(
    request: pytest.FixtureRequest,
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """每個非 live 的測試：只允許這次 session 的暫存目錄（比 session 範圍的防護更窄）。"""
    if request.node.get_closest_marker(LIVE_MARKER) is not None:
        return
    _block_docker(monkeypatch, tmp_path_factory.getbasetemp().resolve())


def _block_docker(patch: pytest.MonkeyPatch, allowed: Path) -> None:
    patch.setenv("DOCKER_HOST", BLOCKED_DOCKER_HOST)
    for key in DOCKER_ENV_KEYS:
        patch.delenv(key, raising=False)
    patch.setattr(_SOCKET_CLASS, "connect", _guarded(_REAL_CONNECT, allowed))
    patch.setattr(_SOCKET_CLASS, "connect_ex", _guarded(_REAL_CONNECT_EX, allowed))


def _guarded[R](connect: Callable[..., R], allowed: Path) -> Callable[[socket.socket, object], R]:
    def guarded(self: socket.socket, address: object) -> R:
        if self.family == socket.AF_UNIX and not _inside(address, allowed):
            raise UnixSocketBlockedError("測試只能連到 pytest 暫存目錄底下的 Unix socket")
        return connect(self, address)

    return guarded


def _inside(address: object, allowed: Path) -> bool:
    if isinstance(address, bytes):
        address = os.fsdecode(address)
    # 空字串或以 NUL 開頭的是 Linux 的 abstract namespace，不在任何目錄底下。
    if not isinstance(address, str) or not address or address.startswith("\0"):
        return False
    return Path(address).resolve().is_relative_to(allowed)
