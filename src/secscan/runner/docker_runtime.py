"""經 docker-socket-proxy 操作容器（docs/DECISIONS.md §14.2）。整個專案只有這個模組 import docker。

- 低階 APIClient、版本固定 1.45（volume subpath 的最低版本）：建立時不呼叫 daemon，也不受 Docker CLI
  的 context 影響。不讀環境變數中的 HTTP proxy 設定。
- 不 pull 映像：create 遇到缺少的映像就失敗（proxy 也不放行 /images/create）。
- create 的 body 由 runner 組好並檢查過，原樣送出。
- Docker 的錯誤一律轉成 RuntimeUnavailableError：只保留動作與狀態碼，不接上原始例外（回應的內容
  可能含容器的設定）。
"""

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any
from uuid import UUID

import docker
import requests
from requests.adapters import BaseAdapter

from secscan.runner.domain.admission import ContainerSpec, managed_run_id
from secscan.runner.domain.runtime import (
    DOCKER_API_VERSION,
    ContainerConflictError,
    ContainerState,
    EngineVersion,
    NetworkState,
    RuntimeUnavailableError,
)

API_VERSION = DOCKER_API_VERSION
DEFAULT_TIMEOUT_SECONDS = 30
_GATEWAY_MODE = "com.docker.network.bridge.gateway_mode_ipv4"
_FINISHED = frozenset({"exited", "dead"})
_CONFLICT = 409


class DockerRuntime:
    def __init__(self, client: docker.APIClient) -> None:
        self._client = client

    @classmethod
    def connect(
        cls,
        url: str,
        *,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        adapter: BaseAdapter | None = None,
    ) -> "DockerRuntime":
        """url 只接受 tcp://主機:port（socket-proxy）或 unix:///絕對路徑。

        adapter 只給測試：取代 HTTP 的傳輸。
        """
        if not _supported(url):
            raise ValueError("Docker 的位址必須是 tcp://主機:port 或 unix:///絕對路徑")
        client = docker.APIClient(base_url=url, version=API_VERSION, timeout=timeout_seconds)
        client.trust_env = False
        if adapter is not None:
            client.mount("http://", adapter)
        return cls(client)

    @property
    def trusts_environment(self) -> bool:
        return bool(self._client.trust_env)

    def version(self) -> EngineVersion:
        with _translate("查詢版本"):
            info = self._client.version()
        with _parsing("查詢版本"):
            return EngineVersion(
                api_version=str(info["ApiVersion"]),
                min_api_version=str(info["MinAPIVersion"]),
                os=str(info["Os"]),
                arch=str(info["Arch"]),
            )

    def image_architecture(self, reference: str) -> str | None:
        try:
            with _translate("查詢映像", absent_ok=True):
                # types-docker 沒有替這兩個方法加上型別。
                info = self._client.inspect_image(reference)  # type: ignore[no-untyped-call]
        except _NotFoundError:
            return None
        with _parsing("查詢映像"):
            return str(info["Architecture"])

    def network(self, name: str) -> NetworkState | None:
        try:
            with _translate("查詢網路", absent_ok=True):
                info = self._client.inspect_network(name)
        except _NotFoundError:
            return None
        with _parsing("查詢網路"):
            options: Mapping[str, Any] = info.get("Options") or {}
            return NetworkState(
                internal=info.get("Internal") is True,
                isolated_gateway=options.get(_GATEWAY_MODE) == "isolated",
            )

    def volume_exists(self, name: str) -> bool:
        try:
            with _translate("查詢 volume", absent_ok=True):
                self._client.inspect_volume(name)
        except _NotFoundError:
            return False
        return True

    def create(self, spec: ContainerSpec) -> None:
        with _translate("建立容器"):
            self._client.create_container_from_config(  # type: ignore[no-untyped-call]
                spec.body, name=spec.name
            )

    def start(self, name: str) -> None:
        with _translate("啟動容器"):
            self._client.start(name)

    def state(self, name: str) -> ContainerState | None:
        try:
            with _translate("查詢容器", absent_ok=True):
                info = self._client.inspect_container(name)
        except _NotFoundError:
            return None
        with _parsing("查詢容器"):
            state: Mapping[str, Any] = info["State"]
            run_label = _run_label(info["Config"])
            if state["Status"] not in _FINISHED:
                return ContainerState(
                    running=True, exit_code=None, oom_killed=False, run_label=run_label
                )
            return ContainerState(
                running=False,
                exit_code=int(state["ExitCode"]),
                oom_killed=state.get("OOMKilled") is True,
                run_label=run_label,
            )

    def stop(self, name: str, *, grace_seconds: int) -> None:
        """送 SIGTERM，grace_seconds 後 SIGKILL。已停止或不存在都不算錯誤。"""
        try:
            with _translate("停止容器", absent_ok=True):
                self._client.stop(name, timeout=grace_seconds)
        except _NotFoundError:
            return

    def remove(self, name: str) -> None:
        """強制刪除（還在執行就 SIGKILL），連同映像宣告的匿名 volume。不存在不算錯誤。"""
        try:
            with _translate("刪除容器", absent_ok=True):
                self._client.remove_container(name, force=True, v=True)
        except _NotFoundError:
            return


class _NotFoundError(Exception):
    """Docker 回 404（在這個模組內部使用）。"""


@contextmanager
def _parsing(action: str) -> Iterator[None]:
    """回應的格式不符（少了欄位、型別不對）：當成 Docker 不可用，不讓 KeyError 結束 runner。"""
    try:
        yield
    except (KeyError, TypeError, ValueError, AttributeError):
        raise RuntimeUnavailableError(f"{action}失敗（回應的格式不符）") from None


@contextmanager
def _translate(action: str, *, absent_ok: bool = False) -> Iterator[None]:
    """absent_ok：404 代表「不存在」，轉成 _NotFoundError 由呼叫端處理；否則和其他錯誤一樣。"""
    try:
        yield
    except docker.errors.NotFound:
        if absent_ok:
            raise _NotFoundError from None
        raise RuntimeUnavailableError(f"{action}失敗（HTTP 404）") from None
    except docker.errors.APIError as exc:
        if exc.status_code == _CONFLICT:
            # create 是同名的容器已經存在；remove 是刪除已在進行中。
            raise ContainerConflictError(f"{action}失敗（HTTP 409）") from None
        raise RuntimeUnavailableError(f"{action}失敗（HTTP {exc.status_code}）") from None
    except (docker.errors.DockerException, requests.exceptions.RequestException) as exc:
        raise RuntimeUnavailableError(f"{action}失敗（{type(exc).__name__}）") from None


def _run_label(config: object) -> UUID | None:
    """Config 一定存在（缺少就是回應的格式不符）；label 不符只代表不是我們的容器。"""
    if not isinstance(config, Mapping):
        raise TypeError("Config 不是物件")
    labels = config.get("Labels")
    return managed_run_id(labels) if isinstance(labels, Mapping) else None


def _supported(url: str) -> bool:
    if url.startswith("unix:///"):
        return len(url) > len("unix:///")
    if not url.startswith("tcp://"):
        return False
    host, separator, port = url.removeprefix("tcp://").rpartition(":")
    return bool(host) and bool(separator) and port.isdigit() and "/" not in host
