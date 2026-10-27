"""容器執行環境的介面（docs/DECISIONS.md §14.2）。

runner 只透過這個介面操作容器；實作是 runner/docker_runtime.py（經 socket-proxy），
測試另有記憶體中的假實作。容器一律以名稱（secscan-run-<run_id>）指定。
"""

from dataclasses import dataclass
from typing import Protocol

from secscan.runner.domain.admission import ContainerSpec


class RuntimeUnavailableError(Exception):
    """Docker 不可用、拒絕請求或回應錯誤。訊息只有動作與狀態碼，不含回應的內容。"""


class ContainerConflictError(RuntimeUnavailableError):
    """同名的容器已經存在（同一個 run 不會啟動第二個容器）。"""


@dataclass(frozen=True, slots=True)
class EngineVersion:
    api_version: str
    min_api_version: str
    os: str
    arch: str


@dataclass(frozen=True, slots=True)
class NetworkState:
    internal: bool
    isolated_gateway: bool


@dataclass(frozen=True, slots=True)
class ContainerState:
    """running 為 false 時，exit_code 是結束的代碼；oom_killed 表示因記憶體上限被終止。"""

    running: bool
    exit_code: int | None
    oom_killed: bool


class ContainerRuntime(Protocol):
    def version(self) -> EngineVersion: ...

    def image_architecture(self, reference: str) -> str | None: ...

    def network(self, name: str) -> NetworkState | None: ...

    def volume_exists(self, name: str) -> bool: ...

    def create(self, spec: ContainerSpec) -> None: ...

    def start(self, name: str) -> None: ...

    def state(self, name: str) -> ContainerState | None: ...

    def stop(self, name: str, *, grace_seconds: int) -> None: ...

    def remove(self, name: str) -> None: ...
