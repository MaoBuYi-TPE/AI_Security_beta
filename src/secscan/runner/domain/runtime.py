"""容器執行環境的介面（docs/DECISIONS.md §14.2）。

runner 只透過這個介面操作容器；實作是 runner/docker_runtime.py（經 socket-proxy），
測試另有記憶體中的假實作。容器一律以名稱（secscan-run-<run_id>）指定。
"""

from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from secscan.runner.domain.admission import ContainerSpec

# Engine API 的版本：1.45 起支援 volume 的 Subpath（docs/DECISIONS.md §14.2）。
DOCKER_API_VERSION = "1.45"


class RuntimeUnavailableError(Exception):
    """Docker 不可用、拒絕請求或回應錯誤。訊息只有動作與狀態碼，不含回應的內容。"""


class ContainerConflictError(RuntimeUnavailableError):
    """Docker 回 409：create 時同名的容器已經存在（同一個 run 不會啟動第二個容器）；remove 時
    刪除已在進行中。"""


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
    """running 為 false 時，exit_code 是結束的代碼；oom_killed 表示因記憶體上限被終止。

    run_label：label 標示的 run（不是 runner 建立的容器是 None；docs/DECISIONS.md §17.2）。
    已建立但還沒啟動、暫停中的容器都算 running（可能之後才開始送出流量）。
    """

    running: bool
    exit_code: int | None
    oom_killed: bool
    run_label: UUID | None = None


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
