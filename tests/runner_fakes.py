"""runner 測試共用的假實作：時鐘與記憶體中的容器 runtime（不碰 Docker）。

假的容器照 busybox 的指令行為：`/bin/sleep N` 在 N 秒後以 0 結束，`/bin/false` 立刻以 1 結束，
preflight 的 `/bin/sh -c` 在 3 秒後以 0 結束；
stop 之後以 143 結束。其他映像（ZAP）照 scripted 的設定：幾秒後以指定的退出碼結束，啟動時
呼叫 on_start（例如寫 out/ 的檔案）。時間由 FakeClock 控制：runner 呼叫 sleep 時時間前進，
到點的 hook 依序執行。
state 和 DockerRuntime 一樣讀回 label 標示的 run；已建立但還沒啟動的容器算 running（Docker 的
created）。
"""

from collections.abc import Callable
from dataclasses import dataclass, field, replace

from secscan.runner.domain.admission import ContainerSpec, managed_run_id
from secscan.runner.domain.runtime import (
    ContainerConflictError,
    ContainerState,
    EngineVersion,
    NetworkState,
    RuntimeUnavailableError,
)
from secscan.scanners.domain.fake import FAKE_IMAGE
from secscan.scanners.domain.zap.policy import ZAP_IMAGE

SIGTERM_EXIT = 143
PREFLIGHT_SECONDS = 3
OOM_EXIT = 137


@dataclass
class FakeClock:
    now: float = 0.0
    _hooks: list[tuple[float, Callable[[], None]]] = field(default_factory=list)

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds
        due = [hook for hook in self._hooks if hook[0] <= self.now]
        self._hooks = [hook for hook in self._hooks if hook[0] > self.now]
        for _, action in due:
            action()

    def at(self, moment: float, action: Callable[[], None]) -> None:
        self._hooks.append((moment, action))


@dataclass
class ScriptedContainer:
    """不是 busybox 的映像：seconds 秒後以 exit_code 結束；啟動時呼叫 on_start。"""

    seconds: float = 3
    exit_code: int = 0
    on_start: Callable[[ContainerSpec], None] | None = None


@dataclass
class FakeContainer:
    spec: ContainerSpec
    started_at: float | None = None
    ended: ContainerState | None = None


@dataclass
class FakeContainerRuntime:
    clock: FakeClock = field(default_factory=FakeClock)
    engine: EngineVersion = field(
        default_factory=lambda: EngineVersion("1.54", "1.40", "linux", "arm64")
    )
    images: dict[str, str] = field(
        default_factory=lambda: {str(FAKE_IMAGE): "arm64", str(ZAP_IMAGE): "arm64"}
    )
    networks: dict[str, NetworkState] = field(
        default_factory=lambda: {
            "secscan_scan_net": NetworkState(internal=True, isolated_gateway=True)
        }
    )
    volumes: set[str] = field(default_factory=lambda: {"secscan_runs", "secscan_run_secrets"})
    containers: dict[str, FakeContainer] = field(default_factory=dict)
    created: list[ContainerSpec] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    stopped: list[str] = field(default_factory=list)
    failing: set[str] = field(default_factory=set)
    # 刪除時回 409 的容器（Docker：刪除已在進行中）。
    conflicting: set[str] = field(default_factory=set)
    # 刪除時回 500 的容器（Docker 本身可用，只有這個容器刪不掉，例如 device busy）。
    broken: set[str] = field(default_factory=set)
    out_of_memory: bool = False
    # 映像 → 容器的行為（ZAP）；沒有設定的 ZAP 容器 3 秒後以 0 結束。
    scripted: dict[str, ScriptedContainer] = field(default_factory=dict)

    def _check(self, operation: str) -> None:
        if operation in self.failing:
            raise RuntimeUnavailableError(f"{operation} 失敗（HTTP 500）")

    def version(self) -> EngineVersion:
        self._check("version")
        return self.engine

    def image_architecture(self, reference: str) -> str | None:
        self._check("image_architecture")
        return self.images.get(reference)

    def network(self, name: str) -> NetworkState | None:
        self._check("network")
        return self.networks.get(name)

    def volume_exists(self, name: str) -> bool:
        self._check("volume_exists")
        return name in self.volumes

    def create(self, spec: ContainerSpec) -> None:
        self._check("create")
        if spec.name in self.containers:
            raise ContainerConflictError("同名的容器已經存在")
        if spec.body["Image"] not in self.images:
            raise RuntimeUnavailableError("建立容器失敗（HTTP 404）")
        self.created.append(spec)
        self.containers[spec.name] = FakeContainer(spec)

    def start(self, name: str) -> None:
        self._check("start")
        container = self.containers[name]
        container.started_at = self.clock.now
        script = self.scripted.get(str(container.spec.body["Image"]))
        if script is not None and script.on_start is not None:
            script.on_start(container.spec)

    def state(self, name: str) -> ContainerState | None:
        self._check("state")
        container = self.containers.get(name)
        if container is None:
            return None
        labels = container.spec.body["Labels"]
        label = managed_run_id(labels) if isinstance(labels, dict) else None
        if container.ended is None and container.started_at is not None:
            container.ended = self._finished(container)
        if container.ended is not None:
            return replace(container.ended, run_label=label)
        return ContainerState(running=True, exit_code=None, oom_killed=False, run_label=label)

    def stop(self, name: str, *, grace_seconds: int) -> None:
        self._check("stop")
        self.stopped.append(name)
        container = self.containers.get(name)
        if container is not None and container.ended is None:
            container.ended = ContainerState(
                running=False, exit_code=SIGTERM_EXIT, oom_killed=False
            )

    def remove(self, name: str) -> None:
        self._check("remove")
        if name in self.conflicting:
            raise ContainerConflictError("刪除容器：衝突（HTTP 409）")
        if name in self.broken:
            raise RuntimeUnavailableError("刪除容器失敗（HTTP 500）")
        if self.containers.pop(name, None) is not None:
            self.removed.append(name)

    def _finished(self, container: FakeContainer) -> ContainerState | None:
        assert container.started_at is not None
        image = str(container.spec.body["Image"])
        if image != str(FAKE_IMAGE):
            script = self.scripted.get(image, ScriptedContainer())
            if self.clock.now - container.started_at < script.seconds:
                return None
            return self._exit(script.exit_code)
        entrypoint = container.spec.body["Entrypoint"]
        if entrypoint == ["/bin/false"]:
            return ContainerState(running=False, exit_code=1, oom_killed=False)
        arguments = container.spec.body["Cmd"]
        assert isinstance(arguments, list)
        # preflight 的 script（/bin/sh -c）：送完兩個請求就結束，這裡當成 3 秒。
        duration = PREFLIGHT_SECONDS if entrypoint == ["/bin/sh", "-c"] else int(str(arguments[0]))
        if self.clock.now - container.started_at < duration:
            return None
        return self._exit(0)

    def _exit(self, exit_code: int) -> ContainerState:
        if self.out_of_memory:
            return ContainerState(running=False, exit_code=OOM_EXIT, oom_killed=True)
        return ContainerState(running=False, exit_code=exit_code, oom_killed=False)
