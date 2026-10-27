"""runner 測試共用的假實作：時鐘與記憶體中的容器 runtime（不碰 Docker）。

假的容器照 busybox 的指令行為：`/bin/sleep N` 在 N 秒後以 0 結束，`/bin/false` 立刻以 1 結束；
stop 之後以 143 結束。時間由 FakeClock 控制：runner 呼叫 sleep 時時間前進，到點的 hook 依序執行。
"""

from collections.abc import Callable
from dataclasses import dataclass, field

from secscan.runner.domain.admission import ContainerSpec
from secscan.runner.domain.runtime import (
    ContainerConflictError,
    ContainerState,
    EngineVersion,
    NetworkState,
    RuntimeUnavailableError,
)
from secscan.scanners.domain.fake import FAKE_IMAGE

SIGTERM_EXIT = 143
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
    images: dict[str, str] = field(default_factory=lambda: {str(FAKE_IMAGE): "arm64"})
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
    out_of_memory: bool = False

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
        self.containers[name].started_at = self.clock.now

    def state(self, name: str) -> ContainerState | None:
        self._check("state")
        container = self.containers.get(name)
        if container is None:
            return None
        if container.ended is None:
            container.ended = self._finished(container)
        if container.ended is not None:
            return container.ended
        return ContainerState(running=True, exit_code=None, oom_killed=False)

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
        if self.containers.pop(name, None) is not None:
            self.removed.append(name)

    def _finished(self, container: FakeContainer) -> ContainerState | None:
        assert container.started_at is not None
        entrypoint = container.spec.body["Entrypoint"]
        if entrypoint == ["/bin/false"]:
            return ContainerState(running=False, exit_code=1, oom_killed=False)
        arguments = container.spec.body["Cmd"]
        assert isinstance(arguments, list)
        duration = int(str(arguments[0]))
        if self.clock.now - container.started_at < duration:
            return None
        if self.out_of_memory:
            return ContainerState(running=False, exit_code=OOM_EXIT, oom_killed=True)
        return ContainerState(running=False, exit_code=0, oom_killed=False)
