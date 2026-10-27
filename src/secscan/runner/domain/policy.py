"""runner 的政策（docs/DECISIONS.md §14.3、§14.4）。

- EnginePolicy：每個引擎核准的映像、指令樣板、環境變數、輸入檔與上限。核准的映像在這裡另外寫一次，
  不引用 scanners 的建構：驗證是獨立的白名單，不是「建構的結果自己核准自己」。
- ContainerPolicy：所有掃描容器共用、不由 plan 決定的部分（網路、volume、user）。
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from secscan.scanners.domain.plan import ResourceLimits
from secscan.scans.domain.catalog import Engine

# 掃描容器的 user：和 runner 相同（隔離靠掛載，不靠 uid；docs/DECISIONS.md §14.4）。
SCAN_USER = "10001:10001"
# Docker 的物件名稱（network、volume）。
_DOCKER_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}")


@dataclass(frozen=True, slots=True)
class ArgumentPattern:
    """整個值必須完全符合的 regex。"""

    regex: str

    def accepts(self, value: str) -> bool:
        return re.fullmatch(self.regex, value) is not None


type ArgumentRule = str | ArgumentPattern


@dataclass(frozen=True, slots=True)
class CommandTemplate:
    """entrypoint 逐字相同；每個 arg 是 literal 或 regex，數量也必須相同。"""

    entrypoint: tuple[str, ...]
    arguments: tuple[ArgumentRule, ...]

    def matches(self, entrypoint: tuple[str, ...], arguments: tuple[str, ...]) -> bool:
        if entrypoint != self.entrypoint or len(arguments) != len(self.arguments):
            return False
        return all(
            rule.accepts(value) if isinstance(rule, ArgumentPattern) else rule == value
            for rule, value in zip(self.arguments, arguments, strict=True)
        )


@dataclass(frozen=True, slots=True)
class EnginePolicy:
    images: frozenset[str]
    commands: tuple[CommandTemplate, ...]
    environment: Mapping[str, ArgumentPattern]
    input_names: frozenset[str]
    max_input_bytes: int
    accepts_target_auth: bool
    max_limits: ResourceLimits


@dataclass(frozen=True, slots=True)
class ContainerPolicy:
    scan_network: str
    runs_volume: str
    secrets_volume: str
    user: str = field(default=SCAN_USER)

    def __post_init__(self) -> None:
        for name in (self.scan_network, self.runs_volume, self.secrets_volume):
            if _DOCKER_NAME.fullmatch(name) is None:
                raise ValueError("network 與 volume 的名稱只能有英數字與 _ . -")


ENGINE_POLICIES: Mapping[Engine, EnginePolicy] = MappingProxyType(
    {
        Engine.FAKE: EnginePolicy(
            images=frozenset(
                {
                    "busybox:1.38.0@sha256:"
                    "fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e"
                }
            ),
            commands=(
                CommandTemplate(("/bin/sleep",), (ArgumentPattern(r"(?:0|[1-9][0-9]{0,2})"),)),
                CommandTemplate(("/bin/false",), ()),
            ),
            environment=MappingProxyType({}),
            input_names=frozenset({"run.json"}),
            max_input_bytes=4096,
            accepts_target_auth=True,
            max_limits=ResourceLimits(
                memory_bytes=64 * 1024 * 1024,
                nano_cpus=500_000_000,
                pids=64,
                wall_clock_seconds=600,
            ),
        )
    }
)
