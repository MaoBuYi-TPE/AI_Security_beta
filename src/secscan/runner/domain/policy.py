"""runner 的政策（docs/DECISIONS.md §14.3、§14.4）。

- EnginePolicy：每個引擎核准的映像、指令樣板、環境變數、輸入檔與上限。核准的映像在這裡另外寫一次，
  不引用 scanners 的建構：驗證是獨立的白名單，不是「建構的結果自己核准自己」。
- ContainerPolicy：所有掃描容器共用、不由 plan 決定的部分（網路、volume、user）。
"""

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from secscan.scanners.domain.plan import ResourceLimits
from secscan.scans.domain.catalog import Engine

# 掃描容器的 user：和 runner 相同（隔離靠掛載，不靠 uid；docs/DECISIONS.md §14.4）。
SCAN_USER = "10001:10001"
# Docker 的物件名稱（network、volume）。不接受 .：名稱也會放進 socket-proxy 的 regex（. 是萬用
# 字元）。host、bridge、none 會讓容器接上宿主或預設的網路（審查發現）。
_DOCKER_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}")
_RESERVED_NAMES = frozenset({"host", "bridge", "none", "default"})


@dataclass(frozen=True, slots=True)
class ArgumentPattern:
    """整個值必須完全符合的 regex。"""

    regex: str

    def accepts(self, value: str) -> bool:
        return re.fullmatch(self.regex, value) is not None


@dataclass(frozen=True, slots=True)
class ArgumentDigest:
    """值的 sha256 必須相同：核准一段固定的 script，而不必在這裡再寫一次全文。"""

    sha256: str

    def accepts(self, value: str) -> bool:
        return hashlib.sha256(value.encode("utf-8")).hexdigest() == self.sha256


type ArgumentRule = str | ArgumentPattern | ArgumentDigest


@dataclass(frozen=True, slots=True)
class CommandTemplate:
    """entrypoint 逐字相同；每個 arg 是 literal 或 regex，數量也必須相同。"""

    entrypoint: tuple[str, ...]
    arguments: tuple[ArgumentRule, ...]

    def matches(self, entrypoint: tuple[str, ...], arguments: tuple[str, ...]) -> bool:
        if entrypoint != self.entrypoint or len(arguments) != len(self.arguments):
            return False
        return all(
            rule == value if isinstance(rule, str) else rule.accepts(value)
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
            if _DOCKER_NAME.fullmatch(name) is None or name.lower() in _RESERVED_NAMES:
                raise ValueError(
                    "network 與 volume 的名稱只能有英數字、_ 與 -，也不能是 host、bridge、none"
                )


_BUSYBOX = "busybox:1.38.0@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e"
# preflight 的 script（scanners.domain.preflight.PREFLIGHT_SCRIPT）的 sha256：script 改了，這裡要
# 重新審查、更新（tests/unit/runner/test_engine_policy.py 核對兩者一致）。
PREFLIGHT_SCRIPT_SHA256 = "c944a7f97be582410ebd7f8e73139a626131e4abe9c934d67b2fb6c93ca5bd1f"

ENGINE_POLICIES: Mapping[Engine, EnginePolicy] = MappingProxyType(
    {
        Engine.PREFLIGHT: EnginePolicy(
            images=frozenset({_BUSYBOX}),
            commands=(
                CommandTemplate(("/bin/sh", "-c"), (ArgumentDigest(PREFLIGHT_SCRIPT_SHA256),)),
            ),
            environment=MappingProxyType({}),
            input_names=frozenset({"request"}),
            max_input_bytes=1024,
            accepts_target_auth=True,
            max_limits=ResourceLimits(
                memory_bytes=64 * 1024 * 1024,
                nano_cpus=500_000_000,
                pids=64,
                wall_clock_seconds=60,
            ),
        ),
        Engine.FAKE: EnginePolicy(
            images=frozenset({_BUSYBOX}),
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
        ),
    }
)
