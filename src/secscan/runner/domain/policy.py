"""runner 的政策（docs/DECISIONS.md §14.3、§14.4、§18.2）。

- EnginePolicy：每個引擎核准的映像、指令樣板、環境變數、輸入檔與上限，以及可寫的 tmpfs、要收集
  輸出的退出碼。核准的映像與 script 的 digest 在這裡另外寫一次，不引用 scanners 的建構：驗證是
  獨立的白名單，不是「建構的結果自己核准自己」。
- AuthEnvironment：認證的環境變數和 target_auth 的對應（掛在指令樣板上：probe 沒有這個規則）。
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
class AuthEnvironment:
    """target_auth 與環境變數的對應（docs/DECISIONS.md §18.2）：mode_variable 的值是 anonymous_mode
    或 authenticated_mode，環境變數的名稱必須剛好是那個模式的集合。認證的值永遠不在 plan 中。
    """

    mode_variable: str
    anonymous_mode: str
    authenticated_mode: str
    anonymous: frozenset[str]
    authenticated: frozenset[str]

    def accepts(self, environment: tuple[tuple[str, str], ...], *, target_auth: bool) -> bool:
        values = dict(environment)
        expected = self.authenticated_mode if target_auth else self.anonymous_mode
        names = self.authenticated if target_auth else self.anonymous
        return set(values) == names and values.get(self.mode_variable) == expected


@dataclass(frozen=True, slots=True)
class CommandTemplate:
    """entrypoint 逐字相同；每個 arg 是 literal 或 regex，數量也必須相同。"""

    entrypoint: tuple[str, ...]
    arguments: tuple[ArgumentRule, ...]
    auth_environment: AuthEnvironment | None = None

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
    # 唯讀 rootfs 之外可寫的 tmpfs（path → 掛載選項）；記憶體上限要包含它。
    scratch: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    # 這些退出碼收集輸出（語意由 parser 判斷）；其他是 ENGINE_FAILED（§18.1）。
    collect_exit_codes: frozenset[int] = frozenset({0})


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
# 重新審查、更新（tests/unit/runner/test_admission.py 核對兩者一致）。
PREFLIGHT_SCRIPT_SHA256 = "5cfd3e5bc89770e36c1b8f523248a554b12dd8da0948a6ac79ee3711fd1ae2cc"

# T03 鎖定的 ZAP（docs/TOOLS.md §1）與兩個 script（scanners.domain.zap.script）的 sha256：script
# 改了，這裡要重新審查、更新（tests/unit/runner/test_zap_admission.py 核對兩者一致）。
_ZAP = (
    "zaproxy/zap-stable:20261016"
    "@sha256:5ccfff9a411743ab2615136a2edd7416bec9ce41572fa94e935df38c14adb2b6"
)
ZAP_SCAN_SCRIPT_SHA256 = "8ee67b2ad2101c6d41cf4116fa1590193cbc3e66123c3baff84d69af4311d385"
ZAP_PROBE_SCRIPT_SHA256 = "a2749f65df1cf2932882cb8fbd95a45dd129dff28293b8a757c55adfd82fda1b"
_ZAP_AUTH = AuthEnvironment(
    mode_variable="SECSCAN_TARGET_AUTH",
    anonymous_mode="none",
    authenticated_mode="header",
    anonymous=frozenset({"SECSCAN_TARGET_AUTH"}),
    authenticated=frozenset({"SECSCAN_TARGET_AUTH", "ZAP_AUTH_HEADER", "ZAP_AUTH_HEADER_SITE"}),
)
# 最大的輸入是正規化之後的規格（specs.domain.openapi.MAX_DOCUMENT_BYTES）。
_ZAP_MAX_INPUT_BYTES = 2 * 1024 * 1024

ENGINE_POLICIES: Mapping[Engine, EnginePolicy] = MappingProxyType(
    {
        Engine.ZAP: EnginePolicy(
            images=frozenset({_ZAP}),
            commands=(
                CommandTemplate(
                    ("/bin/sh", "-c"),
                    (ArgumentDigest(ZAP_SCAN_SCRIPT_SHA256),),
                    auth_environment=_ZAP_AUTH,
                ),
                CommandTemplate(("/bin/sh", "-c"), (ArgumentDigest(ZAP_PROBE_SCRIPT_SHA256),)),
            ),
            environment=MappingProxyType(
                {
                    "SECSCAN_TARGET_AUTH": ArgumentPattern(r"none|header"),
                    # auth profile 的 header 名稱（auth_profiles.domain.credentials）。
                    "ZAP_AUTH_HEADER": ArgumentPattern(
                        r"(?=[A-Za-z0-9-]{1,64}$)[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*"
                    ),
                    # target 的 host：小寫的名稱或 IPv4（targets.domain.Origin）。
                    "ZAP_AUTH_HEADER_SITE": ArgumentPattern(
                        r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?"
                    ),
                }
            ),
            input_names=frozenset({"plan.yaml", "openapi.json", "probe.yaml"}),
            max_input_bytes=_ZAP_MAX_INPUT_BYTES,
            accepts_target_auth=True,
            max_limits=ResourceLimits(
                memory_bytes=3 * 1024 * 1024 * 1024,
                nano_cpus=2_000_000_000,
                pids=1024,
                wall_clock_seconds=1_500,
            ),
            # 容器內的 tmpfs（ZAP 的 home 與 JVM 的暫存），不是宿主的暫存目錄。
            scratch=MappingProxyType({"/tmp": "rw,noexec,nosuid,nodev,size=768m,mode=1777"}),  # noqa: S108
            collect_exit_codes=frozenset({0, 1, 2}),
        ),
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
