"""ExecutionPlan：一次 run 要啟動的容器（docs/DECISIONS.md §14.3、ARCHITECTURE.md §4）。

只描述「跑什麼」：映像、指令、非秘密的環境變數、要放進 in/ 的輸入檔、是否掛載 target 的 secret
（只有參照）與上限。host path、網路、user、privileged 這些「怎麼跑」不在這裡：由 runner 固定的
容器政策決定，plan 想放也放不進去。
"""

import re
from dataclasses import dataclass
from uuid import UUID

from secscan.scans.domain.catalog import Engine

# repo:tag@sha256:<64 hex>：只接受同時有 tag 與 digest 的寫法（CLAUDE.md §4）。repository 依
# Docker 的 reference 文法（小寫、以 . _ - 分隔；可以有 registry 與 port）。
_IMAGE_REFERENCE = re.compile(
    r"(?P<repository>(?:[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]{1,5})?/)?"
    r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*)"
    r":(?P<tag>[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})"
    r"@(?P<digest>sha256:[0-9a-f]{64})"
)
_INPUT_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")


@dataclass(frozen=True, slots=True)
class ImageReference:
    repository: str
    tag: str
    digest: str

    @classmethod
    def parse(cls, text: str) -> "ImageReference":
        match = _IMAGE_REFERENCE.fullmatch(text)
        if match is None:
            raise ValueError("映像必須是 repo:tag@sha256:<64 個 hex>（同時有 tag 與 digest）")
        return cls(repository=match["repository"], tag=match["tag"], digest=match["digest"])

    def __str__(self) -> str:
        return f"{self.repository}:{self.tag}@{self.digest}"


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    """容器的上限：記憶體（bytes，不能用 swap）、CPU（10^-9 個 CPU）、pid 數與牆鐘時間（秒）。"""

    memory_bytes: int
    nano_cpus: int
    pids: int
    wall_clock_seconds: int

    def __post_init__(self) -> None:
        for field in ("memory_bytes", "nano_cpus", "pids", "wall_clock_seconds"):
            value = getattr(self, field)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{field} 必須是正整數")


@dataclass(frozen=True, slots=True)
class InputFile:
    """runner 寫進 in/ 的輸入檔（唯讀掛載）。名稱只有小寫英數字與 . _ -，不能以 . 開頭。"""

    name: str
    content: bytes

    def __post_init__(self) -> None:
        if _INPUT_NAME.fullmatch(self.name) is None:
            raise ValueError("輸入檔的名稱只能有小寫英數字與 . _ -，最多 64 個字元")


@dataclass(frozen=True, slots=True)
class ExecutionPlan:
    run_id: UUID
    scan_id: UUID
    engine: Engine
    image: ImageReference
    entrypoint: tuple[str, ...]
    arguments: tuple[str, ...]
    # (名稱, 值)；只有非秘密的設定。秘密以檔案注入（target_auth）。
    environment: tuple[tuple[str, str], ...]
    inputs: tuple[InputFile, ...]
    # 是否把這個 run 的 target secret 唯讀掛進容器（值由 runner 在啟動前解密寫入）。
    target_auth: bool
    limits: ResourceLimits
