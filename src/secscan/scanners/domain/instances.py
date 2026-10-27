"""runner 與 worker 的心跳與能力（docs/DECISIONS.md §14.7）。

capabilities 只由 enum、映像 ref 與版本字串組成：不含路徑、主機名稱或任何秘密。
"""

from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum

from secscan.scans.domain.catalog import Engine

HEARTBEAT_EVERY = timedelta(seconds=5)
# 30 秒內有心跳才算存活（和 lease 的長度相同）。
ALIVE_WITHIN = timedelta(seconds=30)
STALE_AFTER = timedelta(days=7)
MAX_CAPABILITIES_BYTES = 4096


class InstanceRole(StrEnum):
    RUNNER = "runner"
    WORKER = "worker"


class CapabilityIssue(StrEnum):
    """引擎不可用的原因。"""

    DOCKER_UNAVAILABLE = "DOCKER_UNAVAILABLE"
    DOCKER_API_UNSUPPORTED = "DOCKER_API_UNSUPPORTED"
    SCAN_NETWORK_NOT_ISOLATED = "SCAN_NETWORK_NOT_ISOLATED"
    RUN_VOLUME_MISSING = "RUN_VOLUME_MISSING"
    IMAGE_MISSING = "IMAGE_MISSING"


@dataclass(frozen=True, slots=True)
class EngineCapability:
    engine: Engine
    image: str | None
    issue: CapabilityIssue | None

    @property
    def available(self) -> bool:
        return self.issue is None


@dataclass(frozen=True, slots=True)
class Capabilities:
    engines: tuple[EngineCapability, ...]

    @property
    def available_engines(self) -> frozenset[Engine]:
        return frozenset(item.engine for item in self.engines if item.available)
