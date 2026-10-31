"""runner 與 worker 的心跳與能力（docs/DECISIONS.md §14.7）。

capabilities 只由 enum、映像 ref 與版本字串組成：不含路徑、主機名稱或任何秘密。
引擎的版本由 runner 的 capability probe 實際執行映像取得（docs/DECISIONS.md §18.8）。
"""

import re
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum

from secscan.core.json_types import JsonObject, JsonValue
from secscan.scanners.domain.plan import ImageReference
from secscan.scans.domain.catalog import (
    AVAILABLE_ENGINES,
    SELECTABLE_ENGINES,
    Engine,
    ScanProfile,
)

HEARTBEAT_EVERY = timedelta(seconds=5)
# 30 秒內有心跳才算存活（和 lease 的長度相同）。
ALIVE_WITHIN = timedelta(seconds=30)
STALE_AFTER = timedelta(days=7)
MAX_CAPABILITIES_BYTES = 4096
_VERSION = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}")


class InstanceRole(StrEnum):
    RUNNER = "runner"
    WORKER = "worker"


class CapabilityIssue(StrEnum):
    """引擎不可用的原因。"""

    DOCKER_UNAVAILABLE = "DOCKER_UNAVAILABLE"
    DOCKER_API_UNSUPPORTED = "DOCKER_API_UNSUPPORTED"
    SCAN_NETWORK_NOT_ISOLATED = "SCAN_NETWORK_NOT_ISOLATED"
    RUN_VOLUME_MISSING = "RUN_VOLUME_MISSING"
    RUN_VOLUME_NOT_WRITABLE = "RUN_VOLUME_NOT_WRITABLE"
    IMAGE_MISSING = "IMAGE_MISSING"
    # egress guard 不可用（status 過期、不再檢查、policy 目錄不可寫；docs/DECISIONS.md §15.8）。
    GUARD_UNAVAILABLE = "GUARD_UNAVAILABLE"
    # 引擎的 capability probe（實際執行映像，docs/DECISIONS.md §18.8）：還沒驗證完、失敗（容器失敗、
    # 逾時、輸出讀不到）、版本或 add-on 或規則和審查過的不同。
    ENGINE_PROBE_PENDING = "ENGINE_PROBE_PENDING"
    ENGINE_PROBE_FAILED = "ENGINE_PROBE_FAILED"
    ENGINE_INCOMPATIBLE = "ENGINE_INCOMPATIBLE"


@dataclass(frozen=True, slots=True)
class EngineCapability:
    engine: Engine
    image: str | None
    issue: CapabilityIssue | None
    # probe 實際取得的版本（只有執行容器驗證的引擎才有）。
    version: str | None = None

    @property
    def available(self) -> bool:
        return self.issue is None


@dataclass(frozen=True, slots=True)
class Capabilities:
    engines: tuple[EngineCapability, ...]

    @property
    def available_engines(self) -> frozenset[Engine]:
        return frozenset(item.engine for item in self.engines if item.available)


def capabilities_json(capabilities: Capabilities) -> JsonObject:
    """存進 runner_instances.capabilities 的形式：引擎 → 映像與不可用的原因。"""
    engines: JsonObject = {item.engine.value: _entry(item) for item in capabilities.engines}
    return {"engines": engines}


def _entry(item: EngineCapability) -> JsonObject:
    entry: JsonObject = {
        "image": item.image,
        "issue": item.issue.value if item.issue is not None else None,
    }
    if item.version is not None:
        entry["version"] = item.version
    return entry


def read_capabilities(document: JsonValue) -> Capabilities:
    """讀回 capabilities_json 的內容；不認得的引擎或格式不對的項目直接略過（視為沒有回報）。"""
    engines = document.get("engines") if isinstance(document, dict) else None
    if not isinstance(engines, dict):
        return Capabilities(engines=())
    items: list[EngineCapability] = []
    for name, entry in engines.items():
        item = _engine_capability(name, entry)
        if item is not None:
            items.append(item)
    return Capabilities(engines=tuple(items))


def _engine_capability(name: str, entry: JsonValue) -> EngineCapability | None:
    if name not in Engine.__members__.values() or not isinstance(entry, dict):
        return None
    image, issue, version = entry.get("image"), entry.get("issue"), entry.get("version")
    if image is not None and not (isinstance(image, str) and _is_image(image)):
        return None
    if issue is not None and issue not in CapabilityIssue.__members__.values():
        return None
    if version is not None and not (isinstance(version, str) and _VERSION.fullmatch(version)):
        return None
    return EngineCapability(
        engine=Engine(name),
        image=image,
        issue=CapabilityIssue(issue) if isinstance(issue, str) else None,
        version=version,
    )


NOT_INTEGRATED = "NOT_INTEGRATED"
RUNNER_UNAVAILABLE = "RUNNER_UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class EngineStatus:
    """GET /scanners 的一個引擎。"""

    engine: Engine
    integrated: bool
    available: bool
    image: str | None
    profiles: tuple[ScanProfile, ...]
    unavailable_reason: str | None
    version: str | None = None


def engine_statuses(runner: Capabilities | None) -> tuple[EngineStatus, ...]:
    """runner 是最近一個存活的 runner 回報的能力（沒有存活的 runner 時是 None）。

    只列出請求可以指定的引擎：preflight 是內部的（docs/DECISIONS.md §16.5）。
    """
    reported = {item.engine: item for item in runner.engines} if runner is not None else {}
    return tuple(_status(engine, reported.get(engine)) for engine in SELECTABLE_ENGINES)


def _status(engine: Engine, capability: EngineCapability | None) -> EngineStatus:
    version = capability.version if capability is not None else None
    if engine not in AVAILABLE_ENGINES:
        return EngineStatus(engine, False, False, None, (), NOT_INTEGRATED, version)
    profiles = tuple(ScanProfile)
    if capability is None:
        return EngineStatus(engine, True, False, None, profiles, RUNNER_UNAVAILABLE)
    reason = capability.issue.value if capability.issue is not None else None
    return EngineStatus(
        engine, True, capability.available, capability.image, profiles, reason, version
    )


def _is_image(value: str) -> bool:
    """只轉出合格的映像 ref（repo:tag@sha256:…），不把任意文字經由 GET /scanners 傳給使用者。"""
    try:
        ImageReference.parse(value)
    except ValueError:
        return False
    return True
