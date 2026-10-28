"""capability probe（docs/DECISIONS.md §14.7）：runner 啟動時與每 60 秒確認環境，不通過就不認領。

- daemon 的 API 版本範圍包含 1.45；
- scan_net 存在、internal、gateway 是 isolated（掃描容器連不到宿主與其他網路）；
- runs 與 secrets 兩個 volume 存在，而且 runner 掛載的目錄可寫（權限錯了要在認領之前發現）；
- 每個核准的映像都在本機（runner 不 pull），而且是 daemon 的架構。
egress guard 不可用時，每個引擎都不可用（require_guard；docs/DECISIONS.md §15.7）。
回報只有引擎、映像 ref 與原因代碼。
"""

from collections.abc import Mapping
from dataclasses import replace

from secscan.runner.domain.policy import ENGINE_POLICIES, ContainerPolicy, EnginePolicy
from secscan.runner.domain.runtime import (
    DOCKER_API_VERSION,
    ContainerRuntime,
    EngineVersion,
    RuntimeUnavailableError,
)
from secscan.scanners.domain.instances import Capabilities, CapabilityIssue, EngineCapability
from secscan.scans.domain.catalog import Engine


def probe(
    runtime: ContainerRuntime,
    policy: ContainerPolicy,
    engines: Mapping[Engine, EnginePolicy] = ENGINE_POLICIES,
    *,
    volumes_writable: bool = True,
) -> Capabilities:
    try:
        version = runtime.version()
        environment = _environment_issue(runtime, policy, version)
        if environment is None and not volumes_writable:
            environment = CapabilityIssue.RUN_VOLUME_NOT_WRITABLE
        items = tuple(
            _engine(runtime, engine, engines[engine], version, environment)
            for engine in sorted(engines)
        )
    except RuntimeUnavailableError:
        items = tuple(
            EngineCapability(engine, _image(engines[engine]), CapabilityIssue.DOCKER_UNAVAILABLE)
            for engine in sorted(engines)
        )
    return Capabilities(engines=items)


def _environment_issue(
    runtime: ContainerRuntime, policy: ContainerPolicy, version: EngineVersion
) -> CapabilityIssue | None:
    required = _api(DOCKER_API_VERSION)
    lowest, highest = _api(version.min_api_version), _api(version.api_version)
    if lowest is None or highest is None or required is None or not lowest <= required <= highest:
        return CapabilityIssue.DOCKER_API_UNSUPPORTED
    network = runtime.network(policy.scan_network)
    if network is None or not (network.internal and network.isolated_gateway):
        return CapabilityIssue.SCAN_NETWORK_NOT_ISOLATED
    if not all(runtime.volume_exists(name) for name in (policy.runs_volume, policy.secrets_volume)):
        return CapabilityIssue.RUN_VOLUME_MISSING
    return None


def _engine(
    runtime: ContainerRuntime,
    engine: Engine,
    policy: EnginePolicy,
    version: EngineVersion,
    environment: CapabilityIssue | None,
) -> EngineCapability:
    image = _image(policy)
    if environment is not None:
        return EngineCapability(engine, image, environment)
    if any(runtime.image_architecture(ref) != version.arch for ref in sorted(policy.images)):
        return EngineCapability(engine, image, CapabilityIssue.IMAGE_MISSING)
    return EngineCapability(engine, image, None)


def _image(policy: EnginePolicy) -> str:
    return sorted(policy.images)[0]


def _api(text: str) -> tuple[int, int] | None:
    major, separator, minor = text.partition(".")
    if not (separator and major.isdigit() and minor.isdigit()):
        return None
    return int(major), int(minor)


def require_guard(capabilities: Capabilities, *, available: bool) -> Capabilities:
    """guard 不可用時，原本可用的引擎都改成 GUARD_UNAVAILABLE（其他原因照原樣回報）。"""
    if available:
        return capabilities
    return Capabilities(
        engines=tuple(
            item
            if item.issue is not None
            else replace(item, issue=CapabilityIssue.GUARD_UNAVAILABLE)
            for item in capabilities.engines
        )
    )
