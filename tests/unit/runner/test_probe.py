"""capability probe（docs/DECISIONS.md §14.7）：環境不對就不認領。

原因是固定的代碼，不含路徑或秘密。
"""

import pytest

from secscan.runner.domain.runtime import EngineVersion, NetworkState
from secscan.runner.probe import probe, require_guard
from secscan.scanners.domain.fake import FAKE_IMAGE
from secscan.scanners.domain.instances import CapabilityIssue, EngineCapability
from secscan.scanners.domain.preflight import PREFLIGHT_IMAGE
from secscan.scans.domain.catalog import Engine
from tests.runner_fakes import FakeContainerRuntime
from tests.unit.runner.plans import POLICY


def _issue(runtime: FakeContainerRuntime) -> CapabilityIssue | None:
    """fake 與 preflight 用同一個映像與環境：兩者的結果一定相同。"""
    issues = {capability.issue for capability in probe(runtime, POLICY).engines}
    [issue] = issues
    return issue


def test_a_ready_environment_makes_fake_and_preflight_available() -> None:
    capabilities = probe(FakeContainerRuntime(), POLICY)

    assert set(capabilities.engines) == {
        EngineCapability(engine=Engine.FAKE, image=str(FAKE_IMAGE), issue=None),
        EngineCapability(engine=Engine.PREFLIGHT, image=str(PREFLIGHT_IMAGE), issue=None),
    }
    assert capabilities.available_engines == frozenset({Engine.FAKE, Engine.PREFLIGHT})


@pytest.mark.parametrize("operation", ["version", "network", "volume_exists", "image_architecture"])
def test_docker_errors_make_everything_unavailable(operation: str) -> None:
    runtime = FakeContainerRuntime()
    runtime.failing.add(operation)

    assert _issue(runtime) is CapabilityIssue.DOCKER_UNAVAILABLE


@pytest.mark.parametrize(
    ("api", "minimum"), [("1.44", "1.40"), ("1.54", "1.46"), ("2.0", "1.46"), ("x", "1.40")]
)
def test_the_daemon_must_speak_api_1_45(api: str, minimum: str) -> None:
    runtime = FakeContainerRuntime(engine=EngineVersion(api, minimum, "linux", "arm64"))

    assert _issue(runtime) is CapabilityIssue.DOCKER_API_UNSUPPORTED


@pytest.mark.parametrize("api", ["1.45", "1.54", "1.100"])
def test_newer_daemons_are_fine(api: str) -> None:
    runtime = FakeContainerRuntime(engine=EngineVersion(api, "1.24", "linux", "arm64"))

    assert _issue(runtime) is None


@pytest.mark.parametrize(
    "networks",
    [
        {},
        {"secscan_scan_net": NetworkState(internal=False, isolated_gateway=True)},
        {"secscan_scan_net": NetworkState(internal=True, isolated_gateway=False)},
    ],
)
def test_the_scan_network_must_be_internal_and_isolated(
    networks: dict[str, NetworkState],
) -> None:
    assert _issue(FakeContainerRuntime(networks=networks)) is (
        CapabilityIssue.SCAN_NETWORK_NOT_ISOLATED
    )


@pytest.mark.parametrize("missing", ["secscan_runs", "secscan_run_secrets"])
def test_both_volumes_must_exist(missing: str) -> None:
    runtime = FakeContainerRuntime()
    runtime.volumes.discard(missing)

    assert _issue(runtime) is CapabilityIssue.RUN_VOLUME_MISSING


@pytest.mark.parametrize("images", [{}, {str(FAKE_IMAGE): "amd64"}])
def test_the_image_must_be_present_for_this_architecture(images: dict[str, str]) -> None:
    assert _issue(FakeContainerRuntime(images=images)) is CapabilityIssue.IMAGE_MISSING


def test_volumes_the_runner_cannot_write_make_engines_unavailable() -> None:
    """volume 的權限錯了，要在認領之前發現，而不是在 prepare 之後（審查發現）。"""
    engines = probe(FakeContainerRuntime(), POLICY, volumes_writable=False).engines

    assert {capability.issue for capability in engines} == {CapabilityIssue.RUN_VOLUME_NOT_WRITABLE}


# --- egress guard（docs/DECISIONS.md §15.7）------------------------------------------------


def test_an_unavailable_guard_makes_every_ready_engine_unavailable() -> None:
    ready = probe(FakeContainerRuntime(), POLICY)

    assert require_guard(ready, available=True) == ready
    engines = require_guard(ready, available=False).engines
    assert {capability.issue for capability in engines} == {CapabilityIssue.GUARD_UNAVAILABLE}
    assert require_guard(ready, available=False).available_engines == frozenset()


def test_other_problems_are_reported_before_the_guard() -> None:
    runtime = FakeContainerRuntime()
    runtime.failing.add("version")
    broken = probe(runtime, POLICY)

    engines = require_guard(broken, available=False).engines

    assert {capability.issue for capability in engines} == {CapabilityIssue.DOCKER_UNAVAILABLE}
