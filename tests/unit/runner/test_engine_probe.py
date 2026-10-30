"""執行容器驗證的 capability probe（docs/DECISIONS.md §18.8）。

runner 的迴圈每圈前進一步：建立與啟動 probe 容器、查狀態、讀結果、刪除。probe 期間其他引擎照常
可用；zap 只有驗證通過才可用。結果以映像快取，失敗以退避重試；runner 停止時刪除執行中的容器。
"""

import json
from collections.abc import Callable
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from secscan.runner.domain.admission import ContainerSpec, managed_run_id
from secscan.runner.engine_probe import PROBE_RETRY_SECONDS, EngineProber
from secscan.runner.probe import probe
from secscan.runner.workspace import Workspace
from secscan.scanners.domain.instances import Capabilities, CapabilityIssue, EngineCapability
from secscan.scanners.domain.zap.policy import REQUIRED_ADDONS, ZAP_IMAGE, ZAP_VERSION
from secscan.scanners.domain.zap.probe import PROBE_WALL_CLOCK_SECONDS
from secscan.scans.domain.catalog import Engine
from tests.runner_fakes import FakeContainerRuntime, ScriptedContainer
from tests.unit.runner.plans import POLICY

PLUGINS = "\n".join(
    f"{name}-release-{version}.zap" for name, version in REQUIRED_ADDONS.items()
).encode()
REPORT = json.dumps({"@version": ZAP_VERSION, "site": []}).encode()


@pytest.fixture
def dirs(tmp_path: Path) -> tuple[Path, Path]:
    runs, secrets = tmp_path / "runs", tmp_path / "secrets"
    runs.mkdir()
    secrets.mkdir()
    return runs, secrets


@pytest.fixture
def runtime() -> FakeContainerRuntime:
    return FakeContainerRuntime()


def _writer(
    runs: Path, *, plugins: bytes | None = PLUGINS, report: bytes | None = REPORT
) -> Callable[[ContainerSpec], None]:
    def write(spec: ContainerSpec) -> None:
        labels = spec.body["Labels"]
        assert isinstance(labels, dict)
        run_id = managed_run_id(labels)
        out = runs / str(run_id) / "out"
        if plugins is not None:
            (out / "plugins.txt").write_bytes(plugins)
        if report is not None:
            (out / "probe-report.json").write_bytes(report)

    return write


def _prober(runtime: FakeContainerRuntime, dirs: tuple[Path, Path]) -> EngineProber:
    return EngineProber(runtime, Workspace(*dirs), POLICY, monotonic=runtime.clock.monotonic)


def _zap(capabilities: Capabilities) -> EngineCapability:
    [zap] = [item for item in capabilities.engines if item.engine is Engine.ZAP]
    return zap


def _settle(prober: EngineProber, runtime: FakeContainerRuntime, base: Capabilities) -> None:
    """模擬 runner 的迴圈：每圈一步、每圈一秒，直到 probe 結束（或上限）。"""
    for _ in range(PROBE_WALL_CLOCK_SECONDS + 30):
        prober.step(base)
        if not prober.running:
            return
        runtime.clock.sleep(1)


def test_zap_is_pending_until_the_probe_passes(
    runtime: FakeContainerRuntime, dirs: tuple[Path, Path]
) -> None:
    runtime.scripted[str(ZAP_IMAGE)] = ScriptedContainer(seconds=15, on_start=_writer(dirs[0]))
    prober = _prober(runtime, dirs)
    base = probe(runtime, POLICY)

    assert _zap(prober.apply(base)).issue is CapabilityIssue.ENGINE_PROBE_PENDING
    prober.step(base)
    assert prober.running
    assert _zap(prober.apply(base)).issue is CapabilityIssue.ENGINE_PROBE_PENDING
    # probe 期間其他引擎照常可用。
    assert {Engine.FAKE, Engine.PREFLIGHT} <= prober.apply(base).available_engines

    _settle(prober, runtime, base)

    zap = _zap(prober.apply(base))
    assert (zap.issue, zap.version) == (None, ZAP_VERSION)
    assert prober.addons == dict(REQUIRED_ADDONS)


def test_the_probe_container_is_hardened_like_a_scan_and_then_removed(
    runtime: FakeContainerRuntime, dirs: tuple[Path, Path]
) -> None:
    runtime.scripted[str(ZAP_IMAGE)] = ScriptedContainer(on_start=_writer(dirs[0]))
    prober = _prober(runtime, dirs)

    _settle(prober, runtime, probe(runtime, POLICY))

    [spec] = runtime.created
    body = spec.body
    assert body["Image"] == str(ZAP_IMAGE)
    assert body["User"] == "10001:10001"
    host = body["HostConfig"]
    assert isinstance(host, dict)
    assert host["ReadonlyRootfs"] is True
    assert host["Tmpfs"] == {"/tmp": "rw,noexec,nosuid,nodev,size=768m,mode=1777"}  # noqa: S108
    assert body["Env"] == []
    assert runtime.removed == [spec.name]
    labels = body["Labels"]
    assert isinstance(labels, dict)
    probe_id = managed_run_id(labels)
    # secret 目錄在容器刪除之後清掉；runs 的目錄留著（和 run 一樣，保留期限在 M5）。
    assert not (dirs[1] / str(probe_id)).exists()


def test_a_verified_image_is_not_probed_again(
    runtime: FakeContainerRuntime, dirs: tuple[Path, Path]
) -> None:
    runtime.scripted[str(ZAP_IMAGE)] = ScriptedContainer(on_start=_writer(dirs[0]))
    prober = _prober(runtime, dirs)
    base = probe(runtime, POLICY)
    _settle(prober, runtime, base)

    for _ in range(5):
        prober.step(base)
        runtime.clock.sleep(PROBE_RETRY_SECONDS)

    assert len(runtime.created) == 1


@pytest.mark.parametrize(
    ("script", "issue"),
    [
        (ScriptedContainer(exit_code=1), CapabilityIssue.ENGINE_PROBE_FAILED),
        (ScriptedContainer(exit_code=2), CapabilityIssue.ENGINE_INCOMPATIBLE),
    ],
)
def test_a_failed_probe_keeps_zap_unavailable_and_retries_later(
    runtime: FakeContainerRuntime,
    dirs: tuple[Path, Path],
    script: ScriptedContainer,
    issue: CapabilityIssue,
) -> None:
    script.on_start = _writer(dirs[0])
    runtime.scripted[str(ZAP_IMAGE)] = script
    prober = _prober(runtime, dirs)
    base = probe(runtime, POLICY)

    _settle(prober, runtime, base)

    assert _zap(prober.apply(base)).issue is issue
    prober.step(base)
    assert len(runtime.created) == 1
    runtime.clock.sleep(PROBE_RETRY_SECONDS)
    prober.step(base)
    assert len(runtime.created) == 2


def test_missing_outputs_are_a_probe_failure(
    runtime: FakeContainerRuntime, dirs: tuple[Path, Path]
) -> None:
    runtime.scripted[str(ZAP_IMAGE)] = ScriptedContainer(on_start=_writer(dirs[0], report=None))
    prober = _prober(runtime, dirs)
    base = probe(runtime, POLICY)

    _settle(prober, runtime, base)

    assert _zap(prober.apply(base)).issue is CapabilityIssue.ENGINE_PROBE_FAILED


def test_a_different_version_is_incompatible(
    runtime: FakeContainerRuntime, dirs: tuple[Path, Path]
) -> None:
    report = json.dumps({"@version": "2.16.0"}).encode()
    runtime.scripted[str(ZAP_IMAGE)] = ScriptedContainer(on_start=_writer(dirs[0], report=report))
    prober = _prober(runtime, dirs)
    base = probe(runtime, POLICY)

    _settle(prober, runtime, base)

    assert _zap(prober.apply(base)).issue is CapabilityIssue.ENGINE_INCOMPATIBLE


def test_a_probe_that_never_ends_is_stopped_and_removed(
    runtime: FakeContainerRuntime, dirs: tuple[Path, Path]
) -> None:
    runtime.scripted[str(ZAP_IMAGE)] = ScriptedContainer(seconds=10_000)
    prober = _prober(runtime, dirs)
    base = probe(runtime, POLICY)

    _settle(prober, runtime, base)

    assert not prober.running
    [spec] = runtime.created
    assert spec.name in runtime.stopped
    assert runtime.removed == [spec.name]
    assert _zap(prober.apply(base)).issue is CapabilityIssue.ENGINE_PROBE_FAILED


def test_docker_errors_while_starting_are_a_probe_failure(
    runtime: FakeContainerRuntime, dirs: tuple[Path, Path]
) -> None:
    runtime.failing.add("start")
    prober = _prober(runtime, dirs)
    base = probe(runtime, POLICY)

    prober.step(base)

    assert not prober.running
    assert _zap(prober.apply(base)).issue is CapabilityIssue.ENGINE_PROBE_FAILED
    assert runtime.removed == [runtime.created[0].name]


def test_a_container_that_cannot_be_removed_leaves_its_secret_directory(
    runtime: FakeContainerRuntime, dirs: tuple[Path, Path]
) -> None:
    """runner 下次啟動時，依證據的清理以 secret 目錄找回容器並刪除（§17.4）。"""
    runtime.scripted[str(ZAP_IMAGE)] = ScriptedContainer(on_start=_writer(dirs[0]))
    prober = _prober(runtime, dirs)
    base = probe(runtime, POLICY)
    prober.step(base)
    [spec] = runtime.created
    runtime.broken.add(spec.name)

    _settle(prober, runtime, base)

    labels = spec.body["Labels"]
    assert isinstance(labels, dict)
    assert (dirs[1] / str(managed_run_id(labels))).is_dir()
    assert _zap(prober.apply(base)).issue is None


def test_zap_is_probed_only_when_its_image_and_environment_are_ready(
    runtime: FakeContainerRuntime, dirs: tuple[Path, Path]
) -> None:
    del runtime.images[str(ZAP_IMAGE)]
    prober = _prober(runtime, dirs)
    base = probe(runtime, POLICY)

    prober.step(base)

    assert runtime.created == []
    assert _zap(prober.apply(base)).issue is CapabilityIssue.IMAGE_MISSING


def test_closing_removes_a_running_probe(
    runtime: FakeContainerRuntime, dirs: tuple[Path, Path]
) -> None:
    runtime.scripted[str(ZAP_IMAGE)] = ScriptedContainer(seconds=60)
    prober = _prober(runtime, dirs)
    prober.step(probe(runtime, POLICY))
    [spec] = runtime.created

    prober.close()

    assert runtime.removed == [spec.name]
    assert not prober.running


def test_each_attempt_uses_a_new_identity(
    runtime: FakeContainerRuntime, dirs: tuple[Path, Path]
) -> None:
    runtime.scripted[str(ZAP_IMAGE)] = ScriptedContainer(exit_code=1)
    prober = _prober(runtime, dirs)
    base = probe(runtime, POLICY)
    _settle(prober, runtime, base)
    runtime.clock.sleep(PROBE_RETRY_SECONDS)
    _settle(prober, runtime, base)

    names = [spec.name for spec in runtime.created]
    assert len(set(names)) == 2
    ids: list[UUID | None] = []
    for spec in runtime.created:
        labels = spec.body["Labels"]
        assert isinstance(labels, dict)
        ids.append(managed_run_id(labels))
    assert all(isinstance(value, UUID) and value != uuid4() for value in ids)
