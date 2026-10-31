"""runner 的迴圈與執行容器驗證的 capability probe（docs/DECISIONS.md §18.8）。

probe 不阻塞迴圈：驗證期間 fake 照常認領，zap 是 ENGINE_PROBE_PENDING、不認領；通過之後 zap 帶著
版本變成可用。runner 停止時刪除執行中的 probe 容器。
每個測試用自己的資料庫（queue_database）。
"""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.runner.domain.admission import ContainerSpec, managed_run_id
from secscan.runner.domain.policy import ContainerPolicy
from secscan.runner.loop import RunnerLoop
from secscan.runner.reconciler import ContainerReconciler
from secscan.runner.service import ContainerRunner
from secscan.runner.workspace import Workspace
from secscan.scanners.domain.fake import FakeScript
from secscan.scanners.domain.instances import InstanceRole
from secscan.scanners.domain.zap.policy import REQUIRED_ADDONS, ZAP_IMAGE, ZAP_VERSION
from secscan.scanners.service import Fleet
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.catalog import ScanProfile
from secscan.scans.domain.lifecycle import RunStatus
from secscan.scans.domain.request import BudgetRequest, ScanRequest
from secscan.scans.queue import ScanQueue
from secscan.targets.domain import TargetKind
from tests.guard_support import ENDPOINT, GuardDouble
from tests.integration.api_support import LAB, Seeder, World
from tests.runner_fakes import FakeClock, FakeContainerRuntime, ScriptedContainer
from tests.secret_support import shared_cipher

pytestmark = pytest.mark.integration

POLICY = ContainerPolicy(
    scan_network="secscan_scan_net",
    runs_volume="secscan_runs",
    secrets_volume="secscan_run_secrets",
)
PROBE_SECONDS = 20


@pytest.fixture
def queue(queue_engine: Engine) -> ScanQueue:
    return ScanQueue(
        sessionmaker(queue_engine, expire_on_commit=False),
        lab=LAB,
        clock=lambda: datetime.now(UTC),
    )


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def dirs(tmp_path: Path) -> tuple[Path, Path]:
    runs, secrets = tmp_path / "runs", tmp_path / "secrets"
    runs.mkdir()
    secrets.mkdir()
    return runs, secrets


@pytest.fixture
def runtime(clock: FakeClock, dirs: tuple[Path, Path]) -> FakeContainerRuntime:
    """zap 的容器：probe 寫出 add-on 清單與報告；掃描寫出報告。"""
    runtime = FakeContainerRuntime(clock=clock)

    def outputs(spec: ContainerSpec) -> None:
        labels = spec.body["Labels"]
        assert isinstance(labels, dict)
        out = dirs[0] / str(managed_run_id(labels)) / "out"
        plugins = "\n".join(f"{name}-beta-{v}.zap" for name, v in REQUIRED_ADDONS.items())
        (out / "plugins.txt").write_text(plugins)
        (out / "probe-report.json").write_text(json.dumps({"@version": ZAP_VERSION}))
        (out / "zap-report.json").write_text("{}")

    runtime.scripted[str(ZAP_IMAGE)] = ScriptedContainer(
        seconds=PROBE_SECONDS, exit_code=0, on_start=outputs
    )
    return runtime


def _loop(
    queue: ScanQueue,
    queue_engine: Engine,
    runtime: FakeContainerRuntime,
    dirs: tuple[Path, Path],
    clock: FakeClock,
    tmp_path: Path,
    *,
    stop_after: float,
) -> RunnerLoop:
    guard = GuardDouble.create(tmp_path).channel()
    workspace = Workspace(*dirs)

    def stop_requested() -> bool:
        return clock.now >= stop_after

    loop = RunnerLoop(
        Fleet(
            sessionmaker(queue_engine, expire_on_commit=False),
            owner="runner:probe",
            role=InstanceRole.RUNNER,
            software_version="0.1.0",
        ),
        runtime=runtime,
        workspace=workspace,
        guard=guard,
        reconciler=ContainerReconciler(queue, runtime, workspace, guard),
        policy=POLICY,
        stop_requested=stop_requested,
        sleep=clock.sleep,
        monotonic=clock.monotonic,
        poll_seconds=2,
    )
    loop.attach(
        ContainerRunner(
            queue,
            runtime,
            workspace,
            owner="runner:probe",
            policy=POLICY,
            script=FakeScript(hold_seconds=1),
            cipher=shared_cipher(),
            guard=guard,
            endpoint=ENDPOINT,
            stop_requested=stop_requested,
            on_heartbeat=loop.beat,
            sleep=clock.sleep,
            monotonic=clock.monotonic,
        )
    )
    return loop


def _zap_capability(seed: Seeder) -> dict[str, Any]:
    [row] = seed.query("SELECT capabilities FROM runner_instances WHERE role = 'runner'")
    capability: dict[str, Any] = row.capabilities["engines"]["zap"]
    return capability


def _web_zap_scan(seed: Seeder, world: World) -> None:
    target = seed.target(world.operator_a, world.project_a.id, kind=TargetKind.WEB)
    grant = seed.approve(world.admin, seed.grant(world.operator_a, target, paths=("/",)))
    request = ScanRequest(
        target_id=target.id,
        scope_grant_id=grant.id,
        api_spec_id=None,
        auth_profile_id=None,
        profile=ScanProfile.WEB_ACTIVE_LAB,
        engines=(ScanEngine.ZAP,),
        budget=BudgetRequest(),
    )
    seed.create_scan(world.operator_a, request)


def test_fake_runs_are_claimed_while_zap_is_being_probed(
    queue: ScanQueue,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    runtime: FakeContainerRuntime,
    dirs: tuple[Path, Path],
    clock: FakeClock,
    tmp_path: Path,
) -> None:
    queue_seed.scan(world.operator_a, queue_seed.scannable(world))
    loop = _loop(queue, queue_engine, runtime, dirs, clock, tmp_path, stop_after=8)

    reports = loop.run()

    assert [report.run_status for report in reports] == [RunStatus.COLLECTED]
    assert _zap_capability(queue_seed)["issue"] == "ENGINE_PROBE_PENDING"
    # runner 停止時刪除執行中的 probe 容器。
    probe = runtime.created[0]
    assert probe.body["Image"] == str(ZAP_IMAGE)
    assert probe.name in runtime.removed


def test_a_zap_run_waits_for_the_probe_and_then_runs(
    queue: ScanQueue,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    runtime: FakeContainerRuntime,
    dirs: tuple[Path, Path],
    clock: FakeClock,
    tmp_path: Path,
) -> None:
    _web_zap_scan(queue_seed, world)
    loop = _loop(queue, queue_engine, runtime, dirs, clock, tmp_path, stop_after=90)

    reports = loop.run()

    assert [report.run_status for report in reports] == [RunStatus.COLLECTED]
    probe, scan = runtime.created
    assert probe.body["Cmd"] != scan.body["Cmd"]
    assert runtime.removed == [probe.name, scan.name]
    assert _zap_capability(queue_seed) == {
        "image": str(ZAP_IMAGE),
        "issue": None,
        "version": ZAP_VERSION,
    }
