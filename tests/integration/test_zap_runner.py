"""zap 的 run（docs/DECISIONS.md §18）：真的 DB 佇列加上記憶體中的容器 runtime（模擬 ZAP）。

- plan：web 從 / 開始 spider；api 只把 eligible 的 operation 交給 ZAP；認證只以 header 名稱進入
  plan，值由 script 從 0400 的 auth-header 檔讀出。
- secret：proxy-url、zap.properties（proxy 的帳密與速率），有認證時加上 auth-header；容器刪除之後
  全部刪掉。
- 退出碼：0、1、2 收集輸出（manifest 記下退出碼與輸入的 hash），其他是 ENGINE_FAILED。
- 時間或請求數不夠：不建立容器，BUDGET_EXHAUSTED。
每個測試用自己的資料庫（queue_database）。zap 在 T15 才開放：scan 以預覽開關建立。
"""

import json
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.runner.domain.admission import ContainerSpec, managed_run_id
from secscan.runner.domain.policy import ContainerPolicy
from secscan.runner.service import ContainerRunner
from secscan.runner.workspace import Workspace
from secscan.scanners.domain.fake import FakeScript
from secscan.scanners.domain.zap.policy import ZAP_IMAGE
from secscan.scanners.domain.zap.script import SCAN_SCRIPT
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.catalog import ScanProfile
from secscan.scans.domain.lifecycle import RunStatus, ScanStatus
from secscan.scans.domain.model import Scan
from secscan.scans.domain.request import BudgetRequest, ScanRequest
from secscan.scans.queue import ScanQueue
from secscan.targets.domain import TargetKind
from tests.guard_support import ENDPOINT, GuardDouble
from tests.integration.api_support import LAB, Seeder, World
from tests.runner_fakes import FakeClock, FakeContainerRuntime, ScriptedContainer
from tests.secret_support import shared_cipher

pytestmark = pytest.mark.integration

OWNER = "runner-zap-1"
ZAP = frozenset({ScanEngine.ZAP, ScanEngine.PREFLIGHT})
PREVIEW = frozenset({ScanEngine.ZAP})
POLICY = ContainerPolicy(
    scan_network="secscan_scan_net",
    runs_volume="secscan_runs",
    secrets_volume="secscan_run_secrets",
)
SECRET = "canary-zap-bearer-0001"
SPEC = json.dumps(
    {
        "openapi": "3.0.3",
        "info": {"title": "lab", "version": "1"},
        "servers": [{"url": "http://placeholder.invalid/api"}],
        "paths": {
            "/items": {"get": {"responses": {"200": {"description": "ok"}}}},
            "/items/{id}": {"delete": {"responses": {"204": {"description": "gone"}}}},
        },
    }
).encode()
R, S = RunStatus, ScanStatus


@dataclass
class Seen:
    """容器啟動那一刻看到的 secret 檔、輸入檔與環境變數。"""

    secrets: dict[str, bytes] = field(default_factory=dict)
    modes: dict[str, int] = field(default_factory=dict)
    inputs: dict[str, bytes] = field(default_factory=dict)
    env: list[str] = field(default_factory=list)


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
def runtime(clock: FakeClock) -> FakeContainerRuntime:
    return FakeContainerRuntime(clock=clock)


@pytest.fixture
def dirs(tmp_path: Path) -> tuple[Path, Path]:
    runs, secrets = tmp_path / "runs", tmp_path / "secrets"
    runs.mkdir()
    secrets.mkdir()
    return runs, secrets


@pytest.fixture
def make_runner(
    queue: ScanQueue,
    runtime: FakeContainerRuntime,
    dirs: tuple[Path, Path],
    clock: FakeClock,
    tmp_path: Path,
) -> Callable[[], ContainerRunner]:
    guard = GuardDouble.create(tmp_path)

    def factory() -> ContainerRunner:
        return ContainerRunner(
            queue,
            runtime,
            Workspace(*dirs),
            owner=OWNER,
            policy=POLICY,
            script=FakeScript(hold_seconds=1),
            cipher=shared_cipher(),
            guard=guard.channel(),
            endpoint=ENDPOINT,
            sleep=clock.sleep,
            monotonic=clock.monotonic,
        )

    return factory


def _watch(
    runtime: FakeContainerRuntime,
    dirs: tuple[Path, Path],
    *,
    exit_code: int = 2,
    seconds: float = 5,
) -> Seen:
    seen = Seen()

    def capture(spec: ContainerSpec) -> None:
        labels = spec.body["Labels"]
        assert isinstance(labels, dict)
        run = str(managed_run_id(labels))
        for path in (dirs[1] / run).iterdir():
            seen.secrets[path.name] = path.read_bytes()
            seen.modes[path.name] = stat.S_IMODE(path.stat().st_mode)
        for path in (dirs[0] / run / "in").iterdir():
            seen.inputs[path.name] = path.read_bytes()
        env = spec.body["Env"]
        assert isinstance(env, list)
        seen.env = [str(item) for item in env]
        (dirs[0] / run / "out" / "zap-report.json").write_bytes(b'{"site": []}')
        (dirs[0] / run / "out" / "zap.log").write_bytes(b"Automation plan succeeded!\n")

    runtime.scripted[str(ZAP_IMAGE)] = ScriptedContainer(
        seconds=seconds, exit_code=exit_code, on_start=capture
    )
    return seen


def _api_scan(seed: Seeder, world: World, *, authenticated: bool = False, **budget: int) -> Scan:
    target = seed.target(world.operator_a, world.project_a.id)
    grant = seed.approve(
        world.admin,
        seed.grant(world.operator_a, target, paths=("/api/items", "/api/items/{id}", "/me")),
    )
    spec = seed.spec(world.operator_a, target, content=SPEC)
    profile = seed.auth_profile(world.operator_a, target, value=SECRET) if authenticated else None
    request = ScanRequest(
        target_id=target.id,
        scope_grant_id=grant.id,
        api_spec_id=spec.id,
        auth_profile_id=profile.id if profile is not None else None,
        profile=ScanProfile.API_ACTIVE_LAB,
        engines=(ScanEngine.ZAP,),
        budget=BudgetRequest(**budget),
    )
    return seed.create_scan(world.operator_a, request, preview=PREVIEW)


def _web_scan(seed: Seeder, world: World) -> Scan:
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
    return seed.create_scan(world.operator_a, request, preview=PREVIEW)


def _row(seed: Seeder, run_id: UUID) -> Any:
    [row] = seed.query(
        "SELECT engine, status, error_code, container_name, image_ref FROM scanner_runs "
        "WHERE id = :id",
        id=run_id,
    )
    return row


def _manifest(dirs: tuple[Path, Path], run_id: UUID) -> dict[str, Any]:
    document = json.loads((dirs[0] / str(run_id) / "manifest.json").read_bytes())
    assert isinstance(document, dict)
    return document


def test_an_anonymous_web_run_starts_from_the_root_with_only_the_mode(
    make_runner: Callable[[], ContainerRunner],
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
    dirs: tuple[Path, Path],
) -> None:
    seen = _watch(runtime, dirs)
    _web_scan(queue_seed, world)

    report = make_runner().run_once(ZAP)

    assert report is not None
    assert report.run_status is R.COLLECTED
    row = _row(queue_seed, report.run_id)
    assert (row.engine, row.image_ref) == ("zap", str(ZAP_IMAGE))
    [spec] = runtime.created
    assert spec.body["Cmd"] == [SCAN_SCRIPT]
    assert seen.env == ["SECSCAN_TARGET_AUTH=none"]
    assert set(seen.inputs) == {"plan.yaml"}
    plan = json.loads(seen.inputs["plan.yaml"])
    spider = next(job for job in plan["jobs"] if job["type"] == "spider")
    assert spider["parameters"]["url"].endswith("/")
    assert set(seen.secrets) == {"proxy-url", "zap.properties"}
    assert set(seen.modes.values()) == {0o400}


def test_the_proxy_configuration_carries_the_run_token_and_rate(
    make_runner: Callable[[], ContainerRunner],
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
    dirs: tuple[Path, Path],
) -> None:
    seen = _watch(runtime, dirs)
    _web_scan(queue_seed, world)

    report = make_runner().run_once(ZAP)

    assert report is not None
    properties = seen.secrets["zap.properties"].decode()
    proxy_url = seen.secrets["proxy-url"].decode()
    token = proxy_url.removeprefix("http://").split("@", 1)[0].split(":", 1)[1]
    assert f"network.connection.httpProxy.password={token}\n" in properties
    assert f"network.connection.httpProxy.username={report.run_id}\n" in properties
    assert "network.ratelimit.rules.rule(0).reqsPerSec=2\n" in properties
    # 容器刪除之後 secret 全部刪掉。
    assert not (dirs[1] / str(report.run_id)).exists()


def test_an_api_run_gets_only_the_eligible_operations(
    make_runner: Callable[[], ContainerRunner],
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
    dirs: tuple[Path, Path],
) -> None:
    seen = _watch(runtime, dirs)
    scan = _api_scan(queue_seed, world)

    report = make_runner().run_once(ZAP)

    assert report is not None
    assert report.run_status is R.COLLECTED
    spec = json.loads(seen.inputs["openapi.json"])
    # grant 只允許 GET：DELETE 不交給 ZAP（scan 建立時判斷為不在範圍內）。
    assert spec["paths"] == {"/items": {"get": {"responses": {"200": {"description": "ok"}}}}}
    assert spec["servers"] == [{"url": f"{scan.target_origin}/api"}]
    plan = json.loads(seen.inputs["plan.yaml"])
    openapi = next(job for job in plan["jobs"] if job["type"] == "openapi")
    assert openapi["parameters"]["targetUrl"] == f"{scan.target_origin}/api"


def test_an_authenticated_run_names_the_header_but_never_carries_the_value(
    make_runner: Callable[[], ContainerRunner],
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
    dirs: tuple[Path, Path],
) -> None:
    seen = _watch(runtime, dirs)
    scan = _api_scan(queue_seed, world, authenticated=True)
    runner = make_runner()

    preflight = runner.run_once(ZAP)
    zap = runner.run_once(ZAP)

    assert preflight is not None
    assert _row(queue_seed, preflight.run_id).engine == "preflight"
    assert zap is not None
    assert zap.run_status is R.COLLECTED
    assert seen.env == [
        "SECSCAN_TARGET_AUTH=header",
        "ZAP_AUTH_HEADER=Authorization",
        f"ZAP_AUTH_HEADER_SITE={scan.target_origin.host}",
    ]
    assert seen.secrets["auth-header"] == f"Authorization: Bearer {SECRET}".encode()
    zap_spec = runtime.created[-1]
    assert SECRET not in json.dumps(zap_spec.body)
    assert all(SECRET.encode() not in content for content in seen.inputs.values())


@pytest.mark.parametrize("exit_code", [0, 1, 2])
def test_automation_framework_exit_codes_are_collected_with_the_inputs(
    make_runner: Callable[[], ContainerRunner],
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
    dirs: tuple[Path, Path],
    exit_code: int,
) -> None:
    seen = _watch(runtime, dirs, exit_code=exit_code)
    _web_scan(queue_seed, world)

    report = make_runner().run_once(ZAP)

    assert report is not None
    assert report.run_status is R.COLLECTED
    manifest = _manifest(dirs, report.run_id)
    assert manifest["exit_code"] == exit_code
    assert [item["path"] for item in manifest["files"]] == ["zap-report.json", "zap.log"]
    [plan_entry] = manifest["inputs"]
    assert plan_entry["path"] == "plan.yaml"
    assert plan_entry["size"] == len(seen.inputs["plan.yaml"])


@pytest.mark.parametrize("exit_code", [64, 65, 3, 143])
def test_other_exit_codes_fail_the_engine_without_collecting(
    make_runner: Callable[[], ContainerRunner],
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
    dirs: tuple[Path, Path],
    exit_code: int,
) -> None:
    _watch(runtime, dirs, exit_code=exit_code)
    _web_scan(queue_seed, world)

    report = make_runner().run_once(ZAP)

    assert report is not None
    assert (report.run_status, _row(queue_seed, report.run_id).error_code) == (
        R.FAILED,
        "ENGINE_FAILED",
    )
    assert not (dirs[0] / str(report.run_id) / "manifest.json").exists()


def test_out_of_memory_is_a_resource_limit(
    make_runner: Callable[[], ContainerRunner],
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
    dirs: tuple[Path, Path],
) -> None:
    _watch(runtime, dirs)
    runtime.out_of_memory = True
    _web_scan(queue_seed, world)

    report = make_runner().run_once(ZAP)

    assert report is not None
    assert _row(queue_seed, report.run_id).error_code == "RESOURCE_LIMIT_EXCEEDED"


def test_a_window_too_small_for_zap_creates_no_container(
    make_runner: Callable[[], ContainerRunner],
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
) -> None:
    _api_scan(queue_seed, world, max_duration_seconds=100)

    report = make_runner().run_once(ZAP)

    assert report is not None
    row = _row(queue_seed, report.run_id)
    assert (report.run_status, row.error_code) == (R.FAILED, "BUDGET_EXHAUSTED")
    assert runtime.created == []


def test_too_few_requests_for_zap_creates_no_container(
    make_runner: Callable[[], ContainerRunner],
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
) -> None:
    # 2 req/s：200 個請求只夠 100 秒，扣掉保留的時間就不到下限。
    _api_scan(queue_seed, world, max_requests=200)

    report = make_runner().run_once(ZAP)

    assert report is not None
    assert _row(queue_seed, report.run_id).error_code == "BUDGET_EXHAUSTED"
    assert runtime.created == []


def test_a_cancelled_zap_run_blocks_the_guard_and_removes_everything(
    make_runner: Callable[[], ContainerRunner],
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
    dirs: tuple[Path, Path],
    clock: FakeClock,
) -> None:
    _watch(runtime, dirs, seconds=600)
    scan = _web_scan(queue_seed, world)
    clock.at(
        12,
        lambda: queue_seed.execute(
            "UPDATE scans SET cancel_requested_at = now() WHERE id = :id", id=scan.id
        ),
    )

    report = make_runner().run_once(ZAP)

    assert report is not None
    assert report.run_status is R.CANCELLED
    [spec] = runtime.created
    assert spec.name in runtime.stopped
    assert runtime.removed == [spec.name]
    assert not (dirs[1] / str(report.run_id)).exists()
