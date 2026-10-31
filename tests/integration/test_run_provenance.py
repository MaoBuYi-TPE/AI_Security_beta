"""每個 run 實際執行的內容（docs/DECISIONS.md §20.2；migration 0011）。

- runner 在建立容器之前寫入 plan_hash（ExecutionPlan 的 sha256）與 zap 的 profile 定義：不論之後
  是否收集，版本都留下（預算用盡、時間上限、取消的 run 也有）。
- 沒有建立容器的 run（BUDGET_EXHAUSTED、PLAN_REJECTED）沒有 plan_hash。
- 預算不同，plan.yaml 的 maxDuration 與牆鐘上限不同，hash 也不同。
- DB：sha256 的格式、只有容器版的 run 有 plan_hash、只有 zap 有 profile 定義；只能寫一次（應用程式
  的條件與 DB 的 trigger）。
每個測試用自己的資料庫（queue_database）。
"""

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from secscan.runner.service import ContainerRunner
from secscan.runner.workspace import Workspace
from secscan.scanners.domain.fake import FAKE_IMAGE, FakeScript
from secscan.scanners.domain.profiles import zap_definition_sha256
from secscan.scanners.domain.zap.policy import ZAP_IMAGE
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.catalog import ScanProfile
from secscan.scans.domain.lifecycle import RunStatus
from secscan.scans.domain.request import BudgetRequest, ScanRequest
from secscan.scans.queue import LeaseLostError, ScanQueue
from secscan.scans.repository import ScanRepository
from secscan.targets.domain import TargetKind
from tests.guard_support import ENDPOINT, GuardDouble
from tests.integration.api_support import LAB, Seeder, World
from tests.integration.sql_support import (
    CHECK_VIOLATION,
    INTEGRITY_CONSTRAINT_VIOLATION,
    violation,
)
from tests.integration.test_zap_runner import POLICY
from tests.runner_fakes import FakeClock, FakeContainerRuntime, ScriptedContainer
from tests.secret_support import shared_cipher

pytestmark = pytest.mark.integration

OWNER = "runner-provenance"
ZAP = frozenset({ScanEngine.ZAP})
SHA = "ab" * 32


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
def make_runner(
    queue: ScanQueue, runtime: FakeContainerRuntime, clock: FakeClock, tmp_path: Path
) -> Callable[[], ContainerRunner]:
    runs, secrets = tmp_path / "runs", tmp_path / "secrets"
    runs.mkdir()
    secrets.mkdir()
    guard = GuardDouble.create(tmp_path)

    def factory() -> ContainerRunner:
        return ContainerRunner(
            queue,
            runtime,
            Workspace(runs, secrets),
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


def _web_scan(
    seed: Seeder, world: World, *, engine: ScanEngine = ScanEngine.ZAP, **budget: int
) -> UUID:
    target = seed.target(world.operator_a, world.project_a.id, kind=TargetKind.WEB)
    grant = seed.approve(world.admin, seed.grant(world.operator_a, target, paths=("/",)))
    request = ScanRequest(
        target_id=target.id,
        scope_grant_id=grant.id,
        api_spec_id=None,
        auth_profile_id=None,
        profile=ScanProfile.WEB_ACTIVE_LAB,
        engines=(engine,),
        budget=BudgetRequest(**budget),
    )
    return seed.create_scan(world.operator_a, request).id


def _provenance(seed: Seeder, run_id: UUID) -> Any:
    [row] = seed.query(
        "SELECT status, error_code, plan_hash, profile_definition_sha256 FROM scanner_runs "
        "WHERE id = :id",
        id=run_id,
    )
    return row


def _exit(runtime: FakeContainerRuntime, exit_code: int) -> None:
    runtime.scripted[str(ZAP_IMAGE)] = ScriptedContainer(seconds=5, exit_code=exit_code)


def test_the_runner_records_what_it_executed(
    make_runner: Callable[[], ContainerRunner],
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
) -> None:
    _exit(runtime, 0)
    _web_scan(queue_seed, world)

    report = make_runner().run_once(ZAP)

    assert report is not None
    row = _provenance(queue_seed, report.run_id)
    assert row.plan_hash is not None
    assert len(row.plan_hash) == 64
    assert row.profile_definition_sha256 == zap_definition_sha256(ScanProfile.WEB_ACTIVE_LAB)


def test_an_uncollected_run_keeps_its_version(
    make_runner: Callable[[], ContainerRunner],
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
) -> None:
    """退出碼不是 AF 的（不收集）：之後查得到當時執行的 plan（§20.2）。"""
    _exit(runtime, 143)
    _web_scan(queue_seed, world)

    report = make_runner().run_once(ZAP)

    assert report is not None
    row = _provenance(queue_seed, report.run_id)
    assert (row.status, row.error_code) == ("failed", "ENGINE_FAILED")
    assert row.plan_hash is not None
    assert row.profile_definition_sha256 is not None


def test_a_run_without_a_container_has_no_plan(
    make_runner: Callable[[], ContainerRunner],
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
) -> None:
    _web_scan(queue_seed, world, max_duration_seconds=100)

    report = make_runner().run_once(ZAP)

    assert report is not None
    row = _provenance(queue_seed, report.run_id)
    assert (row.error_code, row.plan_hash, row.profile_definition_sha256) == (
        "BUDGET_EXHAUSTED",
        None,
        None,
    )
    assert runtime.created == []


def test_the_budget_is_part_of_the_plan(
    make_runner: Callable[[], ContainerRunner],
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
) -> None:
    """maxDuration 與牆鐘上限來自預算：預算不同，hash 就不同；規則的定義相同。"""
    _exit(runtime, 0)
    _web_scan(queue_seed, world, max_duration_seconds=600)
    _web_scan(queue_seed, world, max_duration_seconds=900)
    runner = make_runner()

    first, second = runner.run_once(ZAP), runner.run_once(ZAP)

    assert first is not None
    assert second is not None
    one, two = _provenance(queue_seed, first.run_id), _provenance(queue_seed, second.run_id)
    assert one.plan_hash != two.plan_hash
    assert one.profile_definition_sha256 == two.profile_definition_sha256


def test_the_scan_shows_the_run_versions(
    make_runner: Callable[[], ContainerRunner],
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
    queue_engine: Engine,
) -> None:
    _exit(runtime, 143)
    scan_id = _web_scan(queue_seed, world)
    report = make_runner().run_once(ZAP)
    assert report is not None
    stored = _provenance(queue_seed, report.run_id)

    with Session(queue_engine) as session:
        scan = ScanRepository(session).get(scan_id)

    assert scan is not None
    [run] = scan.runs
    assert (run.plan_hash, run.profile_definition_sha256) == (
        stored.plan_hash,
        stored.profile_definition_sha256,
    )


def test_a_preflight_run_has_a_plan_but_no_profile_definition(
    make_runner: Callable[[], ContainerRunner],
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
) -> None:
    """profile 的規則定義只屬於 zap；preflight 的 run 也記下自己執行的 plan。"""
    _exit(runtime, 0)
    target = queue_seed.target(world.operator_a, world.project_a.id, kind=TargetKind.WEB)
    grant = queue_seed.approve(
        world.admin, queue_seed.grant(world.operator_a, target, paths=("/", "/me"))
    )
    profile = queue_seed.auth_profile(world.operator_a, target)
    request = ScanRequest(
        target_id=target.id,
        scope_grant_id=grant.id,
        api_spec_id=None,
        auth_profile_id=profile.id,
        profile=ScanProfile.WEB_ACTIVE_LAB,
        engines=(ScanEngine.ZAP,),
        budget=BudgetRequest(),
    )
    queue_seed.create_scan(world.operator_a, request)

    preflight = make_runner().run_once(frozenset({ScanEngine.PREFLIGHT, ScanEngine.ZAP}))

    assert preflight is not None
    row = _provenance(queue_seed, preflight.run_id)
    assert row.plan_hash is not None
    assert row.profile_definition_sha256 is None


def test_the_plan_is_recorded_once(queue: ScanQueue, queue_seed: Seeder, world: World) -> None:
    _web_scan(queue_seed, world)
    lease = queue.claim(OWNER, ZAP)
    assert lease is not None
    launch = queue.prepare_launch(lease, image_ref=str(ZAP_IMAGE))
    assert launch.progress.run_status is RunStatus.RUNNING

    queue.record_plan(lease, plan_hash=SHA, profile_definition_sha256=SHA)

    with pytest.raises(LeaseLostError):
        queue.record_plan(lease, plan_hash="cd" * 32, profile_definition_sha256=None)
    assert _provenance(queue_seed, lease.run_id).plan_hash == SHA


# --- DB 約束 -------------------------------------------------------------------------------

SET_PLAN = (
    "UPDATE scanner_runs SET plan_hash = :plan, profile_definition_sha256 = :definition "
    "WHERE id = :run"
)


def _running(queue: ScanQueue, seed: Seeder, world: World, engine: ScanEngine) -> UUID:
    _web_scan(seed, world, engine=engine)
    lease = queue.claim(OWNER, frozenset({engine}))
    assert lease is not None
    image = ZAP_IMAGE if engine is ScanEngine.ZAP else FAKE_IMAGE
    assert (
        queue.prepare_launch(lease, image_ref=str(image)).progress.run_status is RunStatus.RUNNING
    )
    return lease.run_id


@pytest.mark.parametrize(
    ("plan", "definition", "constraint"),
    [
        ("AB" * 32, None, "ck_scanner_runs_plan_hash_valid"),
        ("ab" * 31, None, "ck_scanner_runs_plan_hash_valid"),
        (SHA, "x" * 64, "ck_scanner_runs_profile_definition_valid"),
        (None, SHA, "ck_scanner_runs_profile_definition_valid"),
    ],
)
def test_invalid_versions_are_rejected(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    queue_engine: Engine,
    plan: str | None,
    definition: str | None,
    constraint: str,
) -> None:
    run_id = _running(queue, queue_seed, world, ScanEngine.ZAP)

    with Session(queue_engine) as session:
        error = violation(
            session, SET_PLAN, {"plan": plan, "definition": definition, "run": run_id}
        )

    assert (error.sqlstate, error.diag.constraint_name) == (CHECK_VIOLATION, constraint)


def test_only_container_runs_have_a_plan(
    queue_seed: Seeder, world: World, queue_engine: Engine
) -> None:
    scan_id = _web_scan(queue_seed, world)
    [run] = queue_seed.query("SELECT id FROM scanner_runs WHERE scan_id = :id", id=scan_id)

    with Session(queue_engine) as session:
        error = violation(session, SET_PLAN, {"plan": SHA, "definition": None, "run": run.id})

    assert error.diag.constraint_name == "ck_scanner_runs_plan_hash_valid"


def test_only_zap_runs_have_a_profile_definition(
    queue: ScanQueue, queue_seed: Seeder, world: World, queue_engine: Engine
) -> None:
    run_id = _running(queue, queue_seed, world, ScanEngine.FAKE)

    with Session(queue_engine) as session:
        error = violation(session, SET_PLAN, {"plan": SHA, "definition": SHA, "run": run_id})
        # plan 本身是合法的（fake 也是容器版的 run）。
        session.execute(text(SET_PLAN), {"plan": SHA, "definition": None, "run": run_id})

    assert error.diag.constraint_name == "ck_scanner_runs_profile_definition_valid"


def test_the_database_keeps_the_first_plan(
    queue: ScanQueue, queue_seed: Seeder, world: World, queue_engine: Engine
) -> None:
    """應用程式以 plan_hash IS NULL 為條件只寫一次；DB 的 trigger 也擋改寫（T16 的審查）。"""
    run_id = _running(queue, queue_seed, world, ScanEngine.ZAP)
    with Session(queue_engine) as session, session.begin():
        session.execute(text(SET_PLAN), {"plan": SHA, "definition": SHA, "run": run_id})

    with Session(queue_engine) as session:
        for plan, definition in (("cd" * 32, SHA), (SHA, None), (None, None)):
            error = violation(
                session, SET_PLAN, {"plan": plan, "definition": definition, "run": run_id}
            )
            assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION
            assert "plan can only be recorded once" in str(error)
        # 其他欄位照常可以更新（run 還沒結束）。
        session.execute(
            text("UPDATE scanner_runs SET heartbeat_at = heartbeat_at WHERE id = :run"),
            {"run": run_id},
        )
