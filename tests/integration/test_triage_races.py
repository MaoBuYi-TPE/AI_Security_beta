"""T21 的併發（G1）：兩條真實連線，以 pg_stat_activity 確認對手正在等列鎖，再檢查最後的 DB 狀態。"""

from collections.abc import Callable
from uuid import UUID

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from secscan.api_keys.domain import Principal
from secscan.comparisons.service import ComparisonService
from secscan.core.errors import AppError
from secscan.findings.domain.model import LifecycleState, TriageState
from secscan.findings.domain.triage import ResolutionBasis
from secscan.findings.service import FindingLinker
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunStatus
from secscan.triage.domain.attestation import Attestation
from secscan.triage.service import TriageCommand, TriageService
from tests.integration.api_support import Seeder, World
from tests.integration.database import ProvisionedDatabase
from tests.integration.finding_support import ZAP_CORS, ZAP_SQLI, parsed_run, web_scan
from tests.integration.locks import Race, wait_until_waiting_for_a_lock
from tests.integration.triage_support import (
    Scenario,
    db_now,
    eligible,
    queue,
    run_scan,
    scenario,
)

pytestmark = pytest.mark.integration
CONFIRM = TriageCommand(expected_version=0, reason="確認", triage=TriageState.CONFIRMED)


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


@pytest.fixture
def item(queue_engine: Engine, queue_seed: Seeder, world: World) -> Scenario:
    return scenario(queue_engine, queue_seed, world)


def change(principal: Principal, finding: UUID, command: TriageCommand) -> Callable[[Session], str]:
    def work(session: Session) -> str:
        TriageService(session).change(principal, finding, command, request_id=None)
        return "changed"

    return work


def events(seed: Seeder, finding: UUID) -> list[tuple[int, str, str]]:
    rows = seed.query(
        "SELECT sequence, lifecycle_state, actor_kind FROM finding_triage_events "
        "WHERE finding_id = :id ORDER BY sequence",
        id=finding,
    )
    return [(row.sequence, row.lifecycle_state, row.actor_kind) for row in rows]


def resolve(engine: Engine, seed: Seeder, world: World, item: Scenario) -> None:
    comparison = eligible(engine, item)
    principal = world.operator_a.principal
    with sessionmaker(engine).begin() as session:
        TriageService(session).change(principal, item.sqli, CONFIRM, request_id=None)
    command = TriageCommand(
        expected_version=1,
        reason="人工複測",
        lifecycle=LifecycleState.RESOLVED,
        basis=ResolutionBasis.MANUAL_RETEST,
        comparison_id=comparison,
        attestation=_attestation(item, seed),
    )
    with sessionmaker(engine).begin() as session:
        TriageService(session).change(principal, item.sqli, command, request_id=None)


def _attestation(item: Scenario, seed: Seeder) -> Attestation:
    return Attestation(
        performed_at=db_now(seed),
        performed_by="operator",
        procedure="複測",
        result="not_reproduced",
        auth_role="anonymous",
        request_excerpt=f"GET /search?q=1 HTTP/1.1\nHost: {item.host}\n",
        response_excerpt="HTTP/1.1 200\n\n[]",
    )


def test_two_patches_with_the_same_version_produce_one_event(
    queue_database: ProvisionedDatabase,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    item: Scenario,
) -> None:
    principal = world.operator_a.principal
    rival = Race(queue_database, "triage-rival", change(principal, item.sqli, CONFIRM))
    with sessionmaker(queue_engine).begin() as session:
        TriageService(session).change(principal, item.sqli, CONFIRM, request_id=None)
        rival.start()
        wait_until_waiting_for_a_lock(queue_seed, "triage-rival")
    rival.join()
    assert rival.results == []
    [error] = rival.errors
    assert isinstance(error, AppError)
    assert error.code == "VERSION_CONFLICT"
    assert events(queue_seed, item.sqli) == [(1, "open", "key")]


def test_manual_and_automatic_reopen_never_reopen_twice(
    queue_database: ProvisionedDatabase,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    item: Scenario,
) -> None:
    resolve(queue_engine, queue_seed, world, item)
    _, lease = run_scan(
        queue_engine, queue_seed, world, item.target, item.grant_id, (ZAP_SQLI,), link=False
    )

    def link(session: Session) -> object:
        # 以對手自己的連線（application_name = linker-rival）執行 linker 的 transaction。
        return FindingLinker(sessionmaker(session.get_bind(), expire_on_commit=False)).link(lease)

    rival = Race(queue_database, "linker-rival", link)
    manual = TriageCommand(expected_version=2, reason="人工重開", lifecycle=LifecycleState.REOPENED)
    with sessionmaker(queue_engine).begin() as session:
        TriageService(session).change(
            world.operator_a.principal, item.sqli, manual, request_id=None
        )
        rival.start()
        wait_until_waiting_for_a_lock(queue_seed, "linker-rival")
    rival.join()
    assert rival.errors == []
    queue(queue_engine).advance(lease, RunStatus.SUCCEEDED)
    assert events(queue_seed, item.sqli)[-1] == (3, "reopened", "key")
    assert len(events(queue_seed, item.sqli)) == 3


def test_a_scan_created_while_resolving_still_reopens(
    queue_database: ProvisionedDatabase,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    item: Scenario,
) -> None:
    [cache] = queue_seed.query(
        "SELECT seqcache FROM pg_sequence "
        "WHERE seqrelid = pg_get_serial_sequence('scans', 'queue_position')::regclass"
    )
    assert cache.seqcache == 1
    comparison = eligible(queue_engine, item)
    principal = world.operator_a.principal
    with sessionmaker(queue_engine).begin() as session:
        TriageService(session).change(principal, item.sqli, CONFIRM, request_id=None)
    command = TriageCommand(
        expected_version=1,
        reason="人工複測",
        lifecycle=LifecycleState.RESOLVED,
        basis=ResolutionBasis.MANUAL_RETEST,
        comparison_id=comparison,
        attestation=_attestation(item, queue_seed),
    )
    with sessionmaker(queue_engine).begin() as session:
        TriageService(session).change(principal, item.sqli, command, request_id=None)
        # resolve 尚未提交時建立的 scan：位置一定大於 trigger 寫入的 watermark。
        web_scan(queue_seed, world, item.target, item.grant_id, (ScanEngine.ZAP,))
    lease = parsed_run(queue(queue_engine), ScanEngine.ZAP, (ZAP_SQLI,))
    FindingLinker(sessionmaker(queue_engine, expire_on_commit=False)).link(lease)
    queue(queue_engine).advance(lease, RunStatus.SUCCEEDED)
    assert events(queue_seed, item.sqli)[-1] == (3, "reopened", "system")


def test_comparison_creation_does_not_wait_for_linker_locks(
    queue_database: ProvisionedDatabase,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    item: Scenario,
) -> None:
    """linker 以 FOR NO KEY UPDATE 鎖 finding；建立比較快照時 FK 的 KEY SHARE 不必等待。"""
    later, _ = run_scan(queue_engine, queue_seed, world, item.target, item.grant_id, (ZAP_CORS,))
    principal = world.operator_a.principal

    def compare(session: Session) -> object:
        return ComparisonService(session).create(principal, item.baseline, later, request_id=None)

    rival = Race(queue_database, "comparison-rival", compare)
    with sessionmaker(queue_engine).begin() as session:
        session.execute(
            text(
                "SELECT id FROM findings WHERE target_id = :target ORDER BY fingerprint "
                "FOR NO KEY UPDATE"
            ),
            {"target": item.target.id},
        )
        rival.start()
        rival.join()
        assert rival.errors == []
    assert len(rival.results) == 1
