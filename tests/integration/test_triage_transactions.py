"""T21 的交易一致性（G2）：在每一步之間拋錯，整筆回滾、不留半套資料；重試不重複產生事件。"""

from collections.abc import Callable
from typing import Any

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.audit.service import AuditTrail
from secscan.findings.domain.model import LifecycleState, TriageState
from secscan.findings.domain.triage import ResolutionBasis
from secscan.findings.service import FindingLinker
from secscan.findings.triage_records import TriageRecords
from secscan.scans.domain.lifecycle import RunStatus
from secscan.triage.service import TriageCommand, TriageService
from tests.integration.api_support import Seeder, World
from tests.integration.finding_support import ZAP_SQLI
from tests.integration.test_triage_races import _attestation, resolve
from tests.integration.triage_support import Scenario, eligible, queue, run_scan, scenario

pytestmark = pytest.mark.integration


class InjectedError(RuntimeError):
    """故障注入：模擬寫到一半時程序或 DB 失敗。"""


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


@pytest.fixture
def item(queue_engine: Engine, queue_seed: Seeder, world: World) -> Scenario:
    return scenario(queue_engine, queue_seed, world)


def snapshot(seed: Seeder, item: Scenario) -> tuple[Any, ...]:
    [finding] = seed.query(
        "SELECT triage_state, lifecycle_state, triage_version, resolved_scan_position "
        "FROM findings WHERE id = :id",
        id=item.sqli,
    )
    counts = seed.query(
        "SELECT (SELECT count(*) FROM finding_triage_events WHERE finding_id = :id) AS events, "
        "(SELECT count(*) FROM finding_triage_excerpts WHERE finding_id = :id) AS excerpts, "
        "(SELECT count(*) FROM audit_events WHERE object_id = :id) AS audits, "
        "(SELECT count(*) FROM finding_observations WHERE finding_id = :id) AS links",
        id=item.sqli,
    )[0]
    return (*finding, counts.events, counts.excerpts, counts.audits, counts.links)


def fail(*_: object, **__: object) -> None:
    raise InjectedError


def run_change(engine: Engine, world: World, item: Scenario, command: TriageCommand) -> None:
    with sessionmaker(engine).begin() as session:
        TriageService(session).change(
            world.operator_a.principal, item.sqli, command, request_id=None
        )


CONFIRM = TriageCommand(expected_version=0, reason="確認", triage=TriageState.CONFIRMED)


@pytest.mark.parametrize(
    "target",
    [
        (TriageRecords, "append"),
        (AuditTrail, "record"),
    ],
)
def test_a_failed_triage_write_rolls_back_everything(
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    item: Scenario,
    monkeypatch: pytest.MonkeyPatch,
    target: tuple[type, str],
) -> None:
    before = snapshot(queue_seed, item)
    monkeypatch.setattr(*target, fail)
    with pytest.raises(InjectedError):
        run_change(queue_engine, world, item, CONFIRM)
    assert snapshot(queue_seed, item) == before
    monkeypatch.undo()
    run_change(queue_engine, world, item, CONFIRM)
    assert snapshot(queue_seed, item)[2] == 1


@pytest.mark.parametrize("step", ["append_excerpts", "record"])
def test_a_failed_resolve_leaves_no_partial_evidence(
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    item: Scenario,
    monkeypatch: pytest.MonkeyPatch,
    step: str,
) -> None:
    comparison = eligible(queue_engine, item)
    run_change(queue_engine, world, item, CONFIRM)
    before = snapshot(queue_seed, item)
    owner: Callable[..., Any] | type = TriageRecords if step == "append_excerpts" else AuditTrail
    monkeypatch.setattr(owner, step, fail)
    command = TriageCommand(
        expected_version=1,
        reason="人工複測",
        lifecycle=LifecycleState.RESOLVED,
        basis=ResolutionBasis.MANUAL_RETEST,
        comparison_id=comparison,
        attestation=_attestation(item, queue_seed),
    )
    with pytest.raises(InjectedError):
        run_change(queue_engine, world, item, command)
    assert snapshot(queue_seed, item) == before


def test_a_failed_reopen_rolls_back_the_links_and_the_retry_reopens_once(
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    item: Scenario,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolve(queue_engine, queue_seed, world, item)
    before = snapshot(queue_seed, item)
    _, lease = run_scan(
        queue_engine, queue_seed, world, item.target, item.grant_id, (ZAP_SQLI,), link=False
    )
    linker = FindingLinker(sessionmaker(queue_engine, expire_on_commit=False))
    monkeypatch.setattr(AuditTrail, "record", fail)
    with pytest.raises(InjectedError):
        linker.link(lease)
    assert snapshot(queue_seed, item) == before
    monkeypatch.undo()
    assert linker.link(lease) == 1
    queue(queue_engine).advance(lease, RunStatus.SUCCEEDED)
    after = snapshot(queue_seed, item)
    assert after[1:3] == ("reopened", 3)
    assert after[4] == before[4] + 1
    assert after[7] == before[7] + 1
