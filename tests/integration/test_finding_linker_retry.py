"""T22 linker 重試：保留凍結證據、lease fencing 與 mapping 不符時 fail closed。"""

from dataclasses import replace
from unittest.mock import Mock, create_autospec
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.findings import records
from secscan.findings.domain.taxonomy import mapping_identity
from secscan.findings.errors import MappingChangedError
from secscan.findings.service import FindingLinker
from secscan.guard.domain.telemetry import RunSummary
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.coverage import Exchange
from secscan.scans.domain.lifecycle import RunStatus
from secscan.scans.leases import LeaseLostError
from secscan.scans.queue import ScanQueue
from secscan.worker.locations import summarize_locations
from secscan.worker.service import Worker
from secscan.worker.telemetry import TelemetryReader
from tests.integration.api_support import Seeder, World
from tests.integration.finding_support import ZAP_SQLI, parsed_run, web_scan, web_target
from tests.integration.test_finding_linker import linker as linker
from tests.integration.test_finding_linker import queue as queue
from tests.integration.test_finding_linker import world as world

pytestmark = pytest.mark.integration
ZAP = ScanEngine.ZAP


def _retry_evidence(seed: Seeder, run_id: UUID) -> tuple[object, ...]:
    """取得不可變證據快照；不包含重試時正常改變的 lease 與 coverage。

    seed 必須是 owner（queue_owner_seed）：應用程式角色只能新增 run_rule_locations，不能讀取。
    """
    run = seed.query(
        "SELECT link_mapping_version, link_taxonomy_sha256, locations_recorded "
        "FROM scanner_runs WHERE id = :run",
        run=run_id,
    )
    observations = seed.query(
        "SELECT o.* FROM observations o WHERE o.scanner_run_id = :run ORDER BY o.ordinal",
        run=run_id,
    )
    links = seed.query(
        "SELECT l.* FROM finding_observations l JOIN observations o ON o.id = l.observation_id "
        "WHERE o.scanner_run_id = :run ORDER BY o.ordinal",
        run=run_id,
    )
    findings = seed.query("SELECT * FROM findings ORDER BY id")
    locations = seed.query(
        "SELECT * FROM run_locations WHERE scanner_run_id = :run ORDER BY method, path_sha256",
        run=run_id,
    )
    rules = seed.query(
        "SELECT * FROM run_rule_locations WHERE scanner_run_id = :run "
        "ORDER BY method, path_sha256, rule",
        run=run_id,
    )
    return tuple(
        tuple(dict(row._mapping) for row in rows)
        for rows in (run, observations, links, findings, locations, rules)
    )


@pytest.mark.parametrize("has_observations", [True, False], ids=["linked", "zero-observations"])
@pytest.mark.parametrize("changed_part", ["version", "taxonomy"])
def test_worker_retries_committed_links_with_a_different_mapping(
    queue: ScanQueue,
    linker: FindingLinker,
    queue_engine: Engine,
    queue_seed: Seeder,
    queue_owner_seed: Seeder,
    world: World,
    monkeypatch: pytest.MonkeyPatch,
    has_observations: bool,
    changed_part: str,
) -> None:
    """link transaction 已提交、coverage 前中斷；重部署後沿用原證據完成。"""
    target, grant_id = web_target(queue_seed, world)
    web_scan(queue_seed, world, target, grant_id, (ZAP,))
    lease = parsed_run(queue, ZAP, (ZAP_SQLI,) if has_observations else ())
    original = summarize_locations((Exchange("GET", "/search", False, 200, "40018"),))
    assert linker.link(lease, locations=original) == int(has_observations)
    before = _retry_evidence(queue_owner_seed, lease.run_id)
    [run] = queue_seed.query(
        "SELECT coverage_recorded, status FROM scanner_runs WHERE id = :run", run=lease.run_id
    )
    assert (run.coverage_recorded, run.status) == (False, "normalizing")
    queue_seed.execute(
        "UPDATE scanner_runs SET lease_expires_at = now() - interval '1 second' WHERE id = :id",
        id=lease.run_id,
    )
    version, digest = mapping_identity()
    changed = (version + "-new", digest) if changed_part == "version" else (version, "f" * 64)
    assert changed != (version, digest)
    monkeypatch.setattr("secscan.findings.service.mapping_identity", lambda: changed)
    new_linker = FindingLinker(sessionmaker(queue_engine, expire_on_commit=False))
    with pytest.raises(LeaseLostError):
        new_linker.link(lease, locations=original)
    telemetry = create_autospec(TelemetryReader, instance=True)
    telemetry.summary.return_value = RunSummary(lease.run_id, lease.scan_id, uuid4(), 1)
    telemetry.comparison_exchanges.return_value = (
        Exchange("GET", "/new-location", False, 200, "new-rule"),
    )
    telemetry.exchanges.return_value = (Exchange("GET", "/search", False, 200, "40018"),)
    reports = Worker(queue, owner="worker-2", findings=new_linker, telemetry=telemetry).drain()

    assert len(reports) == 1
    assert (reports[0].run_id, reports[0].run_status) == (lease.run_id, RunStatus.SUCCEEDED)
    [completed] = queue_seed.query(
        "SELECT status, coverage_recorded FROM scanner_runs WHERE id = :run", run=lease.run_id
    )
    assert (completed.status, completed.coverage_recorded) == ("succeeded", True)
    assert _retry_evidence(queue_owner_seed, lease.run_id) == before


@pytest.mark.parametrize("changed_part", ["version", "taxonomy"])
def test_unlinked_observations_reject_a_different_frozen_mapping(
    queue: ScanQueue,
    queue_engine: Engine,
    queue_seed: Seeder,
    queue_owner_seed: Seeder,
    world: World,
    monkeypatch: pytest.MonkeyPatch,
    changed_part: str,
) -> None:
    """既有 provenance 但仍有未連結觀察，不能以新版分類補寫。"""
    target, grant_id = web_target(queue_seed, world)
    web_scan(queue_seed, world, target, grant_id, (ZAP,))
    lease = parsed_run(queue, ZAP, (ZAP_SQLI,))
    sessions = sessionmaker(queue_engine, expire_on_commit=False)
    summary = summarize_locations((Exchange("GET", "/search", False, 200, "40018"),))
    mapping = mapping_identity()
    # 模擬歷史不完整證據：以真實 fenced transaction 凍結 mapping，但不建立連結。
    with sessions.begin() as session:
        store = records.FindingRecords(session)
        store.lock_run(lease)
        store.record_comparison(lease, mapping, summary)
    before = _retry_evidence(queue_owner_seed, lease.run_id)
    changed = (
        (mapping[0] + "-new", mapping[1]) if changed_part == "version" else (mapping[0], "f" * 64)
    )
    assert changed != mapping
    monkeypatch.setattr("secscan.findings.service.mapping_identity", lambda: changed)
    new_linker = FindingLinker(sessions)

    with pytest.raises(MappingChangedError, match="mapping") as error:
        new_linker.link(lease, locations=summary)
    assert isinstance(error.value, ValueError)
    assert _retry_evidence(queue_owner_seed, lease.run_id) == before
    [run] = queue_seed.query(
        "SELECT status, coverage_recorded FROM scanner_runs WHERE id = :run", run=lease.run_id
    )
    assert (run.status, run.coverage_recorded) == ("normalizing", False)


@pytest.mark.parametrize("has_observations", [True, False], ids=["linked", "zero-observations"])
@pytest.mark.parametrize("invalid_part", ["owner", "scan"])
def test_frozen_retry_still_requires_a_valid_lease(
    queue: ScanQueue,
    linker: FindingLinker,
    queue_seed: Seeder,
    queue_owner_seed: Seeder,
    world: World,
    has_observations: bool,
    invalid_part: str,
) -> None:
    target, grant = web_target(queue_seed, world)
    web_scan(queue_seed, world, target, grant, (ZAP,))
    lease = parsed_run(queue, ZAP, (ZAP_SQLI,) if has_observations else ())
    assert linker.link(lease) == int(has_observations)
    before = _retry_evidence(queue_owner_seed, lease.run_id)
    invalid = (
        replace(lease, owner="another-worker")
        if invalid_part == "owner"
        else replace(lease, scan_id=uuid4())
    )

    with pytest.raises(LeaseLostError):
        linker.link(invalid)
    assert _retry_evidence(queue_owner_seed, lease.run_id) == before


@pytest.mark.parametrize("has_observations", [True, False], ids=["linked", "zero-observations"])
def test_frozen_retry_does_not_backfill_missing_locations(
    queue: ScanQueue,
    linker: FindingLinker,
    queue_seed: Seeder,
    queue_owner_seed: Seeder,
    world: World,
    has_observations: bool,
) -> None:
    target, grant = web_target(queue_seed, world)
    web_scan(queue_seed, world, target, grant, (ZAP,))
    lease = parsed_run(queue, ZAP, (ZAP_SQLI,) if has_observations else ())
    assert linker.link(lease) == int(has_observations)
    before = _retry_evidence(queue_owner_seed, lease.run_id)
    summary = summarize_locations((Exchange("GET", "/search", False, 200, "40018"),))

    assert linker.link(lease, locations=summary) == 0
    assert _retry_evidence(queue_owner_seed, lease.run_id) == before
    [run] = queue_seed.query(
        "SELECT locations_recorded FROM scanner_runs WHERE id = :run", run=lease.run_id
    )
    assert run.locations_recorded is False


def test_unlinked_observations_with_the_same_mapping_can_finish_without_replacing_locations(
    queue: ScanQueue,
    linker: FindingLinker,
    queue_engine: Engine,
    queue_seed: Seeder,
    queue_owner_seed: Seeder,
    world: World,
) -> None:
    target, grant = web_target(queue_seed, world)
    web_scan(queue_seed, world, target, grant, (ZAP,))
    lease = parsed_run(queue, ZAP, (ZAP_SQLI,))
    original = summarize_locations((Exchange("GET", "/search", False, 200, "40018"),))
    with sessionmaker(queue_engine).begin() as session:
        store = records.FindingRecords(session)
        store.lock_run(lease)
        store.record_comparison(lease, mapping_identity(), original)
    before = _retry_evidence(queue_owner_seed, lease.run_id)
    replacement = summarize_locations((Exchange("GET", "/new-location", False, 200, "new"),))

    assert linker.link(lease, locations=replacement) == 1
    after = _retry_evidence(queue_owner_seed, lease.run_id)
    assert after[0] == before[0]
    assert after[-2:] == before[-2:]
    [linked] = queue_seed.query("SELECT count(*) AS n FROM finding_observations")
    assert linked.n == 1
    assert linker.link(lease) == 0


def test_a_late_link_failure_rolls_back_all_comparison_and_finding_evidence(
    queue: ScanQueue,
    linker: FindingLinker,
    queue_seed: Seeder,
    queue_owner_seed: Seeder,
    world: World,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, grant = web_target(queue_seed, world)
    web_scan(queue_seed, world, target, grant, (ZAP,))
    lease = parsed_run(queue, ZAP, (ZAP_SQLI,))
    before = _retry_evidence(queue_owner_seed, lease.run_id)
    summary = summarize_locations((Exchange("GET", "/search", False, 200, "40018"),))
    with monkeypatch.context() as patch:
        patch.setattr(
            records.FindingRecords,
            "insert_links",
            Mock(side_effect=RuntimeError("link write failed")),
        )
        with pytest.raises(RuntimeError, match="link write failed"):
            linker.link(lease, locations=summary)
    assert _retry_evidence(queue_owner_seed, lease.run_id) == before
    assert linker.link(lease, locations=summary) == 1
