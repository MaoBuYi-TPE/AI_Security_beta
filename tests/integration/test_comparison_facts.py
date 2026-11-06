"""比較只讀掃描時凍結的資料，不以現在設定回填舊 scan。"""

from datetime import UTC, datetime
from uuid import UUID

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from secscan.comparisons.inputs import ComparisonInputs
from secscan.findings.domain.taxonomy import mapping_identity
from secscan.findings.service import FindingLinker
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunStatus
from secscan.scans.domain.model import Lease
from secscan.scans.queue import ScanQueue
from tests.integration.api_support import LAB, Seeder
from tests.integration.finding_support import ZAP_SQLI, parsed_run, web_scan, web_target

pytestmark = pytest.mark.integration


def test_reader_preserves_link_mapping_and_unknown_engine_provenance(
    queue_engine: Engine,
    queue_seed: Seeder,
) -> None:
    sessions = sessionmaker(queue_engine, expire_on_commit=False)
    queue = ScanQueue(sessions, lab=LAB, clock=lambda: datetime.now(UTC))
    world = queue_seed.world()
    target, grant = web_target(queue_seed, world)
    baseline = web_scan(queue_seed, world, target, grant, (ScanEngine.ZAP,))
    lease = parsed_run(queue, ScanEngine.ZAP, (ZAP_SQLI,))
    FindingLinker(sessions).link(lease)
    queue.advance(lease, RunStatus.SUCCEEDED)
    current = web_scan(queue_seed, world, target, grant, (ScanEngine.ZAP,))
    other = parsed_run(queue, ScanEngine.ZAP, ())
    FindingLinker(sessions).link(other)
    queue.advance(other, RunStatus.SUCCEEDED)
    with Session(queue_engine) as session:
        inputs = ComparisonInputs(session)
        before, after = inputs.scan(baseline), inputs.scan(current)
        assert before is not None
        assert after is not None
        assert before.scan.mapping_version == mapping_identity()[0]
        assert before.scan.taxonomy_sha256 == mapping_identity()[1]
        assert before.scan.fingerprint_version == "2"
        assert before.scan.scope_sha256 == after.scan.scope_sha256
        assert before.scan.definitions == (("zap", None),)
        assert before.runs[0].identity_verified
        assert not before.runs[0].locations_recorded
        [finding] = inputs.findings(baseline, current)
        assert finding.rule_group == "zap-sql-injection"
        [appearance] = finding.appearances
        assert appearance.scan_id == baseline
        assert appearance.sources[0].source.rule_id == "40018"
        assert appearance.sources[0].paths == ("/search",)
        assert appearance.sources[0].link_taxonomy_sha256 == (mapping_identity()[1],)


@pytest.mark.parametrize("linked", [True, False])
def test_unlinked_observations_are_not_treated_as_zero_findings(
    queue_engine: Engine,
    queue_seed: Seeder,
    linked: bool,
) -> None:
    sessions = sessionmaker(queue_engine, expire_on_commit=False)
    queue = ScanQueue(sessions, lab=LAB, clock=lambda: datetime.now(UTC))
    world = queue_seed.world()
    target, grant = web_target(queue_seed, world)
    scan_id = web_scan(queue_seed, world, target, grant, (ScanEngine.ZAP,))
    lease = parsed_run(queue, ScanEngine.ZAP, (ZAP_SQLI,))
    if linked:
        FindingLinker(sessions).link(lease)
    queue.advance(lease, RunStatus.SUCCEEDED)
    with Session(queue_engine) as session:
        facts = ComparisonInputs(session).scan(scan_id)
        assert facts is not None
        assert facts.runs[0].observations_complete is linked
        assert (facts.scan.mapping_version is not None) is linked


@pytest.mark.parametrize(
    ("preflight", "rejected", "expected"),
    [
        ("passed", 0, True),
        ("passed", 1, False),
        ("inconclusive", 0, False),
    ],
)
def test_scan_identity_uses_preflight_and_run_health_not_only_a_200_response(
    queue_engine: Engine,
    queue_seed: Seeder,
    preflight: str,
    rejected: int,
    expected: bool,
) -> None:
    from secscan.scans.domain.preflight import PreflightResult
    from secscan.scans.domain.traffic import AuthHealth, GuardTraffic
    from tests.integration.test_finding_linker import _authenticated_scan

    sessions = sessionmaker(queue_engine, expire_on_commit=False)
    queue = ScanQueue(sessions, lab=LAB, clock=lambda: datetime.now(UTC))
    world = queue_seed.world()
    scannable = queue_seed.scannable(world)
    _authenticated_scan(queue, queue_seed, world, scannable, PreflightResult(preflight))
    lease = parsed_run(
        queue,
        ScanEngine.ZAP,
        (),
        traffic=GuardTraffic(
            forwarded=5,
            answered=5,
            auth=AuthHealth(accepted=5 - rejected, rejected=rejected, regressed=0),
        ),
    )
    FindingLinker(sessions).link(lease)
    queue.advance(lease, RunStatus.SUCCEEDED)
    with Session(queue_engine) as session:
        facts = ComparisonInputs(session).scan(lease.scan_id)
        assert facts is not None
        assert facts.scan.has_spec
        assert facts.scan.spec_sha256 == scannable.spec.document_sha256.hex()
        assert len(facts.runs) == 1  # preflight 不混入 scanner 的 mapping／definitions。
        assert facts.runs[0].identity_verified is expected
        assert facts.runs[0].observations_complete


def test_location_digest_is_read_without_loading_a_path_or_parameters(
    queue_engine: Engine,
    queue_seed: Seeder,
) -> None:
    import hashlib

    from secscan.scans.domain.locations import Location, LocationSummary

    sessions = sessionmaker(queue_engine, expire_on_commit=False)
    queue = ScanQueue(sessions, lab=LAB, clock=lambda: datetime.now(UTC))
    world = queue_seed.world()
    target, grant = web_target(queue_seed, world)
    scan_id = web_scan(queue_seed, world, target, grant, (ScanEngine.ZAP,))
    lease = parsed_run(queue, ScanEngine.ZAP, ())
    FindingLinker(sessions).link(
        lease,
        locations=LocationSummary(
            (Location("GET", "/private-unrecognized-value", True, False, False, False),),
            (),
            False,
        ),
    )
    queue.advance(lease, RunStatus.SUCCEEDED)
    with Session(queue_engine) as session:
        inputs = ComparisonInputs(session)
        assert inputs.scan(UUID(int=0)) is None
        facts = inputs.scan(scan_id)
        assert facts is not None
        [location] = facts.runs[0].locations
        assert facts.runs[0].locations_recorded
        assert location.path_sha256 == hashlib.sha256(b"/private-unrecognized-value").hexdigest()
        assert "private-unrecognized" not in repr(facts)


def _record_full_run(queue: ScanQueue, engine: ScanEngine) -> tuple[Lease, str]:
    from types import MappingProxyType

    from secscan.grants.domain.scope import HttpMethod
    from secscan.runner.plans import ENGINE_IMAGES
    from secscan.scanners.domain.rule_set import frozen_rule_set
    from secscan.scans.domain.catalog import ScanProfile
    from secscan.scans.domain.observation import ParsedRun, RunOutcome
    from secscan.scans.domain.traffic import GuardTraffic

    rules = frozen_rule_set(engine, ScanProfile.WEB_ACTIVE_LAB, (HttpMethod.GET,))
    assert rules is not None
    runner = queue.claim("provenance-test", frozenset({engine}))
    assert runner is not None
    queue.prepare_launch(runner, image_ref=str(ENGINE_IMAGES[engine]))
    queue.record_plan(
        runner,
        plan_hash="a" * 64,
        profile_definition_sha256="b" * 64,
        rule_set=rules.rules,
        rule_set_sha256=rules.sha256,
    )
    queue.advance(runner, RunStatus.COLLECTING)
    queue.advance(runner, RunStatus.COLLECTED)
    worker = queue.claim_collected("provenance-worker", frozenset({engine}))
    assert worker is not None
    parsed = ParsedRun(
        parser_version="test-parser/1",
        engine_version="test-engine/1",
        components=MappingProxyType({"test-addon": "1"}),
        outcome=RunOutcome(RunStatus.SUCCEEDED),
        traffic=GuardTraffic(forwarded=0, answered=0),
    )
    queue.record_results(worker, parsed, (), exit_code=0)
    return worker, rules.sha256


@pytest.mark.parametrize("engine", [ScanEngine.ZAP, ScanEngine.NUCLEI])
def test_reader_preserves_the_definition_recorded_by_queue_and_parser(
    queue_engine: Engine, queue_seed: Seeder, engine: ScanEngine
) -> None:
    from secscan.comparisons.domain.provenance import EngineProvenance, definition_digest
    from secscan.runner.plans import ENGINE_IMAGES

    sessions = sessionmaker(queue_engine, expire_on_commit=False)
    queue = ScanQueue(sessions, lab=LAB, clock=lambda: datetime.now(UTC))
    world = queue_seed.world()
    target, grant = web_target(queue_seed, world)
    scan_id = web_scan(queue_seed, world, target, grant, (engine,))
    lease, rule_hash = _record_full_run(queue, engine)
    FindingLinker(sessions).link(lease)
    queue.advance(lease, RunStatus.SUCCEEDED)
    with Session(queue_engine) as session:
        facts = ComparisonInputs(session).scan(scan_id)
        assert facts is not None
        expected = definition_digest(
            EngineProvenance(
                engine.value,
                str(ENGINE_IMAGES[engine]),
                "test-engine/1",
                "test-parser/1",
                "b" * 64,
                rule_hash,
                (("test-addon", "1"),),
            )
        )
        assert expected is not None
        assert facts.scan.definitions == ((engine.value, expected),)
        assert facts.runs[0].time_limit_reached is False
        assert facts.runs[0].observations_complete
