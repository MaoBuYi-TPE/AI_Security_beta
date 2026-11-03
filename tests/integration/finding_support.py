"""finding 的整合測試共用（T19）：建立 web scan、以佇列寫入觀察（和 parser 同一個契約）。"""

from collections.abc import Sequence
from uuid import UUID

from secscan.runner.plans import ENGINE_IMAGES
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.catalog import ScanProfile
from secscan.scans.domain.lifecycle import RunStatus
from secscan.scans.domain.model import Lease
from secscan.scans.domain.observation import (
    ObservationInput,
    ParameterLocation,
    ParsedRun,
    RunOutcome,
    event_id,
)
from secscan.scans.domain.request import BudgetRequest, ScanRequest
from secscan.scans.domain.traffic import GuardTraffic
from secscan.scans.queue import RunUsage, ScanQueue
from secscan.targets.domain import Target, TargetKind
from tests.integration.api_support import Seeder, World


def observation(
    rule: str,
    variant: str | None = None,
    *,
    severity: str = "2",
    path: str = "/",
    parameter: str | None = None,
    cwe: int | None = None,
    nuclei: bool = False,
) -> ObservationInput:
    return ObservationInput(
        source_event_id=event_id(rule, variant or "", path, parameter or "", severity),
        source_index=0,
        source_rule=rule,
        rule_variant=variant if variant is not None else (None if nuclei else rule),
        title=f"title of {rule}",
        raw_severity=severity,
        severity_label="Medium",
        raw_confidence="unknown" if nuclei else "2",
        confidence_label="Unknown" if nuclei else "Medium",
        cwe_id=cwe,
        wasc_id=None,
        method="GET",
        path=path,
        query=None,
        parameter=parameter,
        parameter_location=ParameterLocation.QUERY if parameter else ParameterLocation.UNKNOWN,
        attack=None,
        evidence=None,
        other_info=None,
    )


ZAP_CORS = observation("10098", cwe=264)
ZAP_XCTO = observation("10021", severity="1", parameter="x-content-type-options", cwe=693)
ZAP_SQLI = observation("40018", severity="3", path="/search", parameter="q", cwe=89)
NUCLEI_CORS = observation(
    "cors-misconfig", "arbitrary-origin", severity="info", cwe=346, nuclei=True
)
NUCLEI_XCTO = observation(
    "http-missing-security-headers", "x-content-type-options", severity="info", nuclei=True
)
NUCLEI_TECH = observation("tech-detect", "python", severity="info", nuclei=True)


def web_target(seed: Seeder, world: World) -> tuple[Target, UUID]:
    target = seed.target(world.operator_a, world.project_a.id, kind=TargetKind.WEB)
    grant = seed.approve(
        world.admin,
        seed.grant(world.operator_a, target, paths=(), allow_all_paths=True, methods=("GET",)),
    )
    return target, grant.id


def web_scan(
    seed: Seeder, world: World, target: Target, grant_id: UUID, engines: Sequence[ScanEngine]
) -> UUID:
    request = ScanRequest(
        target_id=target.id,
        scope_grant_id=grant_id,
        api_spec_id=None,
        auth_profile_id=None,
        profile=ScanProfile.WEB_ACTIVE_LAB,
        engines=tuple(engines),
        budget=BudgetRequest(),
    )
    return seed.create_scan(world.operator_a, request).id


def parsed_run(
    queue: ScanQueue,
    engine: ScanEngine,
    observations: Sequence[ObservationInput],
    *,
    traffic: GuardTraffic | None = None,
) -> Lease:
    """runner 收集完、worker 認領並寫入觀察（normalizing 的 lease）。"""
    runner = queue.claim("runner-1", frozenset({engine}))
    assert runner is not None
    queue.prepare_launch(runner, image_ref=str(ENGINE_IMAGES[engine]))
    queue.record_usage(runner, RunUsage(requests_sent=1, requests_denied=0, traffic_seconds=1))
    queue.advance(runner, RunStatus.COLLECTING)
    queue.advance(runner, RunStatus.COLLECTED)
    lease = queue.claim_collected("worker-1", frozenset({engine}))
    assert lease is not None
    parsed = ParsedRun(
        parser_version="test-1",
        outcome=RunOutcome(RunStatus.SUCCEEDED),
        observations=tuple(observations),
        traffic=traffic,
    )
    queue.record_results(lease, parsed, (), exit_code=0)
    return lease
