"""每個引擎的 ExecutionPlan（docs/DECISIONS.md §18.7）：完整分派、建好之後再核對引擎與映像。"""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from uuid import uuid4

import pytest

from secscan.auth_profiles.domain.credentials import AuthType, Credential
from secscan.auth_profiles.domain.model import StoredSecret
from secscan.auth_profiles.domain.preflight import Preflight
from secscan.grants.domain.scope import HttpMethod, Scope
from secscan.guard.domain.budget import RunBudget
from secscan.runner import plans
from secscan.runner.domain.admission import PlanRejectedError, PlanRejection
from secscan.runner.plans import ENGINE_IMAGES, RunPlanner
from secscan.scanners.domain.fake import FakeScript
from secscan.scanners.domain.plan import ExecutionPlan
from secscan.scanners.domain.zap.plan import PlanWindowTooSmallError
from secscan.scanners.domain.zap.policy import ZAP_IMAGE
from secscan.scans.domain.catalog import Engine, ScanProfile
from secscan.scans.domain.lifecycle import RunStatus, ScanStatus
from secscan.scans.domain.model import Lease
from secscan.scans.queue import EgressScope, Launch, Progress
from secscan.scans.run_records import SpecInputs
from secscan.targets.domain import parse_origin

NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
ORIGIN = parse_origin("http://lab-web:3000")
SCOPE = Scope(
    origins=(ORIGIN,),
    ips=(IPv4Address("10.89.7.20"),),
    paths=(),
    allow_all_paths=True,
    excluded_paths=(),
    methods=(HttpMethod.GET,),
)
SPEC = SpecInputs(
    document=(
        b'{"info":{"title":"t","version":"1"},"openapi":"3.0.3",'
        b'"paths":{"/items":{"get":{"responses":{"200":{"description":"ok"}}}}},'
        b'"servers":[{"url":"http://lab-web:3000/api"}]}'
    ),
    base_path="/api",
    eligible=frozenset({("GET", "/api/items")}),
)
PREFLIGHT = Preflight(method="GET", path="/me", expected_status=200, expected_json={"/ok": True})
SECRET = StoredSecret(
    profile_id=uuid4(), version=1, credential=Credential(AuthType.BEARER), token=b"x"
)


def _lease(engine: Engine) -> Lease:
    return Lease(run_id=uuid4(), scan_id=uuid4(), engine=engine, owner="runner")


def _launch(
    *,
    profile: ScanProfile | None = ScanProfile.WEB_ACTIVE_LAB,
    seconds: int = 600,
    requests: int = 5_000,
    valid_for: timedelta = timedelta(days=1),
    spec: SpecInputs | None = None,
    egress: bool = True,
) -> Launch:
    return Launch(
        progress=Progress(RunStatus.RUNNING, ScanStatus.RUNNING),
        max_duration_seconds=seconds,
        secret=None,
        egress=EgressScope(
            origin=ORIGIN,
            scope=SCOPE,
            valid_until=NOW + valid_for,
            budget=RunBudget(requests_per_second=2, burst=1, max_requests=requests),
            auth_header=None,
        )
        if egress
        else None,
        scan_profile=profile,
        spec=spec,
    )


def _planner() -> RunPlanner:
    return RunPlanner(script=FakeScript(hold_seconds=1), clock=NOW.timestamp)


def _rejected(lease: Lease, launch: Launch, image_ref: str) -> PlanRejection:
    with pytest.raises(PlanRejectedError) as caught:
        _planner().plan(lease, launch, image_ref=image_ref)
    return caught.value.reason


def test_every_engine_with_an_image_has_its_own_plan() -> None:
    for engine, image in ENGINE_IMAGES.items():
        if engine is Engine.PREFLIGHT:
            continue
        plan = _planner().plan(_lease(engine), _launch(), image_ref=str(image))
        assert (plan.engine, plan.image) == (engine, image)


def test_engines_without_a_plan_are_refused() -> None:
    lease = _lease(Engine.NUCLEI)

    assert _rejected(lease, _launch(), str(ZAP_IMAGE)) is PlanRejection.ENGINE_NOT_ALLOWED


def test_a_plan_for_another_engine_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    planner = _planner()
    fake = planner.plan(_lease(Engine.FAKE), _launch(), image_ref=str(ENGINE_IMAGES[Engine.FAKE]))
    monkeypatch.setattr(planner, "_build", lambda lease, launch: fake)

    with pytest.raises(PlanRejectedError) as caught:
        planner.plan(_lease(Engine.ZAP), _launch(), image_ref=str(ZAP_IMAGE))

    assert caught.value.reason is PlanRejection.ENGINE_NOT_ALLOWED


def test_an_image_other_than_the_recorded_one_is_refused() -> None:
    recorded = str(ENGINE_IMAGES[Engine.FAKE])

    assert _rejected(_lease(Engine.ZAP), _launch(), recorded) is PlanRejection.IMAGE_NOT_APPROVED


def test_zap_needs_the_egress_and_the_profile() -> None:
    image = str(ZAP_IMAGE)

    assert _rejected(_lease(Engine.ZAP), _launch(egress=False), image) is (
        PlanRejection.ENGINE_NOT_ALLOWED
    )
    assert _rejected(_lease(Engine.ZAP), _launch(profile=None), image) is (
        PlanRejection.ENGINE_NOT_ALLOWED
    )


def test_an_api_run_filters_the_spec_before_planning() -> None:
    launch = _launch(profile=ScanProfile.API_ACTIVE_LAB, spec=SPEC)

    plan = _planner().plan(_lease(Engine.ZAP), launch, image_ref=str(ZAP_IMAGE))

    assert [item.name for item in plan.inputs] == ["plan.yaml", "openapi.json"]


def test_a_spec_that_cannot_be_handed_over_is_refused() -> None:
    broken = SpecInputs(document=SPEC.document, base_path="/api", eligible=frozenset())
    launch = _launch(profile=ScanProfile.API_ACTIVE_LAB, spec=broken)

    assert _rejected(_lease(Engine.ZAP), launch, str(ZAP_IMAGE)) is PlanRejection.INPUT_NOT_ALLOWED


def test_an_incompatible_profile_is_refused() -> None:
    launch = _launch(profile=ScanProfile.API_ACTIVE_LAB, spec=None)

    assert _rejected(_lease(Engine.ZAP), launch, str(ZAP_IMAGE)) is PlanRejection.INPUT_NOT_ALLOWED


PREFLIGHT_LAUNCH = replace(_launch(), preflight=PREFLIGHT, secret=SECRET)


@pytest.mark.parametrize(
    "launch",
    [
        replace(PREFLIGHT_LAUNCH, preflight=None),
        replace(PREFLIGHT_LAUNCH, secret=None),
        replace(PREFLIGHT_LAUNCH, egress=None),
    ],
)
def test_a_preflight_without_its_binding_is_refused(launch: Launch) -> None:
    image = str(ENGINE_IMAGES[Engine.PREFLIGHT])

    assert _planner().plan(_lease(Engine.PREFLIGHT), PREFLIGHT_LAUNCH, image_ref=image).engine is (
        Engine.PREFLIGHT
    )
    assert _rejected(_lease(Engine.PREFLIGHT), launch, image) is PlanRejection.ENGINE_NOT_ALLOWED


def test_a_preflight_url_the_builder_refuses_is_an_input_problem(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse(**_: object) -> ExecutionPlan:
        raise ValueError("URL 不合法")

    monkeypatch.setattr(plans, "plan_preflight_run", refuse)
    image = str(ENGINE_IMAGES[Engine.PREFLIGHT])

    assert _rejected(_lease(Engine.PREFLIGHT), PREFLIGHT_LAUNCH, image) is (
        PlanRejection.INPUT_NOT_ALLOWED
    )


@pytest.mark.parametrize(
    "launch",
    [
        _launch(seconds=100),
        _launch(requests=200),
        _launch(valid_for=timedelta(seconds=90)),
        _launch(valid_for=-timedelta(seconds=5)),
    ],
)
def test_too_little_time_requests_or_validity_is_a_budget_problem(launch: Launch) -> None:
    with pytest.raises(PlanWindowTooSmallError):
        _planner().plan(_lease(Engine.ZAP), launch, image_ref=str(ZAP_IMAGE))
