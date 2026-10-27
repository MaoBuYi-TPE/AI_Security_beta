"""ExecutionPlan 的驗證（SEC-12 的應用層、docs/DECISIONS.md §14.3）。

每一類未核准的內容都被拒絕；訊息只有原因，不含被拒絕的值。
"""

from dataclasses import replace

import pytest
from hypothesis import given
from hypothesis import strategies as st

from secscan.runner.domain.admission import PlanRejectedError, PlanRejection, admit
from secscan.runner.domain.policy import ENGINE_POLICIES, ArgumentPattern, CommandTemplate
from secscan.scanners.domain.fake import MAX_HOLD_SECONDS, FakeOutcome, FakeScript
from secscan.scanners.domain.plan import ExecutionPlan, ImageReference, InputFile, ResourceLimits
from secscan.scans.domain.catalog import Engine
from tests.unit.runner.plans import fake_plan

DIGEST = "sha256:" + "cd" * 32
PLAN = fake_plan()


def _rejected(plan: ExecutionPlan) -> PlanRejection:
    with pytest.raises(PlanRejectedError) as caught:
        admit(plan)
    return caught.value.reason


@given(
    outcome=st.sampled_from(FakeOutcome),
    hold=st.floats(min_value=0, max_value=MAX_HOLD_SECONDS),
    target_auth=st.booleans(),
)
def test_every_fake_plan_is_admitted(outcome: FakeOutcome, hold: float, target_auth: bool) -> None:
    admit(fake_plan(FakeScript(outcome=outcome, hold_seconds=hold), target_auth=target_auth))


@pytest.mark.parametrize("engine", [Engine.ZAP, Engine.NUCLEI, Engine.SCHEMATHESIS])
def test_engines_without_a_policy_are_rejected(engine: Engine) -> None:
    assert _rejected(replace(PLAN, engine=engine)) is PlanRejection.ENGINE_NOT_ALLOWED


@pytest.mark.parametrize(
    "image",
    [
        f"busybox:1.38.0@{DIGEST}",
        f"busybox:1.37.0@{PLAN.image.digest}",
        f"library/busybox:1.38.0@{PLAN.image.digest}",
        f"alpine:3.22@{PLAN.image.digest}",
    ],
)
def test_unapproved_images_are_rejected(image: str) -> None:
    plan = replace(PLAN, image=ImageReference.parse(image))

    assert _rejected(plan) is PlanRejection.IMAGE_NOT_APPROVED


@pytest.mark.parametrize(
    ("entrypoint", "arguments"),
    [
        (("/bin/sh",), ("-c", "sleep 5")),
        (("sh",), ()),
        (("/bin/busybox",), ("sh",)),
        (("/bin/sleep",), ("5", "6")),
        (("/bin/sleep",), ()),
        (("/bin/sleep",), ("5;id",)),
        (("/bin/sleep",), ("1000",)),
        (("/bin/sleep",), ("-1",)),
        (("/bin/sleep",), (" 5",)),
        (("/bin/sleep",), ("5\n",)),
        (("/bin/false",), ("x",)),
        (("/bin/sleep", "5"), ()),
        ((), ("5",)),
        (("/bin/wget",), ("http://example.com",)),
        (("/bin/cat",), ("/scan/secret/target-auth",)),
    ],
)
def test_commands_outside_the_templates_are_rejected(
    entrypoint: tuple[str, ...], arguments: tuple[str, ...]
) -> None:
    plan = replace(PLAN, entrypoint=entrypoint, arguments=arguments)

    assert _rejected(plan) is PlanRejection.COMMAND_NOT_ALLOWED


@pytest.mark.parametrize(
    "environment",
    [
        (("HTTP_PROXY", "http://guard:8080"),),
        (("LD_PRELOAD", "/scan/in/x.so"),),
        (("PATH", "/scan/in"),),
    ],
)
def test_environment_outside_the_allowlist_is_rejected(
    environment: tuple[tuple[str, str], ...],
) -> None:
    assert _rejected(replace(PLAN, environment=environment)) is (
        PlanRejection.ENVIRONMENT_NOT_ALLOWED
    )


def test_environment_values_must_match_their_pattern() -> None:
    policy = replace(
        ENGINE_POLICIES[Engine.FAKE], environment={"FAKE_MODE": ArgumentPattern(r"[a-z]{1,8}")}
    )
    policies = {Engine.FAKE: policy}

    admit(replace(PLAN, environment=(("FAKE_MODE", "quiet"),)), policies)
    for value in ("Quiet", "quiet\n", "a" * 9, "", "q\x00"):
        with pytest.raises(PlanRejectedError) as caught:
            admit(replace(PLAN, environment=(("FAKE_MODE", value),)), policies)
        assert caught.value.reason is PlanRejection.ENVIRONMENT_NOT_ALLOWED
    with pytest.raises(PlanRejectedError) as twice:
        admit(replace(PLAN, environment=(("FAKE_MODE", "a"), ("FAKE_MODE", "b"))), policies)
    assert twice.value.reason is PlanRejection.ENVIRONMENT_NOT_ALLOWED


@pytest.mark.parametrize(
    "inputs",
    [
        (InputFile("plan.yaml", b"x"),),
        (InputFile("run.json", b"{}"), InputFile("run.json", b"{}")),
        (InputFile("run.json", b"x" * 4097),),
    ],
)
def test_inputs_outside_the_allowlist_are_rejected(inputs: tuple[InputFile, ...]) -> None:
    assert _rejected(replace(PLAN, inputs=inputs)) is PlanRejection.INPUT_NOT_ALLOWED


def test_target_auth_needs_an_engine_that_accepts_it() -> None:
    policies = {Engine.FAKE: replace(ENGINE_POLICIES[Engine.FAKE], accepts_target_auth=False)}

    admit(PLAN, policies)
    with pytest.raises(PlanRejectedError) as caught:
        admit(replace(PLAN, target_auth=True), policies)
    assert caught.value.reason is PlanRejection.TARGET_AUTH_NOT_ALLOWED


@pytest.mark.parametrize("field", ["memory_bytes", "nano_cpus", "pids", "wall_clock_seconds"])
def test_limits_above_the_engine_cap_are_rejected(field: str) -> None:
    cap = getattr(ENGINE_POLICIES[Engine.FAKE].max_limits, field)
    limits = replace(PLAN.limits, **{field: cap + 1})

    assert _rejected(replace(PLAN, limits=limits)) is PlanRejection.LIMITS_OUT_OF_RANGE


def test_limits_at_the_cap_are_admitted() -> None:
    admit(replace(PLAN, limits=ENGINE_POLICIES[Engine.FAKE].max_limits))


def test_the_rejection_does_not_echo_the_value() -> None:
    secret_like = "Bearer secscan-canary-value"
    plan = replace(PLAN, arguments=(secret_like,))

    with pytest.raises(PlanRejectedError) as caught:
        admit(plan)

    assert secret_like not in str(caught.value)
    assert "canary" not in repr(caught.value)


def test_templates_match_whole_arguments_only() -> None:
    template = CommandTemplate(entrypoint=("/bin/sleep",), arguments=(ArgumentPattern(r"[0-9]+"),))

    assert template.matches(("/bin/sleep",), ("12",))
    assert not template.matches(("/bin/sleep",), ("12a",))
    assert not template.matches(("/bin/sleep",), ("a12",))
    assert not template.matches(("/bin/sleep",), ())
    assert not template.matches(("/bin/sleep", "x"), ("12",))


def test_resource_limits_type_is_shared() -> None:
    assert isinstance(ENGINE_POLICIES[Engine.FAKE].max_limits, ResourceLimits)
