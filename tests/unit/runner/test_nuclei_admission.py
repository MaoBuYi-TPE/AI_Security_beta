"""nuclei 的政策、admission 與 create 的 body（T18；docs/DECISIONS.md §14.3、§18.1、§23）。

- 合法的 nuclei plan 通過驗證；映像以 digest 獨立核准，模板以每檔 sha256（來自 lock）核准。
- 竄改模板、改參數、改環境變數都被拒絕；只收集退出碼 0；輸出要遮罩。
- tmpfs 只接受政策宣告的固定值，送出前以 admission 自己的字面值核對。
"""

import copy
from dataclasses import replace
from typing import Any

import pytest

from secscan.runner.domain import admission
from secscan.runner.domain.admission import (
    IN_DIR,
    OUT_DIR,
    PROXY_FILE,
    SECRET_DIR,
    ContainerSpec,
    PlanRejectedError,
    PlanRejection,
    admit,
    build_container,
    check_container_spec,
    container_spec,
)
from secscan.runner.domain.inputs import ContentDigest
from secscan.runner.domain.policy import ENGINE_POLICIES
from secscan.scanners.domain.nuclei import plan as nuclei_plan
from secscan.scanners.domain.nuclei.plan import NucleiBudget, plan_nuclei_run
from secscan.scanners.domain.nuclei.policy import NUCLEI_IMAGE, load_templates
from secscan.scanners.domain.plan import ExecutionPlan, InputFile, ResourceLimits
from secscan.scans.domain.catalog import Engine
from secscan.targets.domain import parse_origin
from tests.unit.runner.plans import POLICY, RUN_ID, SCAN_ID, fake_plan

ORIGIN = parse_origin("http://lab-web:3000")
BUDGET = NucleiBudget(requests_per_second=2, remaining_seconds=1_500)
NUCLEI_TMPFS = {"/tmp": "rw,noexec,nosuid,nodev,size=256m,mode=1777"}  # noqa: S108
type Body = dict[str, Any]


def _nuclei(*, budget: NucleiBudget = BUDGET) -> ExecutionPlan:
    return plan_nuclei_run(run_id=RUN_ID, scan_id=SCAN_ID, origin=ORIGIN, budget=budget)


def _rejected(plan: ExecutionPlan) -> PlanRejection:
    with pytest.raises(PlanRejectedError) as caught:
        admit(plan)
    return caught.value.reason


# --- admission ----------------------------------------------------------------------------------


@pytest.mark.parametrize("rate", [1, 2, 10])
@pytest.mark.parametrize("seconds", [120, 1_500])
def test_every_nuclei_plan_is_admitted(rate: int, seconds: int) -> None:
    plan = _nuclei(budget=NucleiBudget(requests_per_second=rate, remaining_seconds=seconds))

    check_container_spec(build_container(plan, policy=POLICY), plan=plan, policy=POLICY)


def test_the_nuclei_image_is_approved_independently() -> None:
    assert ENGINE_POLICIES[Engine.NUCLEI].images == frozenset({str(NUCLEI_IMAGE)})


def test_the_approved_inputs_are_exactly_the_frozen_templates() -> None:
    policy = ENGINE_POLICIES[Engine.NUCLEI]
    templates = load_templates()
    assert policy.input_names == frozenset(f"{t.id}.yaml" for t in templates)
    # 每檔的 ContentDigest 就是 lock 的 sha256（獨立白名單）。
    for template in templates:
        rule = policy.input_rules[f"{template.id}.yaml"]
        assert isinstance(rule, ContentDigest)
        assert rule.sha256 == template.sha256


def test_the_plan_and_policy_agree_on_the_container_paths() -> None:
    # scanners 的 plan 與 runner 的 admission 各寫一份字面值：必須一致。
    proxy_path = f"{SECRET_DIR}/{PROXY_FILE}"
    assert nuclei_plan.IN_DIR == IN_DIR
    assert nuclei_plan.OUT_DIR == OUT_DIR
    assert proxy_path == nuclei_plan.PROXY_PATH


def test_a_tampered_template_is_rejected() -> None:
    plan = _nuclei()
    first, *rest = plan.inputs
    tampered = (InputFile(first.name, first.content + b"\n# tampered\n"), *rest)
    assert _rejected(replace(plan, inputs=tampered)) is PlanRejection.INPUT_NOT_ALLOWED


def test_an_unknown_template_name_is_rejected() -> None:
    plan = _nuclei()
    extra = (*plan.inputs, InputFile("surprise.yaml", b"id: surprise\n"))
    assert _rejected(replace(plan, inputs=extra)) is PlanRejection.INPUT_NOT_ALLOWED


def test_a_truncated_command_is_rejected() -> None:
    short = ("-ni", "-duc", "-pt", "http", "-jsonl", "-silent")
    assert _rejected(replace(_nuclei(), arguments=short)) is PlanRejection.COMMAND_NOT_ALLOWED


def test_an_extra_argument_is_rejected() -> None:
    plan = _nuclei()
    assert _rejected(replace(plan, arguments=(*plan.arguments, "-debug"))) is (
        PlanRejection.COMMAND_NOT_ALLOWED
    )


def test_a_changed_concurrency_is_rejected() -> None:
    plan = _nuclei()
    args = list(plan.arguments)
    args[args.index("-c") + 1] = "25"  # 凍結成 1，放寬即拒
    assert _rejected(replace(plan, arguments=tuple(args))) is PlanRejection.COMMAND_NOT_ALLOWED


def test_an_inline_proxy_instead_of_the_file_is_rejected() -> None:
    plan = _nuclei()
    args = list(plan.arguments)
    args[args.index("-p") + 1] = "http://user:token@egress-guard:8080"
    assert _rejected(replace(plan, arguments=tuple(args))) is PlanRejection.COMMAND_NOT_ALLOWED


def test_nuclei_cannot_run_another_engines_command() -> None:
    fake = fake_plan()
    swapped = replace(_nuclei(), entrypoint=fake.entrypoint, arguments=fake.arguments)
    assert _rejected(swapped) is PlanRejection.COMMAND_NOT_ALLOWED


@pytest.mark.parametrize(
    "environment",
    [
        (("HOME", "/root"),),  # 值不是 /tmp
        (("HOME", "/tmp"), ("NUCLEI_SIGNATURE_PRIVATE_KEY", "x")),  # noqa: S108 - 測試資料
        (("LD_PRELOAD", "/scan/in/x.so"), ("HOME", "/tmp")),  # noqa: S108 - 測試資料
    ],
)
def test_environment_variables_outside_home_tmp_are_rejected(
    environment: tuple[tuple[str, str], ...],
) -> None:
    # admission 只限制「可出現哪些」環境變數；plan 一定帶 HOME=/tmp，多出或變值即拒。
    assert _rejected(replace(_nuclei(), environment=environment)) is (
        PlanRejection.ENVIRONMENT_NOT_ALLOWED
    )


def test_target_auth_is_refused() -> None:
    assert _rejected(replace(_nuclei(), target_auth=True)) is PlanRejection.TARGET_AUTH_NOT_ALLOWED


@pytest.mark.parametrize(
    "limits",
    [
        ResourceLimits(2 * 1024**3 + 1, 2_000_000_000, 1024, 1_500),
        ResourceLimits(2 * 1024**3, 2_000_000_001, 1024, 1_500),
        ResourceLimits(2 * 1024**3, 2_000_000_000, 1025, 1_500),
        ResourceLimits(2 * 1024**3, 2_000_000_000, 1024, 1_501),
    ],
)
def test_limits_above_the_nuclei_cap_are_rejected(limits: ResourceLimits) -> None:
    assert _rejected(replace(_nuclei(), limits=limits)) is PlanRejection.LIMITS_OUT_OF_RANGE


def test_nuclei_collects_only_a_clean_exit() -> None:
    assert ENGINE_POLICIES[Engine.NUCLEI].collect_exit_codes == frozenset({0})


def test_nuclei_outputs_are_masked() -> None:
    assert ENGINE_POLICIES[Engine.NUCLEI].redact_outputs is True


# --- create 的 body -----------------------------------------------------------------------------


def _body(plan: ExecutionPlan) -> Body:
    return copy.deepcopy(dict(container_spec(plan, POLICY).body))


def _check(plan: ExecutionPlan, body: Body) -> None:
    spec = ContainerSpec(name=f"secscan-run-{RUN_ID}", body=body)
    check_container_spec(spec, plan=plan, policy=POLICY)


def test_the_nuclei_container_gets_only_the_declared_tmpfs() -> None:
    body = _body(_nuclei())
    assert body["HostConfig"]["Tmpfs"] == NUCLEI_TMPFS
    assert body["Healthcheck"] == {"Test": ["NONE"]}
    assert body["HostConfig"]["ReadonlyRootfs"] is True
    assert body["User"] == "10001:10001"


def test_the_check_keeps_its_own_tmpfs_table() -> None:
    nuclei = ENGINE_POLICIES[Engine.NUCLEI]
    assert dict(admission._REQUIRED_TMPFS[Engine.NUCLEI]) == dict(nuclei.scratch) == NUCLEI_TMPFS


def test_a_changed_tmpfs_is_refused() -> None:
    plan = _nuclei()
    body = _body(plan)
    body["HostConfig"]["Tmpfs"] = {"/tmp": "rw,exec,nosuid,nodev,size=8g,mode=1777"}  # noqa: S108
    with pytest.raises(PlanRejectedError):
        _check(plan, body)
