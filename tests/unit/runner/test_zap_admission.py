"""zap 的政策、admission 與 create 的 body（docs/DECISIONS.md §18.1、§18.2、§18.8）。

- zap 的 plan（掃描與 probe）都通過驗證；script 以 sha256 核准，改了就要重新審查。
- 認證的環境變數和 target_auth 一致：值永遠不在 plan，anonymous 沒有 header 的變數。
- tmpfs 只接受引擎政策宣告的固定值，送出前以自己的字面值核對；所有引擎都關閉映像的 healthcheck。
"""

import copy
import hashlib
import json
from collections.abc import Callable
from dataclasses import replace
from ipaddress import IPv4Address
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from secscan.grants.domain.scope import HttpMethod, Scope
from secscan.runner.domain import admission
from secscan.runner.domain.admission import (
    ContainerSpec,
    PlanRejectedError,
    PlanRejection,
    admit,
    build_container,
    check_container_spec,
    container_spec,
)
from secscan.runner.domain.policy import (
    ENGINE_POLICIES,
    ZAP_PROBE_PLAN_SHA256,
    ZAP_PROBE_SCRIPT_SHA256,
    ZAP_SCAN_SCRIPT_SHA256,
)
from secscan.scanners.domain.plan import ExecutionPlan, InputFile, ResourceLimits
from secscan.scanners.domain.zap.plan import (
    ANONYMOUS,
    ToolSpec,
    ZapAuth,
    ZapBudget,
    plan_zap_run,
)
from secscan.scanners.domain.zap.policy import ZAP_IMAGE
from secscan.scanners.domain.zap.probe import plan_zap_probe
from secscan.scanners.domain.zap.script import PROBE_SCRIPT, SCAN_SCRIPT
from secscan.scans.domain.catalog import Engine, ScanProfile
from secscan.specs.domain.openapi import MAX_DOCUMENT_BYTES
from secscan.targets.domain import parse_origin
from tests.unit.runner.plans import POLICY, RUN_ID, SCAN_ID, fake_plan

ORIGIN = parse_origin("http://lab-web:3000")
SCOPE = Scope(
    origins=(ORIGIN,),
    ips=(IPv4Address("10.89.7.20"),),
    paths=(),
    allow_all_paths=True,
    excluded_paths=("/admin",),
    methods=(HttpMethod.GET, HttpMethod.POST),
)
BUDGET = ZapBudget(2, 5_000, 1_500, 86_400)
SPEC = ToolSpec(document=b"{}", base_path="/api")
# 容器內的 tmpfs（不是宿主的暫存目錄）。
SCRATCH = "/tmp"  # noqa: S108
ZAP_TMPFS = {SCRATCH: "rw,noexec,nosuid,nodev,size=768m,mode=1777"}
type Body = dict[str, Any]


def _zap(
    profile: ScanProfile = ScanProfile.WEB_ACTIVE_LAB,
    *,
    auth: ZapAuth = ANONYMOUS,
    budget: ZapBudget = BUDGET,
) -> ExecutionPlan:
    return plan_zap_run(
        run_id=RUN_ID,
        scan_id=SCAN_ID,
        profile=profile,
        origin=ORIGIN,
        scope=SCOPE,
        auth=auth,
        budget=budget,
        spec=SPEC if profile is ScanProfile.API_ACTIVE_LAB else None,
    )


def _rejected(plan: ExecutionPlan) -> PlanRejection:
    with pytest.raises(PlanRejectedError) as caught:
        admit(plan)
    return caught.value.reason


# --- admission ----------------------------------------------------------------------------------


@given(
    profile=st.sampled_from(ScanProfile),
    header=st.sampled_from([None, "Authorization", "Cookie", "X-Api-Key"]),
    seconds=st.integers(120, 1_500),
    requests=st.integers(240, 5_000),
)
def test_every_zap_plan_is_admitted(
    profile: ScanProfile, header: str | None, seconds: int, requests: int
) -> None:
    plan = _zap(
        profile, auth=ZapAuth(header=header), budget=ZapBudget(2, requests, seconds, 86_400)
    )

    check_container_spec(build_container(plan, policy=POLICY), plan=plan, policy=POLICY)


def test_the_probe_plan_is_admitted() -> None:
    plan = plan_zap_probe(RUN_ID)

    check_container_spec(build_container(plan, policy=POLICY), plan=plan, policy=POLICY)


def test_the_approved_digests_are_the_zap_scripts() -> None:
    assert hashlib.sha256(SCAN_SCRIPT.encode()).hexdigest() == ZAP_SCAN_SCRIPT_SHA256
    assert hashlib.sha256(PROBE_SCRIPT.encode()).hexdigest() == ZAP_PROBE_SCRIPT_SHA256


def test_the_zap_image_is_approved_independently() -> None:
    assert ENGINE_POLICIES[Engine.ZAP].images == frozenset({str(ZAP_IMAGE)})


@pytest.mark.parametrize(
    "arguments",
    [
        (SCAN_SCRIPT + " ",),
        (SCAN_SCRIPT.replace("-silent ", ""),),
        (SCAN_SCRIPT.replace("-nostdout ", ""),),
        (SCAN_SCRIPT, "extra"),
        ("exec /zap/zap.sh -cmd -autorun /scan/in/plan.yaml",),
    ],
)
def test_any_other_script_is_rejected(arguments: tuple[str, ...]) -> None:
    assert _rejected(replace(_zap(), arguments=arguments)) is PlanRejection.COMMAND_NOT_ALLOWED


def test_zap_cannot_run_the_fake_commands_or_vice_versa() -> None:
    fake = fake_plan()
    zap = _zap()

    swapped = replace(zap, entrypoint=fake.entrypoint, arguments=fake.arguments)
    assert _rejected(swapped) is PlanRejection.COMMAND_NOT_ALLOWED
    as_fake = replace(fake, entrypoint=zap.entrypoint, arguments=zap.arguments)
    assert _rejected(as_fake) is PlanRejection.COMMAND_NOT_ALLOWED


@pytest.mark.parametrize(
    "environment",
    [
        # 值永遠不在 plan。
        (("SECSCAN_TARGET_AUTH", "none"), ("ZAP_AUTH_HEADER_VALUE", "Bearer x")),
        # anonymous 沒有 header 的變數。
        (("SECSCAN_TARGET_AUTH", "none"), ("ZAP_AUTH_HEADER", "Authorization")),
        (("SECSCAN_TARGET_AUTH", "none"), ("ZAP_AUTH_HEADER_SITE", "lab-web")),
        # 模式和 target_auth 不一致。
        (
            ("SECSCAN_TARGET_AUTH", "header"),
            ("ZAP_AUTH_HEADER", "Authorization"),
            ("ZAP_AUTH_HEADER_SITE", "lab-web"),
        ),
        # 沒有模式。
        (),
        (("SECSCAN_TARGET_AUTH", "None"),),
        (("JAVA_TOOL_OPTIONS", "-javaagent:/scan/in/x.jar"), ("SECSCAN_TARGET_AUTH", "none")),
    ],
)
def test_an_anonymous_plan_carries_only_the_mode(environment: tuple[tuple[str, str], ...]) -> None:
    plan = replace(_zap(), environment=environment)

    assert _rejected(plan) is PlanRejection.ENVIRONMENT_NOT_ALLOWED


@pytest.mark.parametrize(
    "environment",
    [
        (("SECSCAN_TARGET_AUTH", "none"),),
        (("SECSCAN_TARGET_AUTH", "header"), ("ZAP_AUTH_HEADER", "Authorization")),
        (("SECSCAN_TARGET_AUTH", "header"), ("ZAP_AUTH_HEADER_SITE", "lab-web")),
        (
            ("SECSCAN_TARGET_AUTH", "header"),
            ("ZAP_AUTH_HEADER", "Bad Header"),
            ("ZAP_AUTH_HEADER_SITE", "lab-web"),
        ),
        (
            ("SECSCAN_TARGET_AUTH", "header"),
            ("ZAP_AUTH_HEADER", "Authorization"),
            ("ZAP_AUTH_HEADER_SITE", "lab-web\nx"),
        ),
        (
            ("SECSCAN_TARGET_AUTH", "header"),
            ("ZAP_AUTH_HEADER", "Authorization"),
            ("ZAP_AUTH_HEADER_SITE", "lab-web"),
            ("ZAP_AUTH_HEADER_VALUE", "Bearer x"),
        ),
    ],
)
def test_an_authenticated_plan_names_the_header_and_the_site(
    environment: tuple[tuple[str, str], ...],
) -> None:
    plan = replace(_zap(auth=ZapAuth(header="Authorization")), environment=environment)

    assert _rejected(plan) is PlanRejection.ENVIRONMENT_NOT_ALLOWED


def test_the_probe_runs_without_any_environment() -> None:
    probe = plan_zap_probe(RUN_ID)

    admit(probe)
    with_mode = replace(probe, environment=(("JAVA_TOOL_OPTIONS", "-Dx=y"),))
    assert _rejected(with_mode) is PlanRejection.ENVIRONMENT_NOT_ALLOWED


@pytest.mark.parametrize(
    "inputs",
    [
        (InputFile("plan.yaml", b"{}"), InputFile("extra.sh", b"x")),
        (InputFile("plan.yaml", b"x" * (MAX_DOCUMENT_BYTES + 1)),),
        (InputFile("run.json", b"{}"),),
    ],
)
def test_zap_inputs_outside_the_allowlist_are_rejected(inputs: tuple[InputFile, ...]) -> None:
    assert _rejected(replace(_zap(), inputs=inputs)) is PlanRejection.INPUT_NOT_ALLOWED


def test_the_largest_normalized_spec_fits() -> None:
    spec = InputFile("openapi.json", b"x" * MAX_DOCUMENT_BYTES)
    plan = replace(_zap(ScanProfile.API_ACTIVE_LAB), inputs=(_zap().inputs[0], spec))

    admit(plan)


# --- 輸入檔的內容（審查 M1）：AF plan 是 ZAP 的程式，admission 自己檢查，不只靠 builder ----------


def _document(plan: ExecutionPlan) -> dict[str, Any]:
    [item] = [item for item in plan.inputs if item.name == "plan.yaml"]
    document = json.loads(item.content)
    assert isinstance(document, dict)
    return document


def _with_plan_file(content: bytes) -> ExecutionPlan:
    return replace(_zap(), inputs=(InputFile("plan.yaml", content),))


def _job(document: dict[str, Any], kind: str) -> dict[str, Any]:
    job = next(job for job in document["jobs"] if job["type"] == kind)
    assert isinstance(job, dict)
    return job


def _variable_in_parameter(document: dict[str, Any]) -> None:
    document["jobs"][0]["parameters"]["user"] = "${ZAP_AUTH_HEADER_VALUE}"


def _variable_in_key(document: dict[str, Any]) -> None:
    document["env"]["${HOME}"] = 1


def _script_job(document: dict[str, Any]) -> None:
    document["jobs"].append({"type": "script", "parameters": {"action": "run"}})


def _plus_template(document: dict[str, Any]) -> None:
    _job(document, "report")["parameters"]["template"] = "traditional-json-plus"


def _report_elsewhere(document: dict[str, Any]) -> None:
    _job(document, "report")["parameters"]["reportDir"] = "/tmp"  # noqa: S108


def _two_reports(document: dict[str, Any]) -> None:
    document["jobs"].append(copy.deepcopy(_job(document, "report")))


def _no_report(document: dict[str, Any]) -> None:
    document["jobs"] = [job for job in document["jobs"] if job["type"] != "report"]


def _every_rule(document: dict[str, Any]) -> None:
    _job(document, "activeScan")["policyDefinition"]["defaultThreshold"] = "medium"


def _no_policy(document: dict[str, Any]) -> None:
    del _job(document, "activeScan")["policyDefinition"]


def _jobs_not_a_list(document: dict[str, Any]) -> None:
    document["jobs"] = {"report": _job(document, "report")}


@pytest.mark.parametrize(
    "change",
    [
        _variable_in_parameter,
        _variable_in_key,
        _script_job,
        _plus_template,
        _report_elsewhere,
        _two_reports,
        _no_report,
        _every_rule,
        _no_policy,
        _jobs_not_a_list,
    ],
)
def test_an_automation_plan_outside_the_rules_is_rejected(
    change: Callable[[dict[str, Any]], None],
) -> None:
    document = _document(_zap())
    admit(_with_plan_file(json.dumps(document).encode()))
    change(document)

    assert _rejected(_with_plan_file(json.dumps(document).encode())) is (
        PlanRejection.INPUT_NOT_ALLOWED
    )


@pytest.mark.parametrize(
    "content",
    [
        # JSON 的跳脫：檔案中沒有 ${，解析之後才有。
        json.dumps(_document(_zap())).replace('"failOnError"', '"\\u0024{X}"').encode(),
        b"not json",
        b"[]",
        b"\xff",
        b"1" * 5_000,
        b"[" * 100_000,
    ],
)
def test_an_unreadable_or_disguised_plan_is_rejected(content: bytes) -> None:
    assert _rejected(_with_plan_file(content)) is PlanRejection.INPUT_NOT_ALLOWED


def test_the_spec_is_not_an_automation_plan() -> None:
    """規格不經過 AF 的代換：說明文字中的 ${ 照樣交給 ZAP。"""
    plan = _zap(ScanProfile.API_ACTIVE_LAB)
    spec = InputFile("openapi.json", b'{"info": {"description": "${HOME}"}}')

    admit(replace(plan, inputs=(plan.inputs[0], spec)))


def test_the_probe_plan_is_approved_by_its_digest() -> None:
    first, second = plan_zap_probe(RUN_ID), plan_zap_probe(SCAN_ID)
    assert first.inputs == second.inputs
    [content] = [item.content for item in first.inputs]
    assert hashlib.sha256(content).hexdigest() == ZAP_PROBE_PLAN_SHA256

    changed = replace(first, inputs=(InputFile("probe.yaml", content.replace(b"low", b"high")),))
    assert _rejected(changed) is PlanRejection.INPUT_NOT_ALLOWED


@pytest.mark.parametrize(
    "change",
    [
        {"environment": (("SECSCAN_TARGET_AUTH", "none"),)},
        {
            "environment": (
                ("SECSCAN_TARGET_AUTH", "header"),
                ("ZAP_AUTH_HEADER", "Authorization"),
                ("ZAP_AUTH_HEADER_SITE", "lab-web"),
            ),
            "target_auth": True,
        },
        {"target_auth": True},
    ],
)
def test_the_probe_command_takes_no_auth(change: dict[str, Any]) -> None:
    """審查 I2：probe 的樣板也有認證的規則（沒有環境變數、不帶認證），兩個樣板都 fail closed。"""
    assert _rejected(replace(plan_zap_probe(RUN_ID), **change)) is (
        PlanRejection.ENVIRONMENT_NOT_ALLOWED
    )


@pytest.mark.parametrize(
    "limits",
    [
        ResourceLimits(3 * 1024**3 + 1, 2_000_000_000, 1024, 1_500),
        ResourceLimits(3 * 1024**3, 2_000_000_001, 1024, 1_500),
        ResourceLimits(3 * 1024**3, 2_000_000_000, 1025, 1_500),
        ResourceLimits(3 * 1024**3, 2_000_000_000, 1024, 1_501),
    ],
)
def test_limits_above_the_zap_cap_are_rejected(limits: ResourceLimits) -> None:
    assert _rejected(replace(_zap(), limits=limits)) is PlanRejection.LIMITS_OUT_OF_RANGE


# --- create 的 body -----------------------------------------------------------------------------


def _body(plan: ExecutionPlan) -> Body:
    return copy.deepcopy(dict(container_spec(plan, POLICY).body))


def _check(plan: ExecutionPlan, body: Body) -> None:
    spec = ContainerSpec(name=f"secscan-run-{RUN_ID}", body=body)
    check_container_spec(spec, plan=plan, policy=POLICY)


def test_the_zap_container_gets_only_the_declared_tmpfs() -> None:
    body = _body(_zap())

    assert body["HostConfig"]["Tmpfs"] == ZAP_TMPFS
    assert body["Healthcheck"] == {"Test": ["NONE"]}
    assert body["HostConfig"]["ReadonlyRootfs"] is True
    assert body["User"] == "10001:10001"


def test_other_engines_get_no_tmpfs_but_no_healthcheck_either() -> None:
    body = _body(fake_plan())

    assert "Tmpfs" not in body["HostConfig"]
    assert body["Healthcheck"] == {"Test": ["NONE"]}


@pytest.mark.parametrize(
    "tmpfs",
    [
        {SCRATCH: "rw,nosuid,nodev,size=768m,mode=1777"},
        {SCRATCH: "rw,exec,nosuid,nodev,size=768m,mode=1777"},
        {SCRATCH: "rw,noexec,nosuid,nodev,size=8g,mode=1777"},
        {SCRATCH: "rw,noexec,nodev,size=768m,mode=1777"},
        {"/home/zap": "rw,noexec,nosuid,nodev,size=768m,mode=1777"},
        {**ZAP_TMPFS, "/run": "rw"},
        {},
        [SCRATCH],
    ],
)
def test_a_changed_tmpfs_is_refused(tmpfs: object) -> None:
    plan = _zap()
    body = _body(plan)
    body["HostConfig"]["Tmpfs"] = tmpfs

    with pytest.raises(PlanRejectedError):
        _check(plan, body)


def test_a_missing_tmpfs_is_refused() -> None:
    plan = _zap()
    body = _body(plan)
    del body["HostConfig"]["Tmpfs"]

    with pytest.raises(PlanRejectedError):
        _check(plan, body)


@pytest.mark.parametrize(
    "healthcheck",
    [None, {"Test": ["CMD-SHELL", "curl http://localhost:8080/"]}, {"Test": []}, "NONE"],
)
def test_the_healthcheck_must_be_off(healthcheck: object) -> None:
    for plan in (_zap(), fake_plan()):
        body = _body(plan)
        if healthcheck is None:
            del body["Healthcheck"]
        else:
            body["Healthcheck"] = healthcheck
        with pytest.raises(PlanRejectedError):
            _check(plan, body)


def test_a_tmpfs_on_an_engine_without_one_is_refused() -> None:
    plan = fake_plan()
    body = _body(plan)
    body["HostConfig"]["Tmpfs"] = ZAP_TMPFS

    with pytest.raises(PlanRejectedError):
        _check(plan, body)


def test_the_check_keeps_its_own_tmpfs_table(monkeypatch: pytest.MonkeyPatch) -> None:
    """組 body 用的是引擎政策的值；檢查以自己的字面值核對，任一邊被改錯都會擋下。"""
    zap = ENGINE_POLICIES[Engine.ZAP]
    widened = replace(zap, scratch={SCRATCH: "rw,exec,size=8g"})
    engines = {**ENGINE_POLICIES, Engine.ZAP: widened}

    with pytest.raises(PlanRejectedError) as caught:
        build_container(_zap(), policy=POLICY, engines=engines)

    assert caught.value.reason is PlanRejection.UNSAFE_CONTAINER
    assert dict(admission._REQUIRED_TMPFS[Engine.ZAP]) == dict(zap.scratch) == ZAP_TMPFS


def test_zap_collects_the_automation_framework_exit_codes() -> None:
    assert ENGINE_POLICIES[Engine.ZAP].collect_exit_codes == frozenset({0, 1, 2})
    assert ENGINE_POLICIES[Engine.FAKE].collect_exit_codes == frozenset({0})
    assert ENGINE_POLICIES[Engine.PREFLIGHT].collect_exit_codes == frozenset({0})
