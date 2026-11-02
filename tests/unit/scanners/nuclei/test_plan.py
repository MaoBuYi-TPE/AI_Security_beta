"""Nuclei 的 ExecutionPlan（T18；DECISIONS §14.3、§23）；純函式。

凍結的旗標、速率/並行與 -dut；proxy 以檔案路徑注入（憑證不上命令列）；42 個模板以 InputFile 掛載、
逐檔 sha256 與 lock 一致；plan_hash 不含 run/scan id。
"""

import hashlib
from uuid import UUID

import pytest

from secscan.scanners.domain.nuclei.plan import (
    MIN_PLAN_SECONDS,
    PROXY_PATH,
    REQUEST_TIMEOUT_SECONDS,
    RESULTS_FILE,
    NucleiBudget,
    NucleiPlanError,
    PlanWindowTooSmallError,
    plan_nuclei_run,
)
from secscan.scanners.domain.nuclei.policy import (
    FROZEN_FLAGS,
    INCLUDE_TEMPLATE_IDS,
    NUCLEI_IMAGE,
    load_templates,
)
from secscan.scanners.domain.plan import ExecutionPlan, plan_hash
from secscan.scans.domain.catalog import Engine
from secscan.targets.domain import parse_origin

RUN_ID = UUID("6f1c2d3e-4b5a-4c6d-8e7f-001122334455")
SCAN_ID = UUID("0a1b2c3d-4e5f-4a6b-9c7d-8e9fa0b1c2d3")
ORIGIN = parse_origin("http://juice-shop:3000")
BUDGET = NucleiBudget(requests_per_second=2, remaining_seconds=1_500)


def _plan(*, budget: NucleiBudget = BUDGET) -> ExecutionPlan:
    return plan_nuclei_run(run_id=RUN_ID, scan_id=SCAN_ID, origin=ORIGIN, budget=budget)


def _after(args: tuple[str, ...], flag: str) -> str:
    return args[args.index(flag) + 1]


def test_plan_targets_the_locked_image_and_runs_anonymously() -> None:
    plan = plan_nuclei_run(run_id=RUN_ID, scan_id=SCAN_ID, origin=ORIGIN, budget=BUDGET)
    assert plan.engine is Engine.NUCLEI
    assert plan.image == NUCLEI_IMAGE
    assert plan.entrypoint == ("nuclei",)
    assert plan.target_auth is False
    assert plan.environment == (("HOME", "/tmp"),)  # noqa: S108 - 容器內 tmpfs 的路徑


def test_arguments_freeze_the_flags_rate_and_proxy_by_file() -> None:
    args = plan_nuclei_run(
        run_id=RUN_ID, scan_id=SCAN_ID, origin=ORIGIN, budget=NucleiBudget(2, 1_500)
    ).arguments
    assert args[: len(FROZEN_FLAGS)] == FROZEN_FLAGS
    assert "-dut" in args
    # proxy 以檔案路徑注入：憑證不會出現在命令列。
    assert _after(args, "-p") == PROXY_PATH
    assert _after(args, "-t") == "/scan/in"
    assert _after(args, "-o") == RESULTS_FILE
    assert _after(args, "-rl") == "2"
    assert _after(args, "-c") == "1"
    assert _after(args, "-bs") == "1"
    assert _after(args, "-retries") == "0"
    assert _after(args, "-timeout") == str(REQUEST_TIMEOUT_SECONDS)
    assert _after(args, "-u") == "http://juice-shop:3000"


def test_inputs_are_the_frozen_templates_verified_against_the_lock() -> None:
    plan = _plan()
    templates = load_templates()
    assert len(plan.inputs) == len(INCLUDE_TEMPLATE_IDS) == 42
    assert {item.name for item in plan.inputs} == {f"{t.id}.yaml" for t in templates}
    by_id = {t.id: t.sha256 for t in templates}
    for item in plan.inputs:
        template_id = item.name.removesuffix(".yaml")
        assert hashlib.sha256(item.content).hexdigest() == by_id[template_id]


def test_plan_hash_excludes_run_and_scan_ids() -> None:
    first = plan_nuclei_run(run_id=RUN_ID, scan_id=SCAN_ID, origin=ORIGIN, budget=BUDGET)
    second = plan_nuclei_run(run_id=SCAN_ID, scan_id=RUN_ID, origin=ORIGIN, budget=BUDGET)
    assert plan_hash(first) == plan_hash(second)


def test_a_zero_rate_is_rejected() -> None:
    with pytest.raises(NucleiPlanError):
        _plan(budget=NucleiBudget(requests_per_second=0, remaining_seconds=1_500))


def test_too_small_a_window_is_rejected() -> None:
    with pytest.raises(PlanWindowTooSmallError):
        _plan(budget=NucleiBudget(requests_per_second=2, remaining_seconds=MIN_PLAN_SECONDS - 1))
