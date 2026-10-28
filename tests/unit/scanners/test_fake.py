"""fake 引擎的 ExecutionPlan（docs/DECISIONS.md §14.3）：sleep 或 false，busybox 以 digest 鎖定。"""

import json
import math
from uuid import uuid4

import pytest
from hypothesis import given
from hypothesis import strategies as st

from secscan.scanners.domain.fake import (
    FAKE_IMAGE,
    FAKE_MAX_WALL_CLOCK_SECONDS,
    MAX_HOLD_SECONDS,
    FakeOutcome,
    FakeScript,
    plan_fake_run,
)
from secscan.scanners.domain.plan import ExecutionPlan
from secscan.scans.domain.catalog import Engine

RUN_ID = uuid4()
SCAN_ID = uuid4()


def _plan(
    script: FakeScript, *, target_auth: bool = False, max_duration: int = 1500
) -> ExecutionPlan:
    return plan_fake_run(
        run_id=RUN_ID,
        scan_id=SCAN_ID,
        script=script,
        target_auth=target_auth,
        max_duration_seconds=max_duration,
    )


def test_success_sleeps_for_the_hold_rounded_up() -> None:
    plan = _plan(FakeScript(hold_seconds=2.1))

    assert (plan.entrypoint, plan.arguments) == (("/bin/sleep",), ("3",))
    assert plan.engine is Engine.FAKE
    assert plan.image == FAKE_IMAGE
    assert (plan.run_id, plan.scan_id) == (RUN_ID, SCAN_ID)


def test_failure_exits_non_zero_at_once() -> None:
    plan = _plan(FakeScript(outcome=FakeOutcome.FAIL, hold_seconds=30))

    assert (plan.entrypoint, plan.arguments) == (("/bin/false",), ())


def test_the_image_is_pinned_busybox() -> None:
    assert FAKE_IMAGE.repository == "busybox"
    assert FAKE_IMAGE.digest.startswith("sha256:")


def test_the_input_describes_the_run_without_secrets() -> None:
    plan = _plan(FakeScript(hold_seconds=1), target_auth=True)

    (run_file,) = plan.inputs
    assert run_file.name == "run.json"
    assert json.loads(run_file.content) == {
        "engine": "fake",
        "hold_seconds": 1,
        "outcome": "succeed",
        "run_id": str(RUN_ID),
        "scan_id": str(SCAN_ID),
    }
    assert plan.environment == ()
    assert plan.target_auth is True


@pytest.mark.parametrize(
    ("max_duration", "expected"),
    [
        (1, 1),
        (60, 60),
        (FAKE_MAX_WALL_CLOCK_SECONDS, FAKE_MAX_WALL_CLOCK_SECONDS),
        (10**6, FAKE_MAX_WALL_CLOCK_SECONDS),
    ],
)
def test_wall_clock_is_the_scan_budget_capped(max_duration: int, expected: int) -> None:
    assert _plan(FakeScript(), max_duration=max_duration).limits.wall_clock_seconds == expected


def test_limits_are_small() -> None:
    limits = _plan(FakeScript()).limits

    assert limits.memory_bytes == 64 * 1024 * 1024
    assert limits.nano_cpus == 500_000_000
    assert limits.pids == 64


@given(hold=st.floats(min_value=0, max_value=MAX_HOLD_SECONDS))
def test_every_hold_becomes_a_whole_number_of_seconds(hold: float) -> None:
    (seconds,) = _plan(FakeScript(hold_seconds=hold)).arguments

    assert seconds.isdigit()
    # 不會比要求的短，最多多不到 1 秒（浮點數的 hold + 1 可能等於 1，所以比較 ceil）。
    assert int(seconds) == math.ceil(hold) >= hold
