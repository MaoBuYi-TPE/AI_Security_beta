"""FakeRunner 的腳本（docs/DECISIONS.md §13.7）：結果與停留的時間有界限。"""

import pytest

from secscan.scanners.domain.fake import MAX_HOLD_SECONDS, FakeOutcome, FakeScript


def test_the_default_script_succeeds_at_once() -> None:
    assert FakeScript() == FakeScript(outcome=FakeOutcome.SUCCEED, hold_seconds=0)


@pytest.mark.parametrize("seconds", [0, 0.5, MAX_HOLD_SECONDS])
def test_hold_seconds_within_bounds(seconds: float) -> None:
    assert FakeScript(hold_seconds=seconds).hold_seconds == seconds


@pytest.mark.parametrize("seconds", [-1, MAX_HOLD_SECONDS + 1, float("nan"), float("inf")])
def test_hold_seconds_outside_bounds_are_rejected(seconds: float) -> None:
    with pytest.raises(ValueError, match="hold_seconds"):
        FakeScript(hold_seconds=seconds)


def test_outcomes() -> None:
    assert {outcome.value for outcome in FakeOutcome} == {"succeed", "fail"}
