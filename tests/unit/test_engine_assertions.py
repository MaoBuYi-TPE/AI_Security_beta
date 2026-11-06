"""live 狀態檢查不得把 Nuclei 模板錯誤當成功或接受任意工具失敗。"""

from typing import Any

import pytest

from tests.live.engine_assertions import assert_engine_outcome


def _run(engine: str, status: str, code: str | None, errors: Any) -> dict[str, Any]:
    return {
        "engine": engine,
        "status": status,
        "error_code": code,
        "result": {"engine_errors": errors},
    }


@pytest.mark.parametrize("engine", ["zap", "nuclei"])
def test_success_requires_no_engine_errors(engine: str) -> None:
    assert_engine_outcome(_run(engine, "succeeded", None, 0), {"results_complete": True})
    with pytest.raises(AssertionError):
        assert_engine_outcome(_run(engine, "succeeded", None, 1), {"results_complete": True})


def test_reported_nuclei_errors_preserve_the_incomplete_scan() -> None:
    assert_engine_outcome(
        _run("nuclei", "failed", "ENGINE_REPORTED_ERRORS", 1), {"results_complete": False}
    )


@pytest.mark.parametrize("engine", ["zap", "nuclei"])
@pytest.mark.parametrize("errors", [0, 2])
def test_timeouts_remain_incomplete_even_with_engine_errors(engine: str, errors: int) -> None:
    assert_engine_outcome(
        _run(engine, "timed_out", "ENGINE_TIMEOUT", errors), {"results_complete": False}
    )


@pytest.mark.parametrize(
    ("engine", "status", "code", "errors", "complete"),
    [
        ("zap", "failed", "ENGINE_REPORTED_ERRORS", 1, False),
        ("nuclei", "failed", "ENGINE_FAILED", 1, False),
        ("nuclei", "failed", "OUTPUT_INVALID", 1, False),
        ("nuclei", "failed", "ENGINE_REPORTED_ERRORS", 0, False),
        ("nuclei", "failed", "ENGINE_REPORTED_ERRORS", -1, False),
        ("nuclei", "failed", "ENGINE_REPORTED_ERRORS", True, False),
        ("nuclei", "failed", "ENGINE_REPORTED_ERRORS", "1", False),
        ("nuclei", "failed", "ENGINE_REPORTED_ERRORS", None, False),
        ("nuclei", "failed", "ENGINE_REPORTED_ERRORS", 1, True),
        ("nuclei", "cancelled", "CANCELLED", 1, False),
        ("nuclei", "interrupted", "RUNNER_STOPPED", 1, False),
        ("nuclei", "timed_out", "ENGINE_TIMEOUT", 0, True),
        ("nuclei", "succeeded", "ENGINE_REPORTED_ERRORS", 0, True),
    ],
)
def test_other_outcomes_are_not_accepted_as_valid_measurements(
    engine: str, status: str, code: str | None, errors: Any, complete: bool
) -> None:
    with pytest.raises(AssertionError):
        assert_engine_outcome(_run(engine, status, code, errors), {"results_complete": complete})


def test_a_missing_parser_result_is_not_an_accepted_failure() -> None:
    run = {**_run("nuclei", "failed", "ENGINE_REPORTED_ERRORS", 1), "result": None}
    with pytest.raises(AssertionError):
        assert_engine_outcome(run, {"results_complete": False})
