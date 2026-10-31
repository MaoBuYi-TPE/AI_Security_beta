"""觀察的輸入契約（docs/DECISIONS.md §19.3）：parser 的輸出，與引擎無關。"""

import dataclasses

import pytest
from hypothesis import given
from hypothesis import strategies as st

from secscan.scans.domain.lifecycle import ERROR_REQUIRED_RUN_STATUSES, RunErrorCode, RunStatus
from secscan.scans.domain.observation import (
    MAX_DETAILS_BYTES,
    Exclusion,
    ObservationInput,
    ParameterLocation,
    ParsedRun,
    RunOutcome,
    event_id,
    outcome_from_details,
    result_details,
)

TIMED_OUT = RunOutcome(RunStatus.TIMED_OUT, RunErrorCode.ENGINE_TIMEOUT)
SUCCEEDED = RunOutcome(RunStatus.SUCCEEDED)


def _observation(**changes: object) -> ObservationInput:
    values: dict[str, object] = {
        "source_event_id": "ab" * 32,
        "source_index": 0,
        "source_rule": "10038",
        "rule_variant": "10038-1",
        "title": "Content Security Policy (CSP) Header Not Set",
        "raw_severity": "2",
        "raw_confidence": "3",
        "cwe_id": 693,
        "wasc_id": 15,
        "method": "GET",
        "path": "/",
        "query": None,
        "parameter": None,
        "parameter_location": ParameterLocation.UNKNOWN,
        "attack": None,
        "evidence": None,
        "other_info": None,
    }
    return ObservationInput(**{**values, **changes})  # type: ignore[arg-type]


@pytest.mark.parametrize("status", [RunStatus.FAILED, RunStatus.TIMED_OUT])
def test_an_unsuccessful_outcome_needs_an_error_code(status: RunStatus) -> None:
    with pytest.raises(ValueError, match="錯誤碼"):
        RunOutcome(status)


def test_a_successful_outcome_cannot_have_an_error_code() -> None:
    with pytest.raises(ValueError, match="錯誤碼"):
        RunOutcome(RunStatus.SUCCEEDED, RunErrorCode.ENGINE_FAILED)


@pytest.mark.parametrize(
    "status", sorted(set(RunStatus) - {RunStatus.SUCCEEDED} - ERROR_REQUIRED_RUN_STATUSES)
)
def test_an_outcome_is_a_status_that_ends_parsing(status: RunStatus) -> None:
    with pytest.raises(ValueError, match="判定"):
        RunOutcome(status)


def test_an_interrupted_outcome_is_not_a_parser_result() -> None:
    with pytest.raises(ValueError, match="判定"):
        RunOutcome(RunStatus.INTERRUPTED, RunErrorCode.LEASE_EXPIRED)


def test_the_contract_is_frozen() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        _observation().title = "changed"  # type: ignore[misc]


def test_event_ids_separate_the_fields() -> None:
    """欄位之間不能互相滲透：("ab", "c") 與 ("a", "bc") 是不同的事件。"""
    assert event_id("ab", "c") != event_id("a", "bc")
    assert event_id("ab", "c") == event_id("ab", "c")
    assert len(event_id("x")) == 64


def test_result_details_keep_the_counts_and_the_outcome() -> None:
    parsed = ParsedRun(
        parser_version="zap-traditional-json/1",
        outcome=TIMED_OUT,
        engine_version="2.17.0",
        observations=(_observation(),),
        excluded={Exclusion.NOT_ANSWERED: 2},
        duplicates=1,
        truncated_fields=3,
        engine_errors=0,
        engine_warnings=1,
        time_limit_reached=True,
        traffic_verified=True,
        components={"reports": "0.46.0"},
    )

    details = result_details(parsed)

    assert details == {
        "status": "timed_out",
        "error_code": "ENGINE_TIMEOUT",
        "excluded": {
            "guard_denied": 0,
            "guard_response": 0,
            "not_answered": 2,
            "out_of_scope": 0,
        },
        "duplicates": 1,
        "truncated_fields": 3,
        "engine_errors": 0,
        "engine_warnings": 1,
        "time_limit_reached": True,
        "traffic_verified": True,
        "problem": None,
        "components": {"reports": "0.46.0"},
    }


@pytest.mark.parametrize("outcome", [SUCCEEDED, TIMED_OUT])
def test_the_outcome_survives_the_details(outcome: RunOutcome) -> None:
    """解析寫入之後、run 結束之前中斷：重試以存下的判定結束，不再解析（§19.6）。"""
    details = result_details(ParsedRun(parser_version="p/1", outcome=outcome))

    assert outcome_from_details(details) == outcome


@given(st.integers(0, 10**9), st.integers(0, 10**9))
def test_the_details_stay_small(duplicates: int, truncated: int) -> None:
    parsed = ParsedRun(
        parser_version="zap-traditional-json/1",
        outcome=SUCCEEDED,
        duplicates=duplicates,
        truncated_fields=truncated,
        excluded=dict.fromkeys(Exclusion, 10**9),
        components=dict.fromkeys((f"addon-{index}" for index in range(9)), "1.44.0"),
    )

    assert len(str(result_details(parsed)).encode()) < MAX_DETAILS_BYTES
