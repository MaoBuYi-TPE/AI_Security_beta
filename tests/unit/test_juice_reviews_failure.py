"""Failure diagnosis requires the actual target crash plus complete original evidence."""

import json
from collections.abc import Callable

import pytest

from tests.juice_reviews_failure import (
    _REQUIRED,
    CAPTURE_REASON,
    EXPECTED_JUICE_BUDGET,
    EXPECTED_JUICE_PATHS,
    assert_original_reviews_failure,
)


def _encode(value: object) -> bytes:
    return json.dumps(value).encode()


def _complete_failure() -> dict[str, bytes]:
    artifacts = dict.fromkeys(_REQUIRED, b"")
    artifacts.update(
        {
            "capture-validation.json": _encode({"valid": False, "reason": CAPTURE_REASON}),
            "collection-errors.json": b"[]",
            "collection-index.json": _encode(dict.fromkeys(_REQUIRED, True)),
            "target-inspect.stdout.log": _encode(
                [
                    {
                        "State": {
                            "Status": "exited",
                            "Running": False,
                            "ExitCode": 1,
                            "OOMKilled": False,
                        }
                    }
                ]
            ),
            "target-logs.stderr.log": (
                b"ReferenceError: get is not defined\n"
                b" at /juice-shop/build/routes/productReviews.js:1:1"
            ),
            "target-events.stdout.log": _encode(
                {"Action": "die", "Actor": {"Attributes": {"exitCode": "1"}}}
            ),
            "scan-api.json": _encode(
                {
                    "id": "scan",
                    "profile": "api_active_lab",
                    "auth": None,
                    "api_spec": {"id": "spec"},
                    "budget": dict(EXPECTED_JUICE_BUDGET),
                }
            ),
            "frozen-scan.json": _encode(
                {
                    "scan_id": "scan",
                    "api_spec_id": "spec",
                    "auth_profile_id": None,
                    "operations": [
                        {"method": "GET", "path": path} for path in EXPECTED_JUICE_PATHS
                    ],
                }
            ),
            "runs.json": _encode(
                [
                    {
                        "id": "run",
                        "engine": "zap",
                        "guard_policy_version": "strict-1",
                        "requests_sent": 1,
                    }
                ]
            ),
            "telemetry.jsonl": _encode(
                {"e": "request", "method": "GET", "path": "/rest/products/1/reviews"}
            ),
            "summary.json": _encode(
                {"policy_version": "strict-1", "scan_id": "scan", "run_id": "run", "forwarded": 1}
            ),
            "report.json": b'{"site": []}',
        }
    )
    for command in ("inspect", "logs", "events"):
        artifacts[f"target-{command}.result.json"] = _encode({"returncode": 0, "error": None})
    return artifacts


def _change_state(artifacts: dict[str, bytes], name: str, value: object) -> None:
    [target] = json.loads(artifacts["target-inspect.stdout.log"])
    target["State"][name] = value
    artifacts["target-inspect.stdout.log"] = _encode([target])


def _missing_report_index(artifacts: dict[str, bytes]) -> None:
    index = json.loads(artifacts["collection-index.json"])
    index["report.json"] = False
    artifacts["collection-index.json"] = _encode(index)


def test_complete_diagnosis_is_accepted_only_as_failed_measurement() -> None:
    assert_original_reviews_failure(_complete_failure(), CAPTURE_REASON)


@pytest.mark.parametrize(
    "reason",
    ["capture process exited unsuccessfully; see encrypted diagnostics", "missing TCP SYN"],
)
def test_unrelated_evidence_error_is_rejected(reason: str) -> None:
    with pytest.raises(AssertionError, match="unexpected measurement failure"):
        assert_original_reviews_failure(_complete_failure(), reason)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda a: _change_state(a, "OOMKilled", True), "unexpected OOM"),
        (lambda a: _change_state(a, "ExitCode", 137), "unexpected target exit"),
        (
            lambda a: a.update({"target-logs.stderr.log": b"different failure"}),
            "missing actual Juice reviews crash",
        ),
        (lambda a: a.update({"target-events.stdout.log": b""}), "missing target crash lifecycle"),
        (_missing_report_index, "missing original measurement input"),
        (lambda a: a.pop("telemetry.jsonl"), "missing diagnosis artifacts"),
        (lambda a: a.update({"telemetry.jsonl": b""}), "no original scanner traffic"),
        (
            lambda a: a.update({"collection-errors.json": b'["unavailable"]'}),
            "incomplete collection",
        ),
        (
            lambda a: a.update(
                {"capture-validation.json": _encode({"valid": True, "reason": CAPTURE_REASON})}
            ),
            "failed capture must remain invalid",
        ),
        (lambda a: a.update({"analysis.json": b"{}"}), "must not become A/B analysis"),
    ],
)
def test_crash_diagnosis_rejects_wrong_cause_or_incomplete_evidence(
    mutation: Callable[[dict[str, bytes]], object],
    message: str,
) -> None:
    artifacts = _complete_failure()
    mutation(artifacts)
    with pytest.raises(AssertionError, match=message):
        assert_original_reviews_failure(artifacts, CAPTURE_REASON)
