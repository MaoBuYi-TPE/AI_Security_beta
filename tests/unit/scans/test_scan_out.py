"""scan 回應中的用量、preflight 與 coverage（docs/API_CONTRACT.md §8；DECISIONS §16.4 至 §16.6）。

- budget_usage：guard 的實際計數（不採用工具自報的數字）；不明是 null。
- auth.preflight：preflight run 的結果，還沒結束是 null。
- coverage：有量測依據時才給 observed 與 authenticated；authenticated 要 preflight 通過，否則是 0
  並標 AUTHENTICATION_NOT_VERIFIED；匿名的 scan 沒有 authenticated（null）。
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from secscan.grants.domain.scope import Budget
from secscan.scans.domain.catalog import Engine, ScanProfile
from secscan.scans.domain.lifecycle import RunStatus, ScanStatus
from secscan.scans.domain.model import AuthBinding, Coverage, Scan, ScannerRun, VersionRef
from secscan.scans.domain.preflight import PreflightResult
from secscan.scans.schemas import ScanOut
from secscan.targets.domain import parse_origin

SCAN_ID = UUID(int=9)
NOW = datetime(2026, 10, 29, tzinfo=UTC)
AUTH = AuthBinding(profile_id=uuid4(), version=1, role_label="standard_user")
COVERAGE = Coverage(
    eligible_operations=10,
    ineligible_operations=1,
    observed_operations=4,
    authenticated_operations=3,
)


def _run(sequence: int, engine: Engine, **fields: Any) -> ScannerRun:
    values: dict[str, Any] = {
        "id": uuid4(),
        "scan_id": SCAN_ID,
        "engine": engine,
        "sequence": sequence,
        "status": RunStatus.SUCCEEDED,
        "error_code": None,
        "started_at": NOW,
        "finished_at": NOW,
        "created_at": NOW,
        "container": True,
        "requests_sent": 2,
        "requests_denied": 1,
        "traffic_seconds": 3,
        "coverage_recorded": True,
    }
    values.update(fields)
    return ScannerRun(**values)


def _out(runs: tuple[ScannerRun, ...], **overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "id": SCAN_ID,
        "project_id": uuid4(),
        "target_id": uuid4(),
        "target_origin": parse_origin("http://lab-target:8080"),
        "status": ScanStatus.COMPLETED,
        "profile": ScanProfile.API_ACTIVE_LAB,
        "scope_grant": VersionRef(id=uuid4(), version=1),
        "api_spec": VersionRef(id=uuid4(), version=1),
        "auth": AUTH,
        "budget": Budget(requests_per_second=2, max_requests=1_000, max_duration_seconds=1_500),
        "runs": runs,
        "coverage": COVERAGE,
        "cancel_requested_at": None,
        "created_by_key_id": uuid4(),
        "created_at": NOW,
        "finished_at": NOW,
    }
    fields.update(overrides)
    return ScanOut.of(Scan(**fields)).model_dump(mode="json")


def _authenticated(result: PreflightResult | None, **fields: Any) -> tuple[ScannerRun, ...]:
    status = RunStatus.SUCCEEDED if result is not None else RunStatus.RUNNING
    preflight = _run(
        1,
        Engine.PREFLIGHT,
        status=status,
        finished_at=NOW if result is not None else None,
        preflight_result=result,
    )
    return (preflight, _run(2, Engine.FAKE, **fields))


def test_budget_usage_is_the_guard_count() -> None:
    out = _out(_authenticated(PreflightResult.PASSED))

    assert out["budget_usage"] == {
        "requests_sent": 4,
        "requests_denied": 2,
        "traffic_duration_seconds": 6,
    }


def test_measured_coverage_with_a_passed_preflight() -> None:
    out = _out(_authenticated(PreflightResult.PASSED))

    assert out["auth"]["preflight"] == "passed"
    assert out["coverage"] == {
        "eligible_operations": 10,
        "ineligible_operations": 1,
        "observed_operations": 4,
        "authenticated_operations": 3,
        "coverage_measured": True,
        "limitations": [],
    }


def test_an_unverified_identity_covers_nothing_authenticated() -> None:
    out = _out(_authenticated(PreflightResult.INCONCLUSIVE))

    assert out["auth"]["preflight"] == "inconclusive"
    assert out["coverage"]["authenticated_operations"] == 0
    assert out["coverage"]["limitations"] == ["AUTHENTICATION_NOT_VERIFIED"]


def test_a_pending_preflight_is_null() -> None:
    out = _out(_authenticated(None, status=RunStatus.QUEUED, started_at=None, finished_at=None))

    assert out["auth"]["preflight"] is None


def test_unmeasured_coverage_has_no_counts() -> None:
    out = _out(_authenticated(PreflightResult.PASSED, coverage_recorded=False))

    assert out["coverage"]["coverage_measured"] is False
    assert (
        out["coverage"]["observed_operations"],
        out["coverage"]["authenticated_operations"],
    ) == (
        None,
        None,
    )
    assert out["coverage"]["limitations"] == ["TRAFFIC_TELEMETRY_UNAVAILABLE"]


def test_anonymous_scans_have_no_authenticated_count() -> None:
    out = _out((_run(1, Engine.FAKE),), auth=None)

    assert out["auth"] is None
    assert out["coverage"]["observed_operations"] == 4
    assert out["coverage"]["authenticated_operations"] is None
    assert out["coverage"]["limitations"] == []


def test_scans_without_a_spec_measure_no_coverage() -> None:
    out = _out((_run(1, Engine.FAKE),), auth=None, api_spec=None, coverage=None)

    assert out["coverage"]["coverage_measured"] is False
    assert out["coverage"]["limitations"] == ["NO_API_SPEC", "TRAFFIC_TELEMETRY_UNAVAILABLE"]
    assert out["budget_usage"]["requests_sent"] == 2
