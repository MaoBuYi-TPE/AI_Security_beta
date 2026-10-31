"""scan 回應中的用量、preflight 與 coverage（docs/API_CONTRACT.md §8；DECISIONS §16.4 至 §16.6）。

- budget_usage：guard 的實際計數（不採用工具自報的數字）；不明是 null。
- auth.preflight：preflight run 的結果，還沒結束是 null。
- coverage：有量測依據時才給 observed 與 authenticated；authenticated 要 preflight 通過，否則是 0
  並標 AUTHENTICATION_NOT_VERIFIED；匿名的 scan 沒有 authenticated（null）。憑證在掃描中途失效
  另標 AUTHENTICATION_LOST（authenticated 是 null），guard 的紀錄看不出時標
  AUTHENTICATION_HEALTH_UNKNOWN（§20.4）。
- engines[]：實際執行的 plan 與 profile 定義的 hash；解析過的 run 另有 guard 的流量明細
  （§20.2、§20.3）。
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from secscan.grants.domain.scope import Budget
from secscan.scans.domain.catalog import Engine, ScanProfile
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus, ScanStatus
from secscan.scans.domain.model import AuthBinding, Coverage, Scan, ScannerRun, VersionRef
from secscan.scans.domain.observation import ParsedRun, RunOutcome, RunResult, result_details
from secscan.scans.domain.preflight import PreflightResult
from secscan.scans.domain.traffic import AuthHealth, GuardTraffic
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


def _zap_result(traffic: GuardTraffic | None) -> RunResult:
    parsed = ParsedRun(
        parser_version="p/1", outcome=RunOutcome(RunStatus.SUCCEEDED), traffic=traffic
    )
    return RunResult(
        parser_version="p/1",
        engine_version="2.17.0",
        exit_code=0,
        observation_count=0,
        details=result_details(parsed),
    )


def _lost(*, lost: bool) -> GuardTraffic:
    regressed = 2 if lost else 0
    return GuardTraffic(
        forwarded=9, answered=9, auth=AuthHealth(accepted=5, rejected=4, regressed=regressed)
    )


def test_a_credential_lost_during_the_scan_limits_the_coverage() -> None:
    """token 在掃描中途失效（§20.4）：不重新登入，揭露為 coverage 的限制。"""
    preflight, _ = _authenticated(PreflightResult.PASSED)
    zap = _run(2, Engine.ZAP, result=_zap_result(_lost(lost=True)))

    out = _out((preflight, zap))

    assert out["coverage"]["limitations"] == ["AUTHENTICATION_LOST"]
    # 過期的 token 打到公開端點仍是 200，會被算成已認證：失效時不給這個數字（T16 的審查）。
    assert out["coverage"]["authenticated_operations"] is None
    assert out["coverage"]["observed_operations"] == 4


def test_a_credential_that_held_has_no_limitation() -> None:
    preflight, _ = _authenticated(PreflightResult.PASSED)
    zap = _run(2, Engine.ZAP, result=_zap_result(_lost(lost=False)))

    assert _out((preflight, zap))["coverage"]["limitations"] == []


def test_the_loss_is_reported_even_without_a_spec() -> None:
    """web profile 沒有規格、沒有 coverage 的數字，失效仍要揭露。"""
    preflight, _ = _authenticated(PreflightResult.PASSED)
    zap = _run(2, Engine.ZAP, result=_zap_result(_lost(lost=True)))

    out = _out((preflight, zap), api_spec=None, coverage=None)

    assert out["coverage"]["limitations"] == [
        "NO_API_SPEC",
        "TRAFFIC_TELEMETRY_UNAVAILABLE",
        "AUTHENTICATION_LOST",
    ]


def test_results_without_guard_traffic_are_not_a_loss() -> None:
    """T16 之前寫入的結果沒有 guard_traffic：不判定失效，但揭露「認證的狀態未知」。"""
    preflight, _ = _authenticated(PreflightResult.PASSED)
    details = dict(_zap_result(None).details)
    del details["guard_traffic"]
    result = RunResult("p/1", "2.17.0", 0, 0, details)

    out = _out((preflight, _run(2, Engine.ZAP, result=result)))

    assert out["coverage"]["limitations"] == ["AUTHENTICATION_HEALTH_UNKNOWN"]
    assert out["engines"][1]["result"]["guard_traffic"] is None


def test_unverifiable_auth_health_is_disclosed() -> None:
    """telemetry 不完整（auth 是 null）：看不出憑證是否整段有效（T16 的審查）。"""
    preflight, _ = _authenticated(PreflightResult.PASSED)
    zap = _run(2, Engine.ZAP, result=_zap_result(GuardTraffic(forwarded=9)))

    out = _out((preflight, zap))

    assert out["coverage"]["limitations"] == ["AUTHENTICATION_HEALTH_UNKNOWN"]
    assert out["coverage"]["authenticated_operations"] == 3


def test_anonymous_scans_have_no_auth_health_to_know() -> None:
    zap = _run(1, Engine.ZAP, result=_zap_result(GuardTraffic(forwarded=9)))

    assert _out((zap,), auth=None)["coverage"]["limitations"] == []


def test_engine_runs_show_the_guard_traffic() -> None:
    traffic = GuardTraffic(
        forwarded=9,
        denied={"PATH_AMBIGUOUS": 1},
        first_at=1_700_000_000.0,
        last_at=1_700_000_030.0,
        answered=8,
        auth=AuthHealth(accepted=5, rejected=3, regressed=0),
    )
    zap = _run(1, Engine.ZAP, result=_zap_result(traffic))

    out = _out((zap,), auth=None)

    assert out["engines"][0]["result"]["guard_traffic"] == {
        "forwarded": 9,
        "denied": {"PATH_AMBIGUOUS": 1},
        "exhausted": False,
        "first_at": "2023-11-14T22:13:20Z",
        "last_at": "2023-11-14T22:13:50Z",
        "answered": 8,
        "auth": {
            "accepted": 5,
            "rejected": 3,
            "regressed": 0,
            "probe_rejected": 0,
            "lost": False,
        },
    }


def test_engine_runs_show_what_was_executed() -> None:
    """每個 run 實際執行的 plan 與 profile 的定義（§20.2）：沒有收集的 run 也有。"""
    plan_hash, definition = "a" * 64, "b" * 64
    zap = _run(
        1,
        Engine.ZAP,
        status=RunStatus.TIMED_OUT,
        error_code=RunErrorCode.TIME_LIMIT_EXCEEDED,
        plan_hash=plan_hash,
        profile_definition_sha256=definition,
    )

    engine = _out((zap,), auth=None)["engines"][0]

    assert (engine["plan_hash"], engine["profile_definition_sha256"]) == (plan_hash, definition)
    assert engine["result"] is None


def test_anonymous_scans_never_lose_a_credential() -> None:
    """沒有綁定 auth profile 的 scan 沒有可以失效的憑證：details 的形狀不影響 limitation。"""
    zap = _run(1, Engine.ZAP, result=_zap_result(_lost(lost=True)))

    assert _out((zap,), auth=None)["coverage"]["limitations"] == []
