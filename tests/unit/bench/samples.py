"""harness 測試用的 API 回應樣本：一律先通過平台真正的輸出 schema，確保和 API 的形狀一致。"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from secscan.comparisons.schemas import ComparisonFindingOut, ComparisonOut
from secscan.findings.schemas import FindingOut
from secscan.grants.domain.scope import Budget
from secscan.scans.domain.allocation import EngineBudget
from secscan.scans.domain.catalog import Engine, ScanProfile
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus, ScanStatus
from secscan.scans.domain.model import Scan, ScannerRun, VersionRef
from secscan.scans.domain.observation import ParsedRun, RunOutcome, RunResult, result_details
from secscan.scans.domain.traffic import GuardTraffic
from secscan.scans.schemas import ScanOut
from secscan.targets.domain import parse_origin

NOW = datetime(2026, 11, 8, 8, 0, tzinfo=UTC)
LATER = datetime(2026, 11, 8, 8, 10, tzinfo=UTC)


def _result(observations: int, *, exhausted: bool, limit: bool) -> RunResult:
    outcome = RunOutcome(RunStatus.TIMED_OUT, RunErrorCode.ENGINE_TIMEOUT) if limit else None
    parsed = ParsedRun(
        parser_version="p/1",
        outcome=outcome or RunOutcome(RunStatus.SUCCEEDED),
        traffic=GuardTraffic(forwarded=10, answered=10, exhausted=exhausted),
        time_limit_reached=limit,
    )
    return RunResult(
        parser_version="p/1",
        engine_version="1",
        exit_code=0,
        observation_count=observations,
        details=result_details(parsed),
    )


def zap_run(scan_id: UUID, *, capped: bool = True, parsed: bool = True) -> ScannerRun:
    return ScannerRun(
        id=uuid4(),
        scan_id=scan_id,
        engine=Engine.ZAP,
        sequence=1,
        status=RunStatus.TIMED_OUT,
        error_code=RunErrorCode.ENGINE_TIMEOUT,
        started_at=NOW,
        finished_at=LATER,
        created_at=NOW,
        container=True,
        requests_sent=700,
        requests_denied=4,
        traffic_seconds=375,
        plan_hash="a" * 64,
        budget=EngineBudget(760, 380) if capped else None,
        requests_allotted=760,
        seconds_allotted=380,
        result=_result(12, exhausted=False, limit=True) if parsed else None,
    )


def nuclei_run(scan_id: UUID, *, capped: bool = True) -> ScannerRun:
    """被 runner 停止、沒有收集的 Nuclei：沒有 result，只有 guard 的計數。"""
    return ScannerRun(
        id=uuid4(),
        scan_id=scan_id,
        engine=Engine.NUCLEI,
        sequence=2,
        status=RunStatus.TIMED_OUT,
        error_code=RunErrorCode.TIME_LIMIT_EXCEEDED,
        started_at=NOW,
        finished_at=LATER,
        created_at=NOW,
        container=True,
        requests_sent=200,
        requests_denied=0,
        traffic_seconds=221,
        plan_hash="b" * 64,
        budget=EngineBudget(440, 220) if capped else None,
        requests_allotted=440,
        seconds_allotted=220,
    )


def scan_json(**overrides: Any) -> dict[str, Any]:
    """ScanOut 的 JSON（經真正的 schema 產生）。"""
    scan_id = overrides.pop("scan_id", uuid4())
    fields: dict[str, Any] = {
        "id": scan_id,
        "project_id": uuid4(),
        "target_id": uuid4(),
        "target_origin": parse_origin("http://lab-fixture-abc123:8080"),
        "status": ScanStatus.TIMED_OUT,
        "profile": ScanProfile.WEB_ACTIVE_LAB,
        "scope_grant": VersionRef(id=uuid4(), version=1),
        "api_spec": None,
        "auth": None,
        "budget": Budget(requests_per_second=2, max_requests=1_200, max_duration_seconds=600),
        "runs": (zap_run(scan_id), nuclei_run(scan_id)),
        "coverage": None,
        "cancel_requested_at": None,
        "created_by_key_id": uuid4(),
        "created_at": NOW,
        "finished_at": LATER,
    }
    fields.update(overrides)
    return ScanOut.of(Scan(**fields)).model_dump(mode="json")


def finding_json(
    rule_group: str,
    *,
    route: str = "/",
    method: str = "GET",
    parameter_location: str | None = None,
    parameter_name: str | None = None,
    engines: tuple[str, ...] = ("zap",),
    kind: str = "security",
    finding_id: str | None = None,
) -> dict[str, Any]:
    """FindingOut 的 JSON（先以真正的 schema 驗證）。"""
    scan = str(uuid4())
    sample: dict[str, Any] = {
        "id": finding_id or str(uuid4()),
        "target_id": str(uuid4()),
        "kind": kind,
        "category": "vulnerability",
        "rule_group": rule_group,
        "title": f"title of {rule_group}",
        "normalized_severity": "medium",
        "severity_conflict": False,
        "needs_review": False,
        "cwe_ids": [],
        "cwe_source": None,
        "location": {
            "method": method,
            "route": route,
            "route_source": "literal",
            "parameter_location": parameter_location,
            "parameter_name": parameter_name,
            "resource": None,
        },
        "auth_role": "anonymous",
        "auth_verified": True,
        "owasp": {
            "top10_2025": None,
            "top10_2025_source": "none",
            "top10_2025_unmapped_reason": "no_cwe",
            "api_2023": None,
            "api_2023_source": "none",
            "api_2023_unmapped_reason": None,
        },
        "mapping_version": "rules-2+owasp-1",
        "triage_state": "unreviewed",
        "lifecycle_state": "open",
        "triage_version": 0,
        "resolution_review_required": False,
        "resolution_review_reasons": [],
        "first_seen_scan_id": scan,
        "last_seen_scan_id": scan,
        "created_at": NOW.isoformat(),
        "last_seen_at": NOW.isoformat(),
        "scan_severity": "medium",
        "tool_cwe_ids": [],
        "sources": [
            {
                "engine": engine,
                "source_rule": f"{engine}-rule",
                "rule_variant": None,
                "raw_severity": "2",
                "severity_label": "Medium",
                "normalized_severity": "medium",
                "raw_confidence": "2",
                "confidence_label": "Medium",
                "normalized_confidence": "medium",
                "cwe_id": None,
                "observations": 2,
            }
            for engine in engines
        ],
        "related_finding_ids": [],
    }
    return FindingOut.model_validate(sample).model_dump(mode="json")


def comparison_json(
    baseline: str, current: str, items: list[tuple[str, str]]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """ComparisonOut 與 ComparisonFindingOut 的 JSON（先以真正的 schema 驗證）。"""
    classes = ("new", "persistent", "not_observed", "inconclusive", "not_comparable")
    counts = dict.fromkeys(classes, 0)
    for _, classification in items:
        counts[classification] += 1
    snapshot = {
        "id": str(uuid4()),
        "project_id": str(uuid4()),
        "target_id": str(uuid4()),
        "baseline_scan_id": baseline,
        "current_scan_id": current,
        "algorithm_version": 1,
        "comparability": "comparable",
        "reasons": [],
        "manual_review_required": False,
        "counts": counts,
        "created_at": NOW.isoformat(),
    }
    evidence = {
        "baseline_observed": True,
        "current_observed": False,
        "fingerprint_comparable": True,
        "mapping_comparable": True,
        "finding_identity_verified": True,
        "other_scan_coverage": None,
        "reidentified": False,
    }
    findings = [
        {
            "finding_id": finding_id,
            "classification": classification,
            "reasons": [] if classification == "persistent" else ["coverage_missing"],
            "manual_review_required": False,
            "evidence": evidence,
        }
        for finding_id, classification in items
    ]
    validated = ComparisonOut.model_validate(snapshot).model_dump(mode="json")
    return validated, [
        ComparisonFindingOut.model_validate(item).model_dump(mode="json") for item in findings
    ]
