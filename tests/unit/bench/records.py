"""評估測試用的紀錄與合成的 ground truth（不是真正的案例表；正式的比對檔由 T27 撰寫）。"""

import json
from dataclasses import replace
from typing import Any

from benchmarks.ground_truth import GroundTruth
from benchmarks.models import (
    EngineCap,
    FindingRecord,
    LabeledScan,
    RunRecord,
    ScanRecord,
    Signature,
)

SQLI = Signature("sql-injection", "GET", "/search", "query", "q")
XSS = Signature("xss-reflected", "GET", "/greet", "query", "name")
XCTO = Signature("security-headers", "GET", "/", "header", "x-content-type-options")
CSP = Signature("security-headers", "GET", "/", "header", "content-security-policy")
ERROR = Signature("error-disclosure", "GET", "/search", None, None)
BLOCKED = Signature("sql-injection", "GET", "/users/{username}", "path", "username")
EXTRA = Signature("crlf-injection", "GET", "/", "query", "x")
NOISE = Signature("zap:10202", "GET", "/form", None, None)

TRUTH: dict[str, Any] = {
    "version": 1,
    "status": "draft",
    "target": "fixture",
    "cases": [
        {
            "id": "SQLI-1",
            "kind": "security",
            "support": "supported",
            "holdout": False,
            "present_in": ["insecure"],
            "matchers": [
                {
                    "rule_group": "sql-injection",
                    "method": "GET",
                    "route": "/search",
                    "parameter_location": ["query"],
                    "parameter_name": "q",
                }
            ],
        },
        {
            "id": "XSS-1",
            "kind": "security",
            "support": "supported",
            "holdout": False,
            "present_in": ["insecure"],
            "matchers": [{"rule_group": "xss-reflected", "route": "/greet"}],
        },
        {
            "id": "HDR-1",
            "kind": "security",
            "support": "supported",
            "holdout": False,
            "present_in": ["insecure"],
            "matchers": [
                {"rule_group": "security-headers", "parameter_name": "x-content-type-options"},
                {"rule_group": "security-headers", "parameter_name": "content-security-policy"},
            ],
        },
        {
            "id": "ERR-1",
            "kind": "security",
            "support": "supported",
            "holdout": True,
            "present_in": ["insecure"],
            "matchers": [{"rule_group": "error-disclosure"}],
        },
        {
            "id": "BOLA-1",
            "kind": "security",
            "support": "unsupported",
            "holdout": False,
            "auth_role": "standard_user",
            "present_in": ["insecure"],
        },
        {
            "id": "PB-1",
            "kind": "security",
            "support": "platform_blocked",
            "holdout": False,
            "present_in": ["insecure"],
            "matchers": [{"rule_group": "sql-injection", "route": "/users/{username}"}],
        },
        {
            "id": "IDOR-1",
            "kind": "security",
            "support": "supported",
            "holdout": False,
            "auth_role": "standard_user",
            "present_in": ["insecure"],
            "matchers": [{"rule_group": "idor"}],
        },
        {
            "id": "C-1",
            "kind": "contract",
            "support": "supported",
            "holdout": False,
            "present_in": ["insecure"],
            "matchers": [{"rule_group": "http-500"}],
        },
    ],
}


def truth(**overrides: Any) -> GroundTruth:
    document = {**TRUTH, **overrides}
    return GroundTruth.model_validate(json.loads(json.dumps(document)))


def finding(
    signature: Signature,
    *engines: str,
    kind: str = "security",
    observations: int = 1,
    finding_id: str | None = None,
) -> FindingRecord:
    return FindingRecord(
        id=finding_id or f"{signature.rule_group}:{signature.route}:{signature.parameter_name}",
        kind=kind,
        signature=signature,
        engines=tuple(sorted(engines or ("zap",))),
        observations=observations,
    )


def run(engine: str, **overrides: Any) -> RunRecord:
    fields: dict[str, Any] = {
        "engine": engine,
        "sequence": 1 if engine == "zap" else 2,
        "status": "succeeded",
        "error_code": None,
        "plan_hash": "a" * 64,
        "cap": None,
        "requests_allotted": 600,
        "seconds_allotted": 300,
        "requests_sent": 100,
        "requests_denied": 2,
        "traffic_seconds": 120,
        "observation_count": 3,
        "time_limit_reached": False,
        "guard_exhausted": False,
    }
    fields.update(overrides)
    return RunRecord(**fields)


def scan(*findings: FindingRecord, **overrides: Any) -> ScanRecord:
    fields: dict[str, Any] = {
        "id": "scan-1",
        "status": "completed",
        "fixture": False,
        "profile": "web_active_lab",
        "auth_role": "anonymous",
        "requests_per_second": 2,
        "max_requests": 1_200,
        "max_duration_seconds": 600,
        "runs": (run("zap"), run("nuclei")),
        "findings": findings,
        "observation_count": max(1, sum(f.observations for f in findings)),
        "coverage_measured": False,
        "eligible_operations": None,
        "observed_operations": None,
        "created_at": "2026-11-08T08:00:00Z",
        "finished_at": "2026-11-08T08:10:30Z",
    }
    fields.update(overrides)
    return ScanRecord(**fields)


def labeled(record: ScanRecord, **overrides: Any) -> LabeledScan:
    fields: dict[str, Any] = {
        "position": 1,
        "group": "C",
        "target": "fixture",
        "target_kind": "fixture",
        "variant": "insecure",
        "repetition": 1,
        "comparison": None,
        "role": None,
        "scan": record,
    }
    fields.update(overrides)
    return LabeledScan(**fields)


def capped(record: RunRecord, requests: int, seconds: int) -> RunRecord:
    return replace(record, cap=EngineCap(requests, seconds))
