"""T33：可信資料、缺資料與不一致不得混為零流量。"""

from dataclasses import replace
from ipaddress import IPv4Address
from uuid import UUID

import pytest

from secscan.grants.domain.matching import ScopeRules
from secscan.grants.domain.scope import HttpMethod, Scope
from secscan.guard.domain.policy import GuardPolicyVersion
from secscan.guard.domain.telemetry import RunSummary
from secscan.scans.domain.coverage import Exchange
from secscan.targets.domain import parse_origin
from secscan.worker.evidence import EvidenceState, verify_telemetry

RUN, SCAN, BOOT = UUID(int=1), UUID(int=2), UUID(int=3)
STRICT = GuardPolicyVersion.STRICT
ENCODED = GuardPolicyVersion.ENCODED_PARAMS
RULES = ScopeRules.of(
    Scope(
        origins=(parse_origin("http://lab:5000"),),
        ips=(IPv4Address("10.89.7.20"),),
        paths=("/users/{name}",),
        allow_all_paths=False,
        excluded_paths=(),
        methods=(HttpMethod.GET,),
    )
)


def _summary(version: GuardPolicyVersion, count: int) -> RunSummary:
    return RunSummary(RUN, SCAN, BOOT, count, policy_version=version)


def test_encoded_evidence_needs_matching_summary_and_authorized_requests() -> None:
    evidence = verify_telemetry(
        run_id=RUN,
        scan_id=SCAN,
        policy_version=ENCODED,
        requests_sent=1,
        rules=RULES,
        summary=_summary(ENCODED, 1),
        exchanges=(Exchange("GET", "/users/name%27", False, 200),),
    )
    assert evidence.state is EvidenceState.TRUSTED
    assert evidence.trusted


@pytest.mark.parametrize("path", ["/admin", "/users/%252F", "/users/%41"])
def test_one_unauthorized_request_invalidates_the_whole_run(path: str) -> None:
    evidence = verify_telemetry(
        run_id=RUN,
        scan_id=SCAN,
        policy_version=ENCODED,
        requests_sent=1,
        rules=RULES,
        summary=_summary(ENCODED, 1),
        exchanges=(Exchange("GET", path, False, 200),),
    )
    assert evidence.state is EvidenceState.INCONSISTENT
    assert not evidence.trusted


@pytest.mark.parametrize("count", [0, 1])
def test_wrong_policy_is_not_hidden_by_zero_requests(count: int) -> None:
    evidence = verify_telemetry(
        run_id=RUN,
        scan_id=SCAN,
        policy_version=ENCODED,
        requests_sent=count,
        rules=RULES,
        summary=_summary(STRICT, count),
        exchanges=(),
    )
    assert evidence.state is EvidenceState.INCONSISTENT
    assert evidence.summary is not None
    assert evidence.summary.policy_version is STRICT


def test_zero_count_does_not_hide_a_recorded_request() -> None:
    evidence = verify_telemetry(
        run_id=RUN,
        scan_id=SCAN,
        policy_version=STRICT,
        requests_sent=0,
        rules=RULES,
        summary=_summary(STRICT, 0),
        exchanges=(Exchange("GET", "/users/a", False, 200),),
    )
    assert evidence.state is EvidenceState.INCONSISTENT


@pytest.mark.parametrize(
    ("version", "expected"), [(STRICT, EvidenceState.TRUSTED), (ENCODED, EvidenceState.MISSING)]
)
def test_only_strict_retains_the_missing_last_line_tolerance(
    version: GuardPolicyVersion,
    expected: EvidenceState,
) -> None:
    evidence = verify_telemetry(
        run_id=RUN,
        scan_id=SCAN,
        policy_version=version,
        requests_sent=2,
        rules=RULES,
        summary=_summary(version, 2),
        exchanges=(Exchange("GET", "/users/a", False, 200),),
    )
    assert evidence.state is expected


def test_historical_strict_can_use_jsonl_without_a_summary() -> None:
    evidence = verify_telemetry(
        run_id=RUN,
        scan_id=SCAN,
        policy_version=STRICT,
        requests_sent=1,
        rules=RULES,
        summary=None,
        exchanges=(Exchange("GET", "/users/a", False, 200),),
    )
    assert evidence.trusted


def test_encoded_needs_summary_even_when_no_requests_were_sent() -> None:
    evidence = verify_telemetry(
        run_id=RUN,
        scan_id=SCAN,
        policy_version=ENCODED,
        requests_sent=0,
        rules=RULES,
        summary=None,
        exchanges=None,
    )
    assert evidence.state is EvidenceState.MISSING


def test_summary_for_another_scan_is_inconsistent() -> None:
    evidence = verify_telemetry(
        run_id=RUN,
        scan_id=SCAN,
        policy_version=STRICT,
        requests_sent=0,
        rules=RULES,
        summary=replace(_summary(STRICT, 0), scan_id=BOOT),
        exchanges=None,
    )
    assert evidence.state is EvidenceState.INCONSISTENT
