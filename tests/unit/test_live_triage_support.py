"""T21 live 的輔助：修補行為的判斷、照實組成的人工複測聲明、報告的核對（不連網）。"""

import hashlib
from datetime import UTC, datetime

import pytest

from secscan.findings.domain.fingerprint import RouteSource
from secscan.reports.domain.model import ReportFormat
from secscan.reports.domain.render import render
from secscan.triage.domain.attestation import (
    Attestation,
    FindingLocation,
    TargetHost,
    check_attestation,
)
from tests.live.report_assertions import check_document, check_headers, check_markdown
from tests.live.triage_support import (
    LOCATION_PROBLEMS,
    Observed,
    assert_rejected_for,
    attestation,
    confirm_body,
    located_attestation,
    passes,
    platform_problems,
    resolve_body,
)
from tests.unit.reports.factory import NOW, snapshot

AT = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)


def observed(case_id: str, status: int, body: str) -> Observed:
    path = "/search?q=apple%27" if case_id == "T30-FX-01" else "/greet?name=%3Cb%3Ex%3C%2Fb%3E"
    return Observed(case_id, "GET", path, status, body, AT)


def test_patched_behaviour_must_hold_before_it_becomes_evidence() -> None:
    assert passes(observed("T30-FX-01", 200, "[]"))
    assert not passes(observed("T30-FX-01", 500, "OperationalError"))
    assert not passes(observed("T30-FX-01", 0, ""))
    assert passes(observed("T30-FX-02", 200, "Hello &lt;b&gt;x&lt;/b&gt;"))
    assert not passes(observed("T30-FX-02", 200, "Hello <b>x</b>"))


@pytest.mark.parametrize(
    ("case_id", "route", "parameter"),
    [("T30-FX-01", "/search", "q"), ("T30-FX-02", "/greet", "name")],
)
def test_attestations_pass_the_platform_consistency_checks(
    case_id: str, route: str, parameter: str
) -> None:
    body = attestation(
        observed(case_id, 200, "ok &lt;b&gt;x&lt;/b&gt;"), "lab-x", 8080, "anonymous"
    )
    assert body["request_excerpt"].startswith(f"GET {route}?")
    assert "HTTP/1.1 200\n\n" in body["response_excerpt"]
    checked = check_attestation(
        Attestation(
            performed_at=AT,
            performed_by=body["performed_by"],
            procedure=body["procedure"],
            result=body["result"],
            auth_role=body["auth_role"],
            request_excerpt=body["request_excerpt"],
            response_excerpt=body["response_excerpt"],
        ),
        FindingLocation("GET", route, RouteSource.LITERAL, parameter, "anonymous"),
        TargetHost("lab-x", 8080),
        now=AT,
        last_observed_at=None,
    )
    assert checked.request_sha256 == hashlib.sha256(checked.request_excerpt.encode()).hexdigest()


def test_request_bodies_and_platform_conditions() -> None:
    assert confirm_body(0)["triage_state"] == "confirmed"
    assert "attestation" not in resolve_body(1, "c", None, basis="rescan_not_observed")
    assert resolve_body(1, "c", {"x": 1})["attestation"] == {"x": 1}
    snapshot_row = {"algorithm_version": 1, "comparability": "comparable"}
    assert platform_problems(snapshot_row, None) == ["finding_not_in_comparison"]


def test_report_checks_accept_platform_reports_and_reject_tampering() -> None:
    item = snapshot()
    rendered = render(item, generated_at=NOW)
    meta = {
        "id": "00000000-0000-0000-0000-000000000003",
        "scan_id": "00000000-0000-0000-0000-000000000001",
        "format": "markdown",
        "sha256": hashlib.sha256(rendered.content).hexdigest(),
        "size_bytes": len(rendered.content),
    }
    headers = {
        "Content-Type": "text/markdown; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; sandbox",
        "Cache-Control": "no-store",
        "Content-Disposition": 'attachment; filename="secscan-report-00000000-00000000.md"',
    }
    check_headers(meta, headers, rendered.content)
    with pytest.raises(AssertionError):
        check_headers(meta, headers, rendered.content + b"x")
    check_markdown(rendered.content.decode())
    with pytest.raises(AssertionError):
        check_markdown("[x](http://evil.example)")
    as_json = render(snapshot(report_format=ReportFormat.JSON), generated_at=NOW)
    document = check_document(as_json.content, complete=False)
    assert document.findings


def _finding(route: str, parameter: str | None, role: str = "anonymous") -> dict[str, object]:
    location = {
        "method": "GET",
        "route": route,
        "parameter_location": "query" if parameter else None,
        "parameter_name": parameter,
    }
    return {"location": location, "auth_role": role}


@pytest.mark.parametrize(
    ("route", "source", "parameter"),
    [("/", RouteSource.LITERAL, None), ("/users/{id}", RouteSource.OPENAPI, "q")],
)
def test_located_attestations_match_their_own_finding(
    route: str, source: RouteSource, parameter: str | None
) -> None:
    body = located_attestation(
        _finding(route, parameter, "user"), observed("T30-FX-01", 200, "[]"), "lab-x", 8080
    )
    assert body["auth_role"] == "user"
    check_attestation(
        Attestation(
            performed_at=AT,
            performed_by=body["performed_by"],
            procedure=body["procedure"],
            result=body["result"],
            auth_role=body["auth_role"],
            request_excerpt=body["request_excerpt"],
            response_excerpt=body["response_excerpt"],
        ),
        FindingLocation("GET", route, source, parameter, "user", "query" if parameter else None),
        TargetHost("lab-x", 8080),
        now=AT,
        last_observed_at=None,
    )


def _rejected(*codes: str) -> dict[str, object]:
    message = "證據不足，不能標成 resolved：" + ", ".join(codes)
    return {"error": {"code": "RESOLUTION_EVIDENCE_INSUFFICIENT", "message": message}}


def test_rejections_must_come_from_the_platform_conditions() -> None:
    found = assert_rejected_for(
        _rejected("engine_incomplete", "performed_before_last_observation"), ["engine_incomplete"]
    )
    assert found == {"engine_incomplete", "performed_before_last_observation"}
    with pytest.raises(AssertionError):
        assert_rejected_for(_rejected("row_not_inconclusive"), ["engine_incomplete"])
    for problem in LOCATION_PROBLEMS:
        with pytest.raises(AssertionError):
            assert_rejected_for(_rejected("engine_incomplete", problem), ["engine_incomplete"])
    with pytest.raises(AssertionError):
        assert_rejected_for(_rejected("engine_incomplete"), [])
    with pytest.raises(AssertionError):
        assert_rejected_for({"error": {"code": "INVALID_REQUEST", "message": "x"}}, ["x"])
