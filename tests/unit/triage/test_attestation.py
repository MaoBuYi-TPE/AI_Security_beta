"""人工複測聲明：只做一致性檢查與遮罩，不證明真實性；平台欄位由平台填寫。"""

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from secscan.findings.domain.fingerprint import RouteSource
from secscan.findings.domain.triage import REQUEST_EXCERPT_MAX_BYTES
from secscan.triage.domain.attestation import (
    PLATFORM_CHECKS,
    Attestation,
    AttestationError,
    AttestationProblem,
    FindingLocation,
    TargetHost,
    check_attestation,
    mask_excerpt,
)

A = AttestationProblem
NOW = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)
LAST = NOW - timedelta(hours=1)
LOCATION = FindingLocation("GET", "/search", RouteSource.LITERAL, "q", "anonymous")
TARGET = TargetHost("lab-fixture", 8080)
REQUEST = "GET /search?q=apple' HTTP/1.1\nHost: lab-fixture:8080\nAccept: */*\n"
RESPONSE = "HTTP/1.1 200\n\n[]"
ATTESTATION = Attestation(
    performed_at=NOW - timedelta(minutes=5),
    performed_by="lab operator",
    procedure="以單引號送出 q，確認回應不是 500。\n比對回應內容。",
    result="not_reproduced",
    auth_role="anonymous",
    request_excerpt=REQUEST,
    response_excerpt=RESPONSE,
)


def check(
    attestation: Attestation = ATTESTATION,
    location: FindingLocation = LOCATION,
    target: TargetHost = TARGET,
    last: datetime | None = LAST,
) -> object:
    return check_attestation(attestation, location, target, now=NOW, last_observed_at=last)


def problems_of(**changes: object) -> tuple[AttestationProblem, ...]:
    with pytest.raises(AttestationError) as caught:
        check(replace(ATTESTATION, **changes))  # type: ignore[arg-type]
    return caught.value.problems


def test_consistent_attestation_records_hashes_and_platform_fields() -> None:
    checked = check_attestation(ATTESTATION, LOCATION, TARGET, now=NOW, last_observed_at=LAST)
    evidence = checked.evidence()
    assert evidence["provenance"] == "operator_supplied"
    assert evidence["platform_checks"] == list(PLATFORM_CHECKS)
    # 檢查名稱不暗示平台驗證了結果：只是「宣稱的結果」符合要求（checks_version 2）。
    assert evidence["checks_version"] == 2
    assert "declared_result_is_not_reproduced" in PLATFORM_CHECKS
    assert "result_not_reproduced" not in PLATFORM_CHECKS
    assert evidence["request_excerpt_sha256"] == hashlib.sha256(REQUEST.encode()).hexdigest()
    assert evidence["response_excerpt_bytes"] == len(RESPONSE.encode())
    # 事件 metadata 不含摘錄內容（另存、T23a 可清除）。
    assert REQUEST not in str(evidence)
    assert "apple" not in str(evidence)
    assert evidence["role"] == "anonymous"
    assert "auth_role" not in evidence


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"result": "reproduced"}, A.RESULT_NOT_ACCEPTED),
        ({"auth_role": "admin"}, A.ROLE_MISMATCH),
        ({"performed_at": NOW + timedelta(seconds=1)}, A.PERFORMED_IN_FUTURE),
        ({"performed_at": LAST - timedelta(seconds=1)}, A.PERFORMED_BEFORE_LAST_OBSERVATION),
        ({"performed_by": "two\nlines"}, A.PERFORMED_BY_INVALID),
        ({"performed_by": " "}, A.PERFORMED_BY_INVALID),
        ({"performed_by": "x" * 101}, A.PERFORMED_BY_INVALID),
        ({"procedure": "esc\x1b[31m"}, A.PROCEDURE_INVALID),
        ({"procedure": "bidi‮"}, A.PROCEDURE_INVALID),
        ({"procedure": "x" * 1001}, A.PROCEDURE_INVALID),
        (
            {"request_excerpt": "POST /search?q=1 HTTP/1.1\nHost: lab-fixture:8080\n"},
            A.REQUEST_LINE_MISMATCH,
        ),
        (
            {"request_excerpt": "GET /other?q=1 HTTP/1.1\nHost: lab-fixture:8080\n"},
            A.REQUEST_LINE_MISMATCH,
        ),
        ({"request_excerpt": "GET /search?q=1\nHost: lab-fixture:8080\n"}, A.REQUEST_LINE_MISMATCH),
        ({"request_excerpt": "GET /search?q=1 HTTP/1.1\nHost: other:8080\n"}, A.HOST_MISMATCH),
        ({"request_excerpt": "GET /search?q=1 HTTP/1.1\nHost: lab-fixture\n"}, A.HOST_MISMATCH),
        ({"request_excerpt": "GET /search?q=1 HTTP/1.1\nAccept: */*\n"}, A.HOST_MISMATCH),
        # absolute-form：authority 以 request-target 為準，必須是 http 而且等於 target。
        (
            {
                "request_excerpt": "GET http://other.example/search?q=1 HTTP/1.1\n"
                "Host: lab-fixture:8080\n"
            },
            A.HOST_MISMATCH,
        ),
        (
            {
                "request_excerpt": "GET https://lab-fixture:8080/search?q=1 HTTP/1.1\n"
                "Host: lab-fixture:8080\n"
            },
            A.HOST_MISMATCH,
        ),
        (
            {
                "request_excerpt": "GET http://user@lab-fixture:8080/search?q=1 HTTP/1.1\n"
                "Host: lab-fixture:8080\n"
            },
            A.HOST_MISMATCH,
        ),
        (
            {
                "request_excerpt": "GET /search?q=1 HTTP/1.1\nHost: lab-fixture:8080\n"
                "Host: lab-fixture:8080\n"
            },
            A.HOST_MISMATCH,
        ),
        (
            {"request_excerpt": "GET /search?x=1 HTTP/1.1\nHost: lab-fixture:8080\n"},
            A.PARAMETER_MISSING,
        ),
        ({"response_excerpt": "200 OK\n\n[]"}, A.RESPONSE_STATUS_LINE_MISSING),
        ({"response_excerpt": "HTTP/1.1 999\n"}, A.RESPONSE_STATUS_LINE_MISSING),
        (
            {"request_excerpt": "GET /search?q=" + "x" * REQUEST_EXCERPT_MAX_BYTES + " HTTP/1.1\n"},
            A.EXCERPT_TOO_LARGE,
        ),
        ({"response_excerpt": "   "}, A.EXCERPT_EMPTY),
        ({"request_excerpt": ""}, A.EXCERPT_EMPTY),
        # 名稱只是其他名稱的一部分、或只出現在 query 值中，都不算有這個參數。
        (
            {"request_excerpt": "GET /search?xq=1 HTTP/1.1\nHost: lab-fixture:8080\n"},
            A.PARAMETER_MISSING,
        ),
        (
            {"request_excerpt": "GET /search?x=q HTTP/1.1\nHost: lab-fixture:8080\n"},
            A.PARAMETER_MISSING,
        ),
    ],
)
def test_each_inconsistency_is_rejected(changes: dict[str, object], expected: A) -> None:
    assert expected in problems_of(**changes)


def test_empty_excerpt_is_not_reported_as_too_large() -> None:
    assert A.EXCERPT_TOO_LARGE not in problems_of(response_excerpt="  \n ")


def test_query_parameter_is_only_matched_in_the_request_target_query() -> None:
    query = replace(LOCATION, parameter_location="query")
    in_body = "GET /search HTTP/1.1\nHost: lab-fixture:8080\n\nq=1"
    with pytest.raises(AttestationError) as caught:
        check(replace(ATTESTATION, request_excerpt=in_body), query)
    assert caught.value.problems == (A.PARAMETER_MISSING,)
    absolute = "GET http://lab-fixture:8080/search?q=1 HTTP/1.1\nHost: lab-fixture:8080\n"
    check(replace(ATTESTATION, request_excerpt=absolute), query)
    check(replace(ATTESTATION, request_excerpt="GET /search?a=1&q= HTTP/1.1\n" + _HOST), query)


_HOST = "Host: lab-fixture:8080\n"


def test_unknown_location_also_matches_header_names_and_body() -> None:
    unknown = replace(LOCATION, parameter_location="unknown", parameter_name="X-Trace")
    header = "GET /search HTTP/1.1\n" + _HOST + "x-trace: 1\n"
    check(replace(ATTESTATION, request_excerpt=header), unknown)
    body = "GET /search HTTP/1.1\n" + _HOST + '\n{"X-Trace": 1}'
    check(replace(ATTESTATION, request_excerpt=body), unknown)
    form = "GET /search HTTP/1.1\n" + _HOST + "\na=1&X-Trace=2"
    check(replace(ATTESTATION, request_excerpt=form), unknown)
    nested = "GET /search HTTP/1.1\n" + _HOST + '\n{"outer": [{"X-Trace": 1}]}'
    check(replace(ATTESTATION, request_excerpt=nested), unknown)
    # 只是其他鍵名或值的一部分不算（不做子字串比對）。
    for body in ('{"X-Trace-Id": 1}', '{"a": "X-Trace"}', "MyX-Trace=1", "[" * 3000):
        partial = "GET /search HTTP/1.1\n" + _HOST + "\n" + body
        with pytest.raises(AttestationError):
            check(replace(ATTESTATION, request_excerpt=partial), unknown)
    # 沒有冒號的畸形 header 行不影響 body 的起點。
    malformed = "GET /search HTTP/1.1\n" + _HOST + "garbage\n\nX-Trace=1"
    check(replace(ATTESTATION, request_excerpt=malformed), unknown)
    missing = "GET /search HTTP/1.1\n" + _HOST + "Accept: x-trace\nX-Trace\n\nnothing"
    with pytest.raises(AttestationError) as caught:
        check(replace(ATTESTATION, request_excerpt=missing), unknown)
    assert caught.value.problems == (A.PARAMETER_MISSING,)


def test_all_problems_are_reported_together() -> None:
    found = problems_of(result="reproduced", auth_role="admin", response_excerpt="nope")
    assert found == (A.RESULT_NOT_ACCEPTED, A.ROLE_MISMATCH, A.RESPONSE_STATUS_LINE_MISSING)


def test_openapi_templates_absolute_form_and_default_port() -> None:
    location = FindingLocation("GET", "/users/{id}", RouteSource.OPENAPI, None, "anonymous")
    request = "GET http://lab-fixture/users/42 HTTP/1.1\nHost: lab-fixture\n"
    attestation = replace(ATTESTATION, request_excerpt=request)
    check(attestation, location, TargetHost("lab-fixture", 80))
    for path in ("/users/42/x", "/users/", "/users"):
        bad = replace(ATTESTATION, request_excerpt=f"GET {path} HTTP/1.1\nHost: lab-fixture\n")
        with pytest.raises(AttestationError):
            check(bad, location, TargetHost("lab-fixture", 80))
    # 字面 route 不把 {id} 當成樣板。
    literal = replace(location, route_source=RouteSource.LITERAL)
    with pytest.raises(AttestationError):
        check(attestation, literal, TargetHost("lab-fixture", 80))


def test_no_last_observation_and_no_parameter() -> None:
    location = replace(LOCATION, parameter_name=None)
    check(replace(ATTESTATION, performed_at=LAST - timedelta(days=1)), location, last=None)


def test_excerpts_are_masked_before_hashing_and_crlf_is_normalised() -> None:
    request = (
        "GET /search?q=1&token=s3cr3t-value HTTP/1.1\r\nHost: lab-fixture:8080\r\n"
        "Authorization: Bearer abc.def.ghi\r\nCookie: sid=zzzz\r\n\r\n"
    )
    checked = check_attestation(
        replace(ATTESTATION, request_excerpt=request),
        LOCATION,
        TARGET,
        now=NOW,
        last_observed_at=LAST,
    )
    stored = checked.request_excerpt
    assert "\r" not in stored
    for secret in ("s3cr3t-value", "abc.def.ghi", "zzzz"):
        assert secret not in stored
    assert checked.request_sha256 == hashlib.sha256(stored.encode()).hexdigest()


@given(st.text(max_size=300))
def test_masked_excerpts_are_idempotent_and_bounded(value: str) -> None:
    masked = mask_excerpt(value, REQUEST_EXCERPT_MAX_BYTES)
    if masked is None:
        return
    assert len(masked.encode("utf-8")) <= REQUEST_EXCERPT_MAX_BYTES
    assert "\r" not in masked
    assert "\x00" not in masked
    assert mask_excerpt(masked, REQUEST_EXCERPT_MAX_BYTES) == masked


def test_only_the_checks_actually_run_are_recorded() -> None:
    with_parameter = check()
    assert "parameter_present" in with_parameter.evidence()["platform_checks"]  # type: ignore[attr-defined]
    no_parameter = replace(LOCATION, parameter_name=None)
    request = "GET /search HTTP/1.1\n" + _HOST
    checked = check(replace(ATTESTATION, request_excerpt=request), no_parameter)
    recorded = checked.evidence()["platform_checks"]  # type: ignore[attr-defined]
    assert "parameter_present" not in recorded
    assert len(recorded) == len(PLATFORM_CHECKS) - 1


def test_target_secret_headers_and_indented_headers_are_masked() -> None:
    target = replace(TARGET, secret_header_names=frozenset({"x-lab"}))
    request = (
        "GET /search?q=1 HTTP/1.1\n" + _HOST + "X-Lab: s3cr3t-value\n Authorization: Token abc\n"
    )
    checked = check(replace(ATTESTATION, request_excerpt=request), target=target)
    assert "s3cr3t-value" not in checked.request_excerpt  # type: ignore[attr-defined]
    assert "Token abc" not in checked.request_excerpt  # type: ignore[attr-defined]


def test_an_excerpt_without_a_trailing_blank_line_is_consistent() -> None:
    request = "GET /search?q=1 HTTP/1.1\nHost: lab-fixture:8080"
    check(replace(ATTESTATION, request_excerpt=request))
