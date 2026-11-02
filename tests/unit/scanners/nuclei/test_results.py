"""Nuclei JSONL parser 的判定與觀察（T18；DECISIONS §19.2 至 §19.5、§23）；純函式。

以真實的 golden JSONL（tests/fixtures/nuclei/）為主，壞掉的輸出由合成的行驅動。CLAUDE.md §8：
零告警、工具失敗、未掃到端點是不同的語意，必須明確可分。guard 的合成 403 要排除、目標真正回的
403 不能排除。
"""

import json
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from secscan.grants.domain.matching import ScopeRules
from secscan.grants.domain.scope import HttpMethod, Scope
from secscan.scanners.domain.nuclei.policy import INCLUDE_TEMPLATE_IDS, NUCLEI_VERSION
from secscan.scanners.domain.nuclei.results import (
    MAX_REPORT_BYTES,
    PARSER_VERSION,
    JsonlProblem,
    NucleiOutput,
    interpret,
    parse_report,
)
from secscan.scans.domain.coverage import Exchange
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.domain.observation import Exclusion, ParameterLocation, RunOutcome
from secscan.security.redaction import REDACTED
from secscan.targets.domain import parse_origin

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "nuclei"
ORIGIN = parse_origin("http://juice-shop:3000")
EVERY_METHOD = (HttpMethod.GET, HttpMethod.HEAD, HttpMethod.POST)
SUCCEEDED = RunOutcome(RunStatus.SUCCEEDED)
ENGINE_FAILED = RunOutcome(RunStatus.FAILED, RunErrorCode.ENGINE_FAILED)
OUTPUT_INVALID = RunOutcome(RunStatus.FAILED, RunErrorCode.OUTPUT_INVALID)
NO_TARGET_TRAFFIC = RunOutcome(RunStatus.FAILED, RunErrorCode.NO_TARGET_TRAFFIC)
TIMED_OUT = RunOutcome(RunStatus.TIMED_OUT, RunErrorCode.ENGINE_TIMEOUT)


def _rules(
    *, methods: tuple[HttpMethod, ...] = EVERY_METHOD, paths: tuple[str, ...] = ()
) -> ScopeRules:
    return ScopeRules.of(
        Scope(
            origins=(ORIGIN,),
            ips=(IPv4Address("10.89.10.210"),),
            paths=paths,
            allow_all_paths=not paths,
            excluded_paths=(),
            methods=methods,
        )
    )


def _finding(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "template-id": "http-missing-security-headers",
        "info": {"name": "Missing Security Headers", "severity": "info"},
        "type": "http",
        "host": "juice-shop",
        "port": "3000",
        "scheme": "http",
        "url": "http://juice-shop:3000",
        "matched-at": "http://juice-shop:3000/",
        "request": "GET / HTTP/1.1\r\nHost: juice-shop:3000\r\n\r\n",
        "response": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>",
    }
    base.update(over)
    return base


def _jsonl(*findings: dict[str, Any]) -> bytes:
    return ("\n".join(json.dumps(finding) for finding in findings) + "\n").encode("utf-8")


def _output(
    report: bytes | None,
    *,
    exit_code: int | None = 0,
    report_listed: bool = True,
    forwarded: int | None = None,
    exchanges: tuple[Exchange, ...] | None = None,
    time_limit_reached: bool = False,
    rules: ScopeRules | None = None,
) -> NucleiOutput:
    return NucleiOutput(
        exit_code=exit_code,
        report=report,
        report_listed=report_listed,
        origin=ORIGIN,
        rules=rules if rules is not None else _rules(),
        forwarded=forwarded,
        exchanges=exchanges,
        time_limit_reached=time_limit_reached,
    )


# --- 真實的輸出 -----------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["nuclei-juice-shop.jsonl", "nuclei-vampi-vuln.jsonl"])
def test_real_golden_output_parses_to_a_clean_success_with_observations(name: str) -> None:
    report = (FIXTURES / name).read_bytes()
    first = json.loads(report.splitlines()[0])
    origin = parse_origin(f"{first['scheme']}://{first['host']}:{first['port']}")
    output = NucleiOutput(
        exit_code=0,
        report=report,
        report_listed=True,
        origin=origin,
        rules=ScopeRules.of(
            Scope(
                origins=(origin,),
                ips=(IPv4Address("10.89.10.210"),),
                paths=(),
                allow_all_paths=True,
                excluded_paths=(),
                methods=EVERY_METHOD,
            )
        ),
        forwarded=None,
        exchanges=None,
    )
    parsed = interpret(output)
    assert parsed.outcome == SUCCEEDED
    assert parsed.parser_version == PARSER_VERSION
    assert parsed.engine_version == NUCLEI_VERSION
    assert parsed.observations  # 真實掃描有發現
    assert all(obs.source_rule in INCLUDE_TEMPLATE_IDS for obs in parsed.observations)
    assert all(obs.path.startswith("/") for obs in parsed.observations)


# --- 退出碼與零告警的語意 -------------------------------------------------------------------


def test_a_nonzero_exit_without_a_report_is_an_engine_failure() -> None:
    parsed = interpret(_output(None, exit_code=1, report_listed=False))
    assert parsed.outcome == ENGINE_FAILED
    assert parsed.observations == ()


def test_a_missing_report_on_a_clean_exit_is_invalid_output() -> None:
    parsed = interpret(_output(None, exit_code=0, report_listed=True))
    assert parsed.outcome == OUTPUT_INVALID
    assert parsed.problem == "report_unreadable"


def test_empty_output_with_forwarded_traffic_is_a_clean_success() -> None:
    # 零告警：成功、沒有觀察（和失敗明確可分）。
    exchanges = (Exchange("GET", "/", authenticated=False, status=200),)
    parsed = interpret(_output(b"", forwarded=1, exchanges=exchanges))
    assert parsed.outcome == SUCCEEDED
    assert parsed.observations == ()
    assert parsed.traffic_verified is True


def test_empty_output_without_any_forwarded_traffic_is_no_target_traffic() -> None:
    parsed = interpret(_output(b"", forwarded=0, exchanges=()))
    assert parsed.outcome == NO_TARGET_TRAFFIC


def test_time_limit_reached_is_timed_out_but_keeps_observations() -> None:
    parsed = interpret(_output(_jsonl(_finding()), forwarded=None, time_limit_reached=True))
    assert parsed.outcome == TIMED_OUT
    assert parsed.time_limit_reached is True
    assert len(parsed.observations) == 1


# --- 壞掉的輸出 -----------------------------------------------------------------------------


def test_a_non_json_line_makes_the_whole_output_invalid() -> None:
    report = _jsonl(_finding()) + b"this is not json\n"
    parsed = interpret(_output(report))
    assert parsed.outcome == OUTPUT_INVALID
    assert parsed.problem == JsonlProblem.NOT_JSONL.value


@pytest.mark.parametrize(
    "finding",
    [
        pytest.param({"info": {"name": "x", "severity": "info"}, "type": "http"}, id="no-id"),
        pytest.param(_finding(type="dns"), id="wrong-type"),
        pytest.param(_finding(info={"severity": "info"}), id="no-name"),
        pytest.param(_finding(info={"name": "x"}), id="no-severity"),
    ],
)
def test_a_line_with_a_bad_shape_is_invalid(finding: dict[str, Any]) -> None:
    assert parse_report(_jsonl(finding)) is JsonlProblem.NOT_JSONL


def test_duplicate_keys_in_a_line_are_rejected() -> None:
    assert parse_report(b'{"type":"http","type":"http"}\n') is JsonlProblem.NOT_JSONL


def test_nan_in_a_line_is_rejected() -> None:
    assert parse_report(b'{"type":"http","x":NaN}\n') is JsonlProblem.NOT_JSONL


def test_a_report_over_the_size_cap_is_too_large() -> None:
    assert parse_report(b"x" * (MAX_REPORT_BYTES + 1)) is JsonlProblem.TOO_LARGE


def test_non_utf8_bytes_are_invalid() -> None:
    assert parse_report(b"\xff\xfe not utf-8\n") is JsonlProblem.NOT_JSONL


def test_floats_such_as_cvss_scores_are_accepted() -> None:
    info = {"name": "x", "severity": "high", "classification": {"cvss-score": 7.5}}
    assert parse_report(_jsonl(_finding(info=info))) != JsonlProblem.NOT_JSONL


# --- guard 的合成 403 與排除 ----------------------------------------------------------------


def test_a_guard_synthetic_403_is_excluded() -> None:
    blocked = _finding(
        response=(
            "HTTP/1.1 403 Forbidden\r\nX-Secscan-Guard: RATE_LIMITED\r\n"
            "Content-Type: text/plain\r\n\r\nblocked by secscan egress guard: RATE_LIMITED\n"
        )
    )
    parsed = interpret(_output(_jsonl(blocked)))
    assert parsed.observations == ()
    assert parsed.excluded.get(Exclusion.GUARD_RESPONSE) == 1


def test_a_real_target_403_is_kept_not_blanket_excluded() -> None:
    # 反例：目標真正回的 403（沒有 X-Secscan-Guard）不能被當成 guard 的合成回應排除。
    forbidden = "HTTP/1.1 403 Forbidden\r\nServer: nginx\r\n\r\n<html>Forbidden</html>"
    real = _finding(response=forbidden)
    parsed = interpret(_output(_jsonl(real)))
    assert len(parsed.observations) == 1
    assert not parsed.excluded


def test_an_out_of_scope_match_is_excluded() -> None:
    other = _finding(**{"matched-at": "http://evil.example:3000/x"})
    parsed = interpret(_output(_jsonl(other)))
    assert parsed.observations == ()
    assert parsed.excluded.get(Exclusion.OUT_OF_SCOPE) == 1


def test_a_method_the_guard_would_deny_is_excluded() -> None:
    post = _finding(request="POST / HTTP/1.1\r\nHost: juice-shop:3000\r\n\r\n")
    parsed = interpret(_output(_jsonl(post), rules=_rules(methods=(HttpMethod.GET,))))
    assert parsed.observations == ()
    assert parsed.excluded.get(Exclusion.GUARD_DENIED) == 1


def test_a_path_not_answered_by_the_target_is_excluded_when_telemetry_exists() -> None:
    finding = _finding(**{"matched-at": "http://juice-shop:3000/missing"})
    exchanges = (Exchange("GET", "/", authenticated=False, status=200),)
    parsed = interpret(_output(_jsonl(finding), forwarded=1, exchanges=exchanges))
    assert parsed.observations == ()
    assert parsed.excluded.get(Exclusion.NOT_ANSWERED) == 1


def test_a_deny_message_body_is_excluded_only_without_telemetry() -> None:
    body = _finding(response="HTTP/1.1 200 OK\r\n\r\nblocked by secscan egress guard: RUN_BLOCKED")
    without = interpret(_output(_jsonl(body)))
    assert without.excluded.get(Exclusion.GUARD_RESPONSE) == 1
    # 有 telemetry 可以核對時，body 是目標控制的內容，不據此排除。
    exchanges = (Exchange("GET", "/", authenticated=False, status=200),)
    with_telemetry = interpret(_output(_jsonl(body), forwarded=1, exchanges=exchanges))
    assert with_telemetry.excluded.get(Exclusion.GUARD_RESPONSE) is None
    assert len(with_telemetry.observations) == 1


# --- 欄位、遮罩、識別 -----------------------------------------------------------------------


def test_extracted_results_are_masked_in_evidence() -> None:
    leaked = _finding(
        **{
            "template-id": "email-extractor",
            "extracted-results": ["Authorization: Bearer supersecrettoken1234567890"],
        }
    )
    [obs] = interpret(_output(_jsonl(leaked))).observations
    assert obs.evidence is not None
    assert REDACTED in obs.evidence
    assert "supersecrettoken1234567890" not in obs.evidence


def test_a_sensitive_query_value_is_masked() -> None:
    finding = _finding(**{"matched-at": "http://juice-shop:3000/cb?token=supersecretvalue99"})
    [obs] = interpret(_output(_jsonl(finding))).observations
    serialised = f"{obs.path}{obs.query}{obs.other_info}"
    assert "supersecretvalue99" not in serialised
    assert REDACTED in serialised


def test_cwe_is_parsed_from_classification() -> None:
    finding = _finding(
        info={"name": "x", "severity": "high", "classification": {"cwe-id": ["CWE-79"]}}
    )
    [obs] = interpret(_output(_jsonl(finding))).observations
    assert obs.cwe_id == 79


@pytest.mark.parametrize(
    ("severity", "label"),
    [("info", "Informational"), ("high", "High"), ("weird", "Unknown")],
)
def test_severity_label_mapping_keeps_the_raw_value(severity: str, label: str) -> None:
    finding = _finding(info={"name": "x", "severity": severity})
    [obs] = interpret(_output(_jsonl(finding))).observations
    assert obs.raw_severity == severity
    assert obs.severity_label == label


def test_method_comes_from_the_request_line() -> None:
    post = _finding(request="POST /x HTTP/1.1\r\nHost: juice-shop:3000\r\n\r\n")
    [obs] = interpret(_output(_jsonl(post))).observations
    assert obs.method == "POST"
    assert obs.parameter is None
    assert obs.parameter_location is ParameterLocation.UNKNOWN


def test_identical_findings_are_deduplicated_and_counted() -> None:
    parsed = interpret(_output(_jsonl(_finding(), _finding())))
    assert len(parsed.observations) == 1
    assert parsed.duplicates == 1


def test_distinct_matchers_on_the_same_url_are_kept() -> None:
    # 同模板、同 URL，但不同 matcher-name 是不同發現，不可被當成重複丟掉（去重鍵含 variant）。
    first = _finding(**{"matcher-name": "missing-csp"})
    second = _finding(**{"matcher-name": "missing-hsts"})
    parsed = interpret(_output(_jsonl(first, second)))
    assert len(parsed.observations) == 2
    assert parsed.duplicates == 0
    assert {obs.rule_variant for obs in parsed.observations} == {"missing-csp", "missing-hsts"}


# --- 不可信輸入的邊界（安全審查）：識別欄位長度、Unicode 斷行、guard 標記偽造 -----------------

# 以 chr() 寫出來、source 維持 ASCII（避免 RUF001）：runtime 才是真正的 NEL／LINE SEPARATOR。
_U0085 = chr(0x85)
_U2028 = chr(0x2028)


def test_a_long_matcher_name_is_truncated_not_rejected() -> None:
    # 簽章模板有 76 字元的 matcher-name：截斷進 VARCHAR(64)、不讓整份失敗或溢位。
    [obs] = interpret(_output(_jsonl(_finding(**{"matcher-name": "x" * 100})))).observations
    assert obs.rule_variant is not None
    assert len(obs.rule_variant) <= 64


def test_a_long_severity_is_truncated() -> None:
    finding = _finding(info={"name": "x", "severity": "s" * 200})
    [obs] = interpret(_output(_jsonl(finding))).observations
    assert 0 < len(obs.raw_severity) <= 32


@pytest.mark.parametrize("template_id", ["", "a b", "x" * 65, "a\x00b", '"quoted"'])
def test_a_malformed_template_id_is_invalid_output(template_id: str) -> None:
    assert parse_report(_jsonl(_finding(**{"template-id": template_id}))) is JsonlProblem.NOT_JSONL


def test_a_raw_unicode_line_separator_does_not_invalidate_the_report() -> None:
    # nuclei 把回應裡的 U+0085 原樣寫進 JSONL：不能用 splitlines() 切行，否則整份被切壞。
    good = json.dumps(_finding())
    body = f"HTTP/1.1 200 OK\r\n\r\nbo{_U0085}dy"
    poisoned = json.dumps(
        _finding(**{"matched-at": f"{ORIGIN}/x", "response": body}), ensure_ascii=False
    )
    parsed = interpret(_output((good + "\n" + poisoned + "\n").encode("utf-8")))
    assert parsed.outcome == SUCCEEDED
    assert len(parsed.observations) == 2


@pytest.mark.parametrize(
    "response",
    [
        # 底線名稱：guard 只剝除精確的 X-Secscan-Guard，目標不能用 X_Secscan_Guard 偽裝。
        "HTTP/1.1 200 OK\r\nX_Secscan_Guard: RATE_LIMITED\r\n\r\nbody",
        # header 值裡藏 U+2028：不可用 splitlines() 切出假的一行。
        f"HTTP/1.1 200 OK\r\nX-Note: a{_U2028}X-Secscan-Guard: RATE_LIMITED\r\n\r\nbody",
        # 值不是 Reason：不是 guard 的合成回應。
        "HTTP/1.1 200 OK\r\nX-Secscan-Guard: not-a-reason\r\n\r\nbody",
    ],
)
def test_a_forged_guard_marker_does_not_hide_a_target_finding(response: str) -> None:
    parsed = interpret(_output(_jsonl(_finding(response=response))))
    assert len(parsed.observations) == 1
    assert not parsed.excluded


# --- fuzz：任何位元組都只產生判定，不丟例外 ------------------------------------------------


@given(st.binary(max_size=512))
def test_any_bytes_only_produce_an_outcome(data: bytes) -> None:
    parsed = interpret(_output(data))
    assert parsed.outcome.status in {RunStatus.SUCCEEDED, RunStatus.FAILED, RunStatus.TIMED_OUT}
