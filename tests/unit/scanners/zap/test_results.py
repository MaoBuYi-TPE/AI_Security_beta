"""ZAP 輸出的判定與觀察（docs/DECISIONS.md §19.2、§19.3、§19.4）；純函式。

以真實的輸出（tests/fixtures/zap/）為主，壞掉的輸出由真實的報告衍生。CLAUDE.md §8：退出碼不等於
漏洞數；零告警、工具失敗、未掃到端點是不同的語意。
"""

import json
from dataclasses import replace
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from secscan.grants.domain.matching import ScopeRules
from secscan.grants.domain.scope import HttpMethod, Scope
from secscan.guard.domain.requests import DENY_MESSAGE
from secscan.guard.domain.telemetry import ForwardedRequest, UpstreamResponse, decode_line
from secscan.scanners.domain.zap.policy import REQUIRED_ADDONS, ZAP_VERSION
from secscan.scanners.domain.zap.report import MAX_REPORT_BYTES
from secscan.scanners.domain.zap.results import (
    MAX_POSITION_LENGTH,
    MAX_TEXT_LENGTH,
    PARSER_VERSION,
    ZapOutput,
    interpret,
)
from secscan.scans.domain.coverage import Exchange
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.domain.observation import Exclusion, ParameterLocation, ParsedRun, RunOutcome
from secscan.security.redaction import REDACTED
from secscan.targets.domain import parse_origin

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "zap"
MANIFEST = json.loads((FIXTURES.parent / "manifest.json").read_text(encoding="utf-8"))
SUMMARY_OK = b"Job report finished, time taken: 00:00:00\nAutomation plan succeeded!\n"
SUMMARY_WARNING = b"Job report finished\nAutomation plan warnings:\n\tsome warning\n"
SUMMARY_ERROR = b"Job report finished\nAutomation plan failures:\n\tsome error\n"
SUMMARY_TIMEOUT = (
    b"Job report finished\nAutomation plan warnings:\n"
    b"\tPlan stopped after reaching maximum duration of 60 second(s)\n"
)
EVERY_METHOD = (HttpMethod.GET, HttpMethod.HEAD, HttpMethod.POST)
OUTPUT_INVALID = RunOutcome(RunStatus.FAILED, RunErrorCode.OUTPUT_INVALID)
SUCCEEDED = RunOutcome(RunStatus.SUCCEEDED)


def _target(scenario: str) -> str:
    [target] = {
        entry["target"] for entry in MANIFEST["fixtures"] if entry.get("scenario") == scenario
    }
    return str(target)


def _exit_code(scenario: str) -> int:
    [code] = {
        entry["exit_code"] for entry in MANIFEST["fixtures"] if entry.get("scenario") == scenario
    }
    return int(code)


def _rules(
    origin: str,
    *,
    excluded: tuple[str, ...] = (),
    paths: tuple[str, ...] = (),
    methods: tuple[HttpMethod, ...] = EVERY_METHOD,
) -> ScopeRules:
    return ScopeRules.of(
        Scope(
            origins=(parse_origin(origin),),
            ips=(IPv4Address("10.89.10.210"),),
            paths=paths,
            allow_all_paths=not paths,
            excluded_paths=excluded,
            methods=methods,
        )
    )


def _exchanges(path: Path) -> tuple[Exchange, ...]:
    records = [decode_line(line) for line in path.read_bytes().splitlines(keepends=True)]
    statuses = {r.sequence: r.status for r in records if isinstance(r, UpstreamResponse)}
    return tuple(
        Exchange(r.method, r.path, r.authenticated, statuses.get(r.sequence))
        for r in records
        if isinstance(r, ForwardedRequest)
    )


def _recorded(scenario: str) -> ZapOutput:
    directory = FIXTURES / scenario
    target = _target(scenario)
    report = directory / "report.json"
    telemetry = directory / "telemetry.jsonl"
    exchanges = _exchanges(telemetry) if telemetry.exists() else None
    return ZapOutput(
        exit_code=_exit_code(scenario),
        report=report.read_bytes() if report.exists() else None,
        report_listed=report.exists(),
        log=(directory / "zap.log").read_bytes(),
        origin=parse_origin(target),
        rules=_rules(target),
        forwarded=len(exchanges) if exchanges is not None else 0,
        exchanges=exchanges,
    )


def _changed(output: ZapOutput, change: Any) -> ZapOutput:
    """真實的報告，改動之後再編碼。"""
    assert output.report is not None
    document = json.loads(output.report)
    change(document)
    return replace(output, report=json.dumps(document).encode())


def _instance(document: dict[str, Any]) -> dict[str, Any]:
    instance: dict[str, Any] = document["site"][0]["alerts"][0]["instances"][0]
    return instance


def _findings(change: Any) -> ParsedRun:
    return interpret(_changed(_recorded("findings"), change))


def _only(document: dict[str, Any]) -> dict[str, Any]:
    """只留下一個 alert、一個 instance，方便檢查欄位。"""
    site = document["site"][0]
    site["alerts"] = site["alerts"][:1]
    site["alerts"][0]["instances"] = site["alerts"][0]["instances"][:1]
    return _instance(document)


def _one(**fields: str) -> ParsedRun:
    return _findings(lambda document: _only(document).update(fields))


# --- 真實的輸出 ---------------------------------------------------------------------------


def test_a_clean_scan_succeeds_with_no_observations() -> None:
    parsed = interpret(_recorded("clean"))

    assert parsed.outcome == SUCCEEDED
    assert parsed.observations == ()
    assert parsed.traffic_verified is True
    assert parsed.parser_version == PARSER_VERSION
    assert parsed.engine_version == ZAP_VERSION


def test_findings_become_observations() -> None:
    parsed = interpret(_recorded("findings"))

    assert parsed.outcome == SUCCEEDED
    assert len(parsed.observations) == 11
    assert sum(parsed.excluded.values()) == 0
    assert dict(parsed.components) == dict(REQUIRED_ADDONS)
    first = parsed.observations[0]
    assert first.source_rule == "10202"
    assert first.rule_variant == "10202"
    assert first.title == "Absence of Anti-CSRF Tokens"
    assert (first.raw_severity, first.raw_confidence) == ("2", "1")
    assert (first.cwe_id, first.wasc_id) == (352, 9)
    assert (first.method, first.path, first.query) == ("GET", "/", None)
    assert first.evidence == '<form action="/login" method="post">'


def test_the_plan_time_limit_is_timed_out_and_keeps_the_observations() -> None:
    parsed = interpret(_recorded("timeout"))

    assert parsed.outcome == RunOutcome(RunStatus.TIMED_OUT, RunErrorCode.ENGINE_TIMEOUT)
    assert parsed.time_limit_reached is True
    assert len(parsed.observations) == 11


def test_a_target_that_never_answered_is_not_a_clean_scan() -> None:
    """每個請求都由 mitmproxy 回 502：ZAP 的告警都是對 proxy 的錯誤頁，不是目標（§19.4）。"""
    parsed = interpret(_recorded("unanswered"))

    assert parsed.outcome == RunOutcome(RunStatus.FAILED, RunErrorCode.NO_TARGET_TRAFFIC)
    assert parsed.observations == ()
    assert parsed.excluded[Exclusion.NOT_ANSWERED] == 9
    assert parsed.engine_warnings == 1


def test_errors_with_a_valid_report_keep_the_reported_failure() -> None:
    parsed = interpret(_recorded("unreachable"))

    assert parsed.outcome == RunOutcome(RunStatus.FAILED, RunErrorCode.ENGINE_REPORTED_ERRORS)
    assert parsed.engine_errors == 1
    assert parsed.engine_version == ZAP_VERSION


def test_an_exit_of_one_without_a_report_is_an_engine_failure() -> None:
    """ZAP 沒有跑到 plan：T14 的交接，JVM 啟動失敗也是退出碼 1。"""
    parsed = interpret(_recorded("engine-error"))

    assert parsed.outcome == RunOutcome(RunStatus.FAILED, RunErrorCode.ENGINE_FAILED)
    assert parsed.engine_version is None


# --- 退出碼與摘要的語意 --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("exit_code", "log", "status", "error_code"),
    [
        (0, SUMMARY_OK, RunStatus.SUCCEEDED, None),
        (2, SUMMARY_WARNING, RunStatus.SUCCEEDED, None),
        (2, SUMMARY_TIMEOUT, RunStatus.TIMED_OUT, RunErrorCode.ENGINE_TIMEOUT),
        (1, SUMMARY_ERROR, RunStatus.FAILED, RunErrorCode.ENGINE_REPORTED_ERRORS),
        # 摘要和退出碼矛盾
        (0, SUMMARY_WARNING, RunStatus.FAILED, RunErrorCode.OUTPUT_INVALID),
        (0, SUMMARY_ERROR, RunStatus.FAILED, RunErrorCode.OUTPUT_INVALID),
        (1, SUMMARY_OK, RunStatus.FAILED, RunErrorCode.OUTPUT_INVALID),
        (1, SUMMARY_WARNING, RunStatus.FAILED, RunErrorCode.OUTPUT_INVALID),
        (2, SUMMARY_OK, RunStatus.FAILED, RunErrorCode.OUTPUT_INVALID),
        (2, SUMMARY_ERROR, RunStatus.FAILED, RunErrorCode.OUTPUT_INVALID),
        # 沒有摘要
        (0, b"no summary\n", RunStatus.FAILED, RunErrorCode.OUTPUT_INVALID),
        (2, b"", RunStatus.FAILED, RunErrorCode.OUTPUT_INVALID),
        # 收集的清單以外的退出碼不會到這裡；到了就是不一致
        (3, SUMMARY_OK, RunStatus.FAILED, RunErrorCode.OUTPUT_INVALID),
        (None, SUMMARY_OK, RunStatus.FAILED, RunErrorCode.OUTPUT_INVALID),
    ],
)
def test_the_exit_code_and_the_summary_decide_the_outcome(
    exit_code: int | None, log: bytes, status: RunStatus, error_code: RunErrorCode | None
) -> None:
    output = replace(_recorded("findings"), exit_code=exit_code, log=log)

    assert interpret(output).outcome == RunOutcome(status, error_code)


def test_observations_are_kept_when_the_engine_reported_errors() -> None:
    """退出碼 1、報告有效：run 是 failed，部分結果仍然入庫（§19.2）。"""
    parsed = interpret(replace(_recorded("findings"), exit_code=1, log=SUMMARY_ERROR))

    assert parsed.outcome.error_code is RunErrorCode.ENGINE_REPORTED_ERRORS
    assert len(parsed.observations) == 11


@pytest.mark.parametrize("exit_code", [0, 2])
def test_a_missing_report_is_invalid_output(exit_code: int) -> None:
    log = SUMMARY_OK if exit_code == 0 else SUMMARY_WARNING
    output = replace(
        _recorded("findings"), exit_code=exit_code, log=log, report=None, report_listed=False
    )

    assert interpret(output).outcome == OUTPUT_INVALID


def test_a_report_that_is_listed_but_unreadable_is_invalid_output() -> None:
    """退出碼 1 不代表沒有報告：有列出、但讀不到（超過上限、hash 不符）不是引擎的失敗。"""
    output = replace(
        _recorded("findings"), exit_code=1, log=SUMMARY_ERROR, report=None, report_listed=True
    )

    parsed = interpret(output)

    assert parsed.outcome == OUTPUT_INVALID
    assert parsed.problem == "report_unreadable"


def test_a_missing_log_is_invalid_output() -> None:
    parsed = interpret(replace(_recorded("findings"), log=None))

    assert parsed.outcome == OUTPUT_INVALID
    assert parsed.problem == "log_unreadable"
    assert parsed.observations == ()


def test_a_contradictory_summary_has_its_own_problem_code() -> None:
    parsed = interpret(replace(_recorded("findings"), exit_code=2, log=SUMMARY_OK))

    assert parsed.problem == "summary_mismatch"


def test_nothing_forwarded_is_not_a_clean_scan() -> None:
    parsed = interpret(replace(_recorded("clean"), forwarded=0, exchanges=None))

    assert parsed.outcome == RunOutcome(RunStatus.FAILED, RunErrorCode.NO_TARGET_TRAFFIC)


def test_observations_without_any_forwarded_request_are_not_kept() -> None:
    parsed = interpret(replace(_recorded("findings"), forwarded=0, exchanges=None))

    assert parsed.outcome.error_code is RunErrorCode.NO_TARGET_TRAFFIC
    assert parsed.observations == ()
    assert parsed.excluded[Exclusion.NOT_ANSWERED] == 11


def test_an_unknown_forwarded_count_does_not_claim_no_traffic() -> None:
    parsed = interpret(replace(_recorded("clean"), forwarded=None, exchanges=None))

    assert parsed.outcome == SUCCEEDED
    assert parsed.traffic_verified is False


def test_errors_take_priority_over_no_traffic() -> None:
    """AF 的錯誤通常就是沒有流量的原因：錯誤碼指向原因（§19.2）。"""
    output = replace(_recorded("clean"), exit_code=1, log=SUMMARY_ERROR, forwarded=0, exchanges=())

    assert interpret(output).outcome.error_code is RunErrorCode.ENGINE_REPORTED_ERRORS


# --- 壞掉的輸出 ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("report", "problem"),
    [
        (b"", "report_not_json"),
        (b"{", "report_not_json"),
        (b" " * (MAX_REPORT_BYTES + 1), "report_too_large"),
        (b'{"@programName": "OTHER", "@version": "2.17.0", "site": []}', "report_program"),
        (b'{"@programName": "ZAP", "@version": "2.16.1", "site": []}', "report_version"),
        (b'{"@programName": "ZAP", "@version": "2.17.0"}', "report_shape"),
    ],
)
def test_a_broken_report_is_invalid_output_with_its_reason(report: bytes, problem: str) -> None:
    parsed = interpret(replace(_recorded("findings"), report=report))

    assert parsed.outcome == OUTPUT_INVALID
    assert parsed.problem == problem
    assert parsed.observations == ()


@given(st.binary(max_size=200), st.binary(max_size=200), st.sampled_from([0, 1, 2, 3, None]))
def test_any_bytes_only_produce_an_outcome(
    report: bytes, log: bytes, exit_code: int | None
) -> None:
    origin = "http://lab-zap:3000"
    output = ZapOutput(
        exit_code=exit_code,
        report=report,
        report_listed=True,
        log=log,
        origin=parse_origin(origin),
        rules=_rules(origin),
        forwarded=None,
        exchanges=None,
    )

    assert interpret(output).outcome == OUTPUT_INVALID


# --- 排除（§19.4）-------------------------------------------------------------------------


def _excluded(parsed: ParsedRun, reason: Exclusion) -> int:
    return parsed.excluded.get(reason, 0)


@pytest.mark.parametrize(
    "uri",
    [
        "http://elsewhere:3000/",
        "https://lab-zap-8a9cbe:3000/",
        "http://lab-zap-8a9cbe:3001/",
        "http://user:pw@lab-zap-8a9cbe:3000/",
        "http://lab-zap-8a9cbe:3000.evil.example/",
        "not a url",
    ],
)
def test_an_instance_on_another_origin_is_out_of_scope(uri: str) -> None:
    parsed = _one(uri=uri)

    assert parsed.observations == ()
    assert _excluded(parsed, Exclusion.OUT_OF_SCOPE) == 1


@pytest.mark.parametrize(
    ("uri", "method"),
    [
        ("/admin", "GET"),
        ("/api/items/%00", "GET"),
        ("/a/{b}", "GET"),
        ("/a?_method=DELETE", "GET"),
        ("/", "DELETE"),
    ],
)
def test_a_request_the_guard_always_denies_is_excluded(uri: str, method: str) -> None:
    origin = _target("findings")
    output = replace(_recorded("findings"), rules=_rules(origin, excluded=("/admin",)))

    def change(document: dict[str, Any]) -> None:
        _only(document).update(uri=f"{origin}{uri}", method=method)

    parsed = interpret(_changed(output, change))

    assert parsed.observations == ()
    assert _excluded(parsed, Exclusion.GUARD_DENIED) == 1


def test_a_path_without_any_upstream_answer_is_excluded() -> None:
    origin = _target("findings")
    parsed = _one(uri=f"{origin}/never-answered")

    assert parsed.observations == ()
    assert _excluded(parsed, Exclusion.NOT_ANSWERED) == 1


def test_the_method_counts_when_matching_the_answers() -> None:
    origin = _target("findings")
    parsed = _one(uri=f"{origin}/", method="POST")

    assert _excluded(parsed, Exclusion.NOT_ANSWERED) == 1


def test_the_query_does_not_count_when_matching_the_answers() -> None:
    """telemetry 的 path 不含 query（§16.3）。"""
    origin = _target("findings")
    parsed = _one(uri=f"{origin}/search?q=<script>")

    assert len(parsed.observations) == 1


@pytest.mark.parametrize("field", ["evidence", "otherinfo"])
def test_a_response_of_the_guard_is_excluded(field: str) -> None:
    parsed = _one(**{field: f"{DENY_MESSAGE}: RATE_LIMITED"})

    assert parsed.observations == ()
    assert _excluded(parsed, Exclusion.GUARD_RESPONSE) == 1


def test_without_telemetry_only_the_answers_cannot_be_checked() -> None:
    origin = _target("findings")
    output = replace(_recorded("findings"), forwarded=None, exchanges=None)

    def change(document: dict[str, Any]) -> None:
        _only(document).update(uri=f"{origin}/never-answered")

    parsed = interpret(_changed(output, change))

    assert parsed.traffic_verified is False
    assert len(parsed.observations) == 1


def test_telemetry_with_more_lines_than_forwarded_cannot_be_trusted() -> None:
    """summary 先寫、行後寫：行數不可能比轉送數多（§16.3）。"""
    recorded = _recorded("findings")

    parsed = interpret(replace(recorded, forwarded=1))

    assert parsed.traffic_verified is False
    assert len(parsed.observations) == 11


def test_a_real_finding_is_not_excluded_by_a_404() -> None:
    """有上游回應就算目標的回應，不看 status。"""
    origin = _target("findings")
    recorded = _recorded("findings")
    exchanges = (*(recorded.exchanges or ()), Exchange("GET", "/x", False, 404))
    output = replace(recorded, exchanges=exchanges, forwarded=len(exchanges))

    def change(document: dict[str, Any]) -> None:
        _only(document).update(uri=f"{origin}/x")

    parsed = interpret(_changed(output, change))

    assert parsed.traffic_verified is True
    assert len(parsed.observations) == 1


def test_an_unknown_forwarded_count_makes_the_telemetry_unverified() -> None:
    """和 coverage 相同的條件：轉送數不明就無法判斷 telemetry 完整。"""
    origin = _target("findings")
    output = replace(_recorded("findings"), forwarded=None)

    def change(document: dict[str, Any]) -> None:
        _only(document).update(uri=f"{origin}/never-answered")

    parsed = interpret(_changed(output, change))

    assert parsed.traffic_verified is False
    assert len(parsed.observations) == 1


# --- 欄位 ---------------------------------------------------------------------------------


def test_the_root_of_the_target_may_have_no_slash() -> None:
    """T03 的真實報告：`http://juice-shop:3000`。"""
    assert _one(uri=_target("findings")).observations[0].path == "/"


def test_a_query_on_the_root_without_a_slash() -> None:
    origin = _target("findings")
    observation = _one(uri=f"{origin}?a=1").observations[0]

    assert (observation.path, observation.query) == ("/", "a=1")


def test_the_default_port_may_be_written_out() -> None:
    origin = "http://lab-target"
    output = replace(
        _recorded("findings"),
        origin=parse_origin(origin),
        rules=_rules(origin),
        forwarded=None,
        exchanges=None,
    )

    def change(document: dict[str, Any]) -> None:
        _only(document).update(uri="http://lab-target:80/page")

    assert interpret(_changed(output, change)).observations[0].path == "/page"


def test_the_fragment_was_never_sent() -> None:
    origin = _target("findings")
    observation = _one(uri=f"{origin}/search#top").observations[0]

    assert (observation.path, observation.query) == ("/search", None)


def test_a_parameter_in_the_query_has_a_location() -> None:
    origin = _target("findings")
    query = _one(uri=f"{origin}/search?q=1&b=2", param="q").observations[0]
    header = _one(uri=f"{origin}/search?q=1", param="x-frame-options").observations[0]
    encoded = _one(uri=f"{origin}/search?%71=1", param="q").observations[0]

    assert (query.parameter, query.parameter_location) == ("q", ParameterLocation.QUERY)
    assert header.parameter_location is ParameterLocation.UNKNOWN
    assert encoded.parameter_location is ParameterLocation.QUERY


def test_empty_fields_are_stored_as_nothing() -> None:
    observation = _one(param="", attack="", evidence="", otherinfo="").observations[0]

    assert observation.parameter is None
    assert observation.attack is None
    assert observation.evidence is None
    assert observation.other_info is None


def test_secrets_in_the_url_are_masked() -> None:
    origin = _target("findings")
    observation = _one(
        uri=f"{origin}/search?token=s3cr3t-value&q=1",
        evidence="s3cr3t-value",
        otherinfo="found s3cr3t-value here",
        attack="s3cr3t-value",
    ).observations[0]

    assert observation.query == f"token={REDACTED}&q=1"
    assert observation.evidence == REDACTED
    assert observation.other_info == f"found {REDACTED} here"
    assert observation.attack == REDACTED


def test_secret_patterns_in_the_text_are_masked() -> None:
    observation = _one(
        evidence="Authorization: Bearer abc.def", attack="password=hunter2"
    ).observations[0]

    assert observation.evidence == f"Authorization: {REDACTED}"
    assert observation.attack == f"password={REDACTED}"


def test_text_that_cannot_be_stored_is_replaced() -> None:
    observation = _one(evidence="nul\x00 lone\ud800 bidi‮").observations[0]

    assert observation.evidence == "nul� lone� bidi�"


def test_long_text_is_truncated_and_counted() -> None:
    parsed = _one(evidence="x" * (MAX_TEXT_LENGTH + 1), otherinfo="y" * (MAX_TEXT_LENGTH + 1))

    observation = parsed.observations[0]
    assert observation.evidence == "x" * MAX_TEXT_LENGTH
    assert parsed.truncated_fields == 2


def test_a_long_position_is_truncated_and_counted() -> None:
    origin = _target("findings")
    parsed = _one(uri=f"{origin}/search?q={'z' * MAX_POSITION_LENGTH}")

    query = parsed.observations[0].query
    assert query is not None
    assert len(query) == MAX_POSITION_LENGTH
    assert parsed.truncated_fields == 1


def test_a_secret_across_the_truncation_point_leaves_nothing() -> None:
    """先遮罩、後截斷：跨過截斷位置的值不會留下一段。"""
    filler = "x" * (MAX_TEXT_LENGTH - 4)
    observation = _one(evidence=f"{filler} password=hunter2").observations[0]

    assert observation.evidence is not None
    assert "hunt" not in observation.evidence


# --- 識別與重複 ---------------------------------------------------------------------------


def test_duplicates_are_counted_and_keep_the_first() -> None:
    def change(document: dict[str, Any]) -> None:
        instance = _only(document)
        alert = document["site"][0]["alerts"][0]
        alert["instances"] = [
            dict(instance, id="1"),
            dict(instance, id="2"),
            dict(instance, id="3"),
        ]

    parsed = _findings(change)

    assert len(parsed.observations) == 1
    assert parsed.duplicates == 2
    assert parsed.observations[0].source_index == 0


def test_the_id_ignores_what_zap_generates_on_each_run() -> None:
    """同一個告警在不同的執行有不同的 instance id：識別不含它。"""
    first = _one(id="111").observations[0]
    second = _one(id="222").observations[0]

    assert first.source_event_id == second.source_event_id


def test_the_id_is_taken_after_masking() -> None:
    first = _one(evidence="Bearer abc.def").observations[0]
    second = _one(evidence="Bearer xyz.uvw").observations[0]

    assert first.source_event_id == second.source_event_id


def test_different_instances_have_different_ids() -> None:
    parsed = interpret(_recorded("findings"))

    assert len({item.source_event_id for item in parsed.observations}) == 11
    assert [item.source_index for item in parsed.observations] == list(range(11))


def test_the_source_index_counts_what_was_excluded() -> None:
    origin = _target("findings")

    def change(document: dict[str, Any]) -> None:
        _instance(document).update(uri=f"{origin}/never-answered")

    parsed = _findings(change)

    assert parsed.observations[0].source_index == 1
