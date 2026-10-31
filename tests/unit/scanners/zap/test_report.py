"""traditional-json 報告的嚴格解析（docs/DECISIONS.md §19.3）。

輸入是 ZAP 寫出的不可信資料：真實的報告（T03 與 T15 錄製）都要接受；由真實報告衍生的每一種壞掉的
輸出都只會得到問題代碼，不會丟例外。壞掉的輸出在測試中產生，不存成檔案。
"""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from secscan.scanners.domain.zap.policy import ZAP_VERSION
from secscan.scanners.domain.zap.report import (
    MAX_ALERTS,
    MAX_INSTANCES,
    MAX_REPORT_BYTES,
    MAX_SITES,
    ReportProblem,
    ZapReport,
    parse_report,
)

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "zap"
FINDINGS = FIXTURES / "findings" / "report.json"


def _document() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(FINDINGS.read_bytes())
    return document


def _encoded(document: object) -> bytes:
    return json.dumps(document).encode()


def _parsed(document: object) -> ZapReport | ReportProblem:
    return parse_report(_encoded(document))


def _alert(document: dict[str, Any]) -> dict[str, Any]:
    alert: dict[str, Any] = document["site"][0]["alerts"][0]
    return alert


def _instance(document: dict[str, Any]) -> dict[str, Any]:
    instance: dict[str, Any] = _alert(document)["instances"][0]
    return instance


@pytest.mark.parametrize(
    ("path", "alerts", "instances"),
    [
        ("findings/report.json", 4, 11),
        ("timeout/report.json", 4, 11),
        ("unanswered/report.json", 3, 9),
        ("clean/report.json", 0, 0),
        ("unreachable/report.json", 0, 0),
        ("zap-juice-shop.json", 4, 11),
        ("zap-vampi-vuln.json", 3, 11),
    ],
)
def test_real_reports_are_accepted(path: str, alerts: int, instances: int) -> None:
    report = parse_report((FIXTURES / path).read_bytes())

    assert isinstance(report, ZapReport)
    assert report.version == ZAP_VERSION
    assert len(report.alerts) == alerts
    assert sum(len(alert.instances) for alert in report.alerts) == instances


def test_the_fields_of_an_alert() -> None:
    report = parse_report(FINDINGS.read_bytes())

    assert isinstance(report, ZapReport)
    [csrf, *_] = report.alerts
    assert (csrf.plugin_id, csrf.alert_ref, csrf.name) == (
        "10202",
        "10202",
        "Absence of Anti-CSRF Tokens",
    )
    assert (csrf.risk, csrf.confidence, csrf.cwe_id, csrf.wasc_id) == ("2", "1", 352, 9)
    [instance] = csrf.instances
    assert instance.method == "GET"
    assert instance.uri.endswith(":3000/")
    assert instance.evidence == '<form action="/login" method="post">'
    assert instance.other_info.startswith("No known Anti-CSRF token")


def test_cwe_and_wasc_without_a_value_stay_empty() -> None:
    """ZAP 以 -1、0 表示沒有對應：不捏造（CLAUDE.md §10）。"""
    document = _document()
    _alert(document).update(cweid="-1", wascid="0")

    report = _parsed(document)

    assert isinstance(report, ZapReport)
    assert (report.alerts[0].cwe_id, report.alerts[0].wasc_id) == (None, None)


def test_unknown_fields_are_ignored() -> None:
    """範本更新多出來的欄位不影響解析（§4.2 的未知欄位）。"""
    document = _document()
    document["future"] = {"x": [1]}
    document["site"][0]["future"] = 1
    _alert(document)["future"] = None
    _instance(document)["future"] = "y"

    assert isinstance(_parsed(document), ZapReport)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"   ",
        b"\xff\xfe{}",
        b"not json",
        FINDINGS.read_bytes()[:2000],
        b'{"@version": "2.17.0", "@version": "2.17.0"}',
        b'{"a": NaN}',
        b'{"a": Infinity}',
        b'{"a": 1.5}',
        b'{"a": 1e3}',
        b'{"a": ' + b"1" * 5000 + b"}",
        b"[" * 200_000,
        b'{"a":' * 200_000,
    ],
    ids=lambda raw: repr(raw[:16]),
)
def test_output_that_is_not_strict_json_is_rejected(raw: bytes) -> None:
    assert parse_report(raw) is ReportProblem.NOT_JSON


def test_a_duplicate_key_inside_an_alert_is_rejected() -> None:
    """重複的 key 會讓不同的 parser 讀到不同的值。"""
    raw = FINDINGS.read_bytes().replace(b'"riskcode": "2"', b'"riskcode": "2","riskcode": "0"', 1)

    assert parse_report(raw) is ReportProblem.NOT_JSON


def test_a_report_over_the_limit_is_rejected_before_parsing() -> None:
    assert parse_report(b" " * (MAX_REPORT_BYTES + 1)) is ReportProblem.TOO_LARGE


@pytest.mark.parametrize("value", ["OWASP ZAP", "", 1, None])
def test_another_program_is_rejected(value: object) -> None:
    document = _document()
    document["@programName"] = value

    assert _parsed(document) is (
        ReportProblem.PROGRAM if isinstance(value, str) else ReportProblem.SHAPE
    )


@pytest.mark.parametrize("value", ["2.16.1", "2.17.0-rc1", ""])
def test_a_version_that_is_not_pinned_is_rejected(value: str) -> None:
    document = _document()
    document["@version"] = value

    assert _parsed(document) is ReportProblem.VERSION


def _without(key: str, select: Callable[[dict[str, Any]], dict[str, Any]]) -> dict[str, Any]:
    document = _document()
    del select(document)[key]
    return document


def _site(document: dict[str, Any]) -> dict[str, Any]:
    site: dict[str, Any] = document["site"][0]
    return site


@pytest.mark.parametrize(
    ("key", "select"),
    [
        ("@programName", lambda document: document),
        ("@version", lambda document: document),
        ("site", lambda document: document),
        ("alerts", _site),
        ("pluginid", _alert),
        ("alertRef", _alert),
        ("name", _alert),
        ("riskcode", _alert),
        ("confidence", _alert),
        ("cweid", _alert),
        ("wascid", _alert),
        ("instances", _alert),
        ("uri", _instance),
        ("method", _instance),
        ("param", _instance),
        ("attack", _instance),
        ("evidence", _instance),
        ("otherinfo", _instance),
    ],
)
def test_a_missing_required_key_rejects_the_report(
    key: str, select: Callable[[dict[str, Any]], dict[str, Any]]
) -> None:
    assert _parsed(_without(key, select)) is ReportProblem.SHAPE


@pytest.mark.parametrize(
    ("change", "select"),
    [
        ({"site": {}}, lambda document: document),
        ({"alerts": None}, _site),
        ({"pluginid": 10202}, _alert),
        ({"pluginid": "abc"}, _alert),
        ({"alertRef": "10202-x"}, _alert),
        ({"alertRef": "10202-1-2"}, _alert),
        ({"name": ""}, _alert),
        # 全空白的標題存不進 DB（title_not_blank）：要走判定，不能讓 worker 崩潰
        ({"name": " \t\n"}, _alert),
        ({"name": 1}, _alert),
        ({"riskcode": "4"}, _alert),
        ({"riskcode": 2}, _alert),
        ({"riskcode": "-1"}, _alert),
        ({"confidence": "5"}, _alert),
        ({"cweid": "x"}, _alert),
        ({"cweid": 352}, _alert),
        ({"wascid": "1.5"}, _alert),
        ({"instances": {}}, _alert),
        ({"method": "BOGUS"}, _instance),
        ({"method": ""}, _instance),
        ({"method": "get"}, _instance),
        ({"uri": 1}, _instance),
        ({"uri": ""}, _instance),
        ({"param": None}, _instance),
        ({"evidence": 5}, _instance),
    ],
)
def test_a_field_of_the_wrong_shape_rejects_the_report(
    change: dict[str, Any], select: Callable[[dict[str, Any]], dict[str, Any]]
) -> None:
    document = _document()
    select(document).update(change)

    assert _parsed(document) is ReportProblem.SHAPE


@pytest.mark.parametrize(
    "document",
    [
        [],
        "report",
        {"@programName": "ZAP", "@version": ZAP_VERSION, "site": ["x"]},
        {"@programName": "ZAP", "@version": ZAP_VERSION, "site": [{"alerts": ["x"]}]},
        {
            "@programName": "ZAP",
            "@version": ZAP_VERSION,
            "site": [{"alerts": [{"instances": ["x"]}]}],
        },
    ],
)
def test_containers_of_the_wrong_type_reject_the_report(document: object) -> None:
    assert _parsed(document) is ReportProblem.SHAPE


def test_too_many_sites_are_rejected() -> None:
    document = _document()
    document["site"] = [{"alerts": []}] * (MAX_SITES + 1)

    assert _parsed(document) is ReportProblem.LIMITS


def test_too_many_alerts_are_rejected() -> None:
    document = _document()
    alert = dict(_alert(document), instances=[])
    _site(document)["alerts"] = [alert] * (MAX_ALERTS + 1)

    assert _parsed(document) is ReportProblem.LIMITS


def test_too_many_instances_are_rejected() -> None:
    document = _document()
    instance = dict(_instance(document), evidence="", otherinfo="")
    _alert(document)["instances"] = [instance] * (MAX_INSTANCES + 1)

    assert _parsed(document) is ReportProblem.LIMITS


def test_the_instance_limit_counts_every_alert() -> None:
    document = _document()
    instance = dict(_instance(document), evidence="", otherinfo="")
    alert = dict(_alert(document), instances=[instance] * (MAX_INSTANCES // 2 + 1))
    _site(document)["alerts"] = [alert, alert]

    assert _parsed(document) is ReportProblem.LIMITS


@given(st.binary(max_size=256))
def test_any_bytes_only_produce_a_report_or_a_problem(raw: bytes) -> None:
    assert isinstance(parse_report(raw), ZapReport | ReportProblem)


JSON_VALUES = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=8),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=8), children, max_size=4)
    ),
    max_leaves=12,
)


@given(JSON_VALUES)
def test_any_json_only_produces_a_report_or_a_problem(value: object) -> None:
    assert isinstance(_parsed(value), ZapReport | ReportProblem)


@given(st.sampled_from(["@programName", "@version", "site"]), JSON_VALUES)
def test_any_value_in_a_real_report_only_produces_a_report_or_a_problem(
    key: str, value: object
) -> None:
    document = _document()
    document[key] = value

    assert isinstance(_parsed(document), ZapReport | ReportProblem)
