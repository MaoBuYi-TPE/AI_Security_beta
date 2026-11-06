"""fixture 修補對照：逐一核對已命中的案例，未命中及沒有對應規則的案例另列。"""

from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Any

from tests.live.fixture_app.cases import SECURITY_CASES

# app._decorate 套用在每個回應（含 404），不只案例表中的示範路由。
_GLOBAL_PATCHES: Mapping[str, str] = MappingProxyType(
    {
        "csp-header-missing": "T30-FX-05",
        "x-content-type-options-missing": "T30-FX-05",
        "anti-clickjacking-header-missing": "T30-FX-05",
        "nuclei-csp-header-missing": "T30-FX-05",
        "nuclei-x-content-type-options-missing": "T30-FX-05",
        "nuclei-x-frame-options-missing": "T30-FX-05",
        "nuclei-referrer-policy-missing": "T30-FX-05",
        "zap-cors-wildcard-origin": "T30-FX-06",
        "nuclei-cors-arbitrary-origin-with-credentials": "T30-FX-06",
    }
)
# key 為群組、method、字面 route、參數位置、參數名；POST form 的舊 ZAP 觀察位置是 unknown。
_PARAMETER_PATCHES: Mapping[tuple[str, str, str, str, str], str] = MappingProxyType(
    {
        ("zap-sql-injection", "GET", "/search", "query", "q"): "T30-FX-01",
        ("zap-reflected-xss", "GET", "/greet", "query", "name"): "T30-FX-02",
        ("zap-sql-injection", "POST", "/login", "unknown", "username"): "T30-FX-03",
        ("zap-sql-injection", "POST", "/login", "unknown", "password"): "T30-FX-03",
        ("zap-sql-injection", "POST", "/login", "body", "username"): "T30-FX-03",
        ("zap-sql-injection", "POST", "/login", "body", "password"): "T30-FX-03",
        ("zap-external-redirect", "GET", "/go", "query", "next"): "T30-FX-08",
    }
)
_MAPPED_CASES = frozenset((*_GLOBAL_PATCHES.values(), *_PARAMETER_PATCHES.values()))
# 修正後三次有效 live 校準都相同的結構（DECISIONS §27.14）：comparability、是否需要人工確認、
# 是否帶 snapshot 理由。各分類的數量隨工具變異與小預算截斷而變，不寫死。
CALIBRATED_STRUCTURE: Mapping[str, tuple[str, bool, bool]] = MappingProxyType(
    {
        "unchanged": ("comparable", False, False),
        "patched": ("comparable", False, False),
        "partial-comparison": ("different", True, True),
    }
)


def assert_conservative_comparison(
    snapshot: Mapping[str, Any], findings: Sequence[Mapping[str, Any]]
) -> None:
    assert snapshot["algorithm_version"] == 1, "演算法換版須重新審查 live 的證據假設"
    assert snapshot["counts"]["new"] == 0
    assert snapshot["counts"]["not_observed"] == 0
    for finding in findings:
        assert finding["classification"] not in {"new", "not_observed"}
        coverage = finding["evidence"]["other_scan_coverage"]
        if coverage is not None:
            assert all(source["rule_completed"] is False for source in coverage["sources"])


def assert_calibrated_structure(label: str, snapshot: Mapping[str, Any]) -> None:
    assert label in CALIBRATED_STRUCTURE, f"未校準的比較 {label}"
    comparability, manual, has_reasons = CALIBRATED_STRUCTURE[label]
    actual = (
        snapshot["comparability"],
        snapshot["manual_review_required"],
        bool(snapshot["reasons"]),
        snapshot["counts"]["not_comparable"],
    )
    # Live 結束會拆除 DB；訊息帶理由與數量，偏離時仍能從日誌分析。
    assert actual == (comparability, manual, has_reasons, 0), (
        f"{label} 偏離校準的結構：得到 {actual}；"
        f"reasons={snapshot['reasons']} counts={snapshot['counts']}"
    )


def _case_id(finding: Mapping[str, Any]) -> str | None:
    location = finding["location"]
    group = finding["rule_group"]
    if location["parameter_name"] is None and group in _GLOBAL_PATCHES:
        return _GLOBAL_PATCHES[group]
    return _PARAMETER_PATCHES.get(
        (
            group,
            location["method"],
            location["route"],
            location["parameter_location"],
            location["parameter_name"],
        )
    )


def check_patched_cases(
    baseline: Sequence[Mapping[str, Any]], comparison: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    matched = tuple((item, _case_id(item)) for item in baseline)
    checks = {item["finding_id"]: item for item in comparison}
    assert any(case_id is not None for _, case_id in matched), "baseline 沒有命中可驗證的修補案例"
    for finding, case_id in matched:
        if case_id is None:
            continue
        finding_id = finding["id"]
        assert finding_id in checks, f"比較缺少修補案例 {case_id}: {finding_id}"
        assert checks[finding_id]["classification"] in {"not_observed", "inconclusive"}, (
            f"修補案例 {case_id}: {finding['rule_group']} {finding['location']} "
            f"得到 {checks[finding_id]['classification']}"
        )
    cases = []
    for case in SECURITY_CASES:
        ids = sorted(item["id"] for item, case_id in matched if case_id == case.case_id)
        status = "checked" if ids else "baseline_not_observed"
        if case.case_id not in _MAPPED_CASES:
            status = "no_automatic_mapping"
        cases.append({"case_id": case.case_id, "status": status, "finding_ids": ids})
    return {
        "cases": cases,
        "unmapped_finding_ids": sorted(item["id"] for item, case_id in matched if case_id is None),
        "notice": "未命中與未對應的案例不算驗證通過；not_observed 不等於已修補。",
    }
