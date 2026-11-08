"""T21 live：逐案的人工複測與 triage 的請求（docs/DECISIONS.md §28；計畫 §6.3）。

人工複測在修補版還在執行時，以 lab_call 的輔助容器（lab 網路、唯讀、cap-drop ALL、不經 guard）
送出；每個案例先斷言修補後的行為成立，才把請求與回應的摘錄當成證據。摘錄照實組成：請求依實際
送出的 method、path 與 Host；回應用實際的狀態碼與 body（lab_call 不回傳 header 與 reason phrase，
不補造）。Live 中的「操作者」是測試本身：它驗證流程、一致性檢查與標示，不證明人工聲明的真實性。
"""

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any
from urllib.parse import urlencode

from pydantic import TypeAdapter

from secscan.comparisons.domain.classification import Classification, ComparisonFacts
from secscan.comparisons.domain.comparability import Comparability
from secscan.findings.domain.triage import ResolutionBasis
from secscan.triage.domain.evidence import CitedComparison, ComparisonRow, evidence_problems
from tests.live.fixture_app.cases import SECURITY_CASES, Case

_FACTS = TypeAdapter(ComparisonFacts)
RESPONSE_EXCERPT_LIMIT = 2000


@dataclass(frozen=True)
class Retest:
    """一個案例的複測請求與修補後應有的行為。"""

    case_id: str
    method: str
    path: str
    accepts: Callable[[int, str], bool]


def _no_server_error(status: int, _: str) -> bool:
    return status == 200


def _escaped(status: int, body: str) -> bool:
    return status == 200 and "<b>x</b>" not in body and "&lt;b&gt;x&lt;/b&gt;" in body


RETESTS: Mapping[str, Retest] = {
    "T30-FX-01": Retest("T30-FX-01", "GET", "/search?q=apple%27", _no_server_error),
    "T30-FX-02": Retest("T30-FX-02", "GET", "/greet?name=%3Cb%3Ex%3C%2Fb%3E", _escaped),
}


@dataclass(frozen=True)
class Observed:
    """lab_call 的實際結果與送出的時間（DB 的時間軸上晚於上一次觀察到它的 scan）。"""

    case_id: str
    method: str
    path: str
    status: int
    body: str
    performed_at: datetime


def case(case_id: str) -> Case:
    return next(item for item in SECURITY_CASES if item.case_id == case_id)


def passes(observed: Observed) -> bool:
    return RETESTS[observed.case_id].accepts(observed.status, observed.body)


def attestation(observed: Observed, host: str, port: int, role: str) -> dict[str, Any]:
    """人工複測聲明（請求與回應照實組成；平台只做一致性檢查）。"""
    item = case(observed.case_id)
    request = f"{observed.method} {observed.path} HTTP/1.1\nHost: {host}:{port}\nAccept: */*\n"
    response = f"HTTP/1.1 {observed.status}\n\n{observed.body[:RESPONSE_EXCERPT_LIMIT]}"
    return {
        "method": "manual_retest",
        "performed_at": observed.performed_at.isoformat(),
        "performed_by": "T21 live test",
        "procedure": f"{item.verification}；修補後預期：{item.patched_behavior}",
        "result": "not_reproduced",
        "auth_role": role,
        "request_excerpt": request,
        "response_excerpt": response,
    }


# 這些原因代表聲明本身對錯了位置或身分：反例必須只因平台條件被拒絕，不能因為這些原因被拒絕。
LOCATION_PROBLEMS = frozenset(
    {"request_line_mismatch", "host_mismatch", "parameter_missing", "role_mismatch"}
)
_TEMPLATE = re.compile(r"\{[^/{}]+\}")


def located_attestation(
    finding: Mapping[str, Any], observed: Observed, host: str, port: int
) -> dict[str, Any]:
    """對準 finding 自己的 method、route、參數與身分的聲明（反例用：拒絕只能來自平台條件）。"""
    location = finding["location"]
    path = _TEMPLATE.sub("1", location["route"])
    if location["parameter_name"]:
        path += "?" + urlencode({location["parameter_name"]: "1"})
    located = replace(observed, method=location["method"], path=path)
    return attestation(located, host, port, finding["auth_role"])


def rejection_codes(response: Mapping[str, Any]) -> set[str]:
    """422 RESOLUTION_EVIDENCE_INSUFFICIENT 訊息中列出的固定原因代碼。"""
    _, _, listed = response["error"]["message"].partition("：")
    return {code.strip() for code in listed.split(",") if code.strip()}


def assert_rejected_for(response: Mapping[str, Any], expected: Iterable[str]) -> set[str]:
    """拒絕原因必須包含每個預期的平台條件，而且不含位置或身分不符（否則反例沒有鑑別力）。"""
    assert response["error"]["code"] == "RESOLUTION_EVIDENCE_INSUFFICIENT", response
    codes = rejection_codes(response)
    wanted = set(expected)
    assert wanted, "反例必須至少有一個預期的平台條件"
    assert wanted <= codes, (sorted(wanted - codes), sorted(codes))
    assert not codes & LOCATION_PROBLEMS, sorted(codes & LOCATION_PROBLEMS)
    return codes


def platform_problems(snapshot: Mapping[str, Any], row: Mapping[str, Any] | None) -> list[str]:
    """以平台相同的規則判斷人工複測這一軌的平台條件（不含新鮮度與人工聲明）。"""
    cited = CitedComparison(
        int(snapshot["algorithm_version"]),
        Comparability(snapshot["comparability"]),
        (
            ComparisonRow(
                Classification(row["classification"]),
                tuple(row["reasons"]),
                bool(row["manual_review_required"]),
                _FACTS.validate_python(row["evidence"]),
            )
            if row is not None
            else None
        ),
    )
    return [
        problem.value
        for problem in evidence_problems(ResolutionBasis.MANUAL_RETEST, cited, observed_after=False)
    ]


def resolve_body(
    version: int, comparison_id: str, body: dict[str, Any] | None, *, basis: str = "manual_retest"
) -> dict[str, Any]:
    request: dict[str, Any] = {
        "expected_version": version,
        "lifecycle_state": "resolved",
        "reason": "T21 live：依人工複測判定",
        "basis": basis,
        "comparison_id": comparison_id,
    }
    if body is not None:
        request["attestation"] = body
    return request


def confirm_body(version: int) -> dict[str, Any]:
    return {
        "expected_version": version,
        "triage_state": "confirmed",
        "reason": "T21 live：fixture 的已知弱點",
    }
