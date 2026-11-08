"""平台 API 的 JSON → 不可變紀錄（BENCH-04）。

- 只經公開的 API 取得資料（GET）：Live 傳入 tests/live/support.Api，integration 測試傳入
  TestClient 的轉接，兩邊走同一段程式。
- 缺欄位、型別不符、分頁不一致、還沒結束的 scan、fake 引擎的 scan（fixture=true）一律失敗
  （fail closed），不以預設值補上。
- 回應是不可信的資料：只取需要的欄位，不執行、不解讀其中的文字。
"""

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from benchmarks.models import (
    TERMINAL_SCAN_STATUSES,
    ComparisonItem,
    ComparisonRecord,
    EngineCap,
    FindingRecord,
    RunRecord,
    ScanRecord,
    Signature,
)

PAGE_LIMIT = 100
MAX_PAGES = 1_000

# path → 回應的 body（envelope：success、data、error、meta）；狀態碼不是 2xx 時拋例外。
Fetch = Callable[[str], Mapping[str, Any]]


class CollectError(ValueError):
    """API 的回應不符合預期的結構；訊息只說明欄位，不回顯內容。"""


def collect_scan(fetch: Fetch, scan_id: str) -> tuple[dict[str, Any], list[dict[str, Any]], int]:
    """一個已結束的 scan 的原始 JSON：scan、這個 scan 的 finding（全部分頁）與觀察數。"""
    scan = _object(_data(fetch(f"/scans/{scan_id}")), "scan")
    findings = pages(fetch, f"/scans/{scan_id}/findings")
    meta = _object(fetch(f"/scans/{scan_id}/observations?page=1&limit=1").get("meta"), "meta")
    return scan, findings, _int(meta, "total")


def collect_comparison(
    fetch: Fetch, comparison_id: str
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    snapshot = _object(_data(fetch(f"/scan-comparisons/{comparison_id}")), "comparison")
    return snapshot, pages(fetch, f"/scan-comparisons/{comparison_id}/findings")


def pages(fetch: Fetch, path: str) -> list[dict[str, Any]]:
    """依 page/limit 取完所有項目；總數改變、項目重複或頁數過多都失敗。"""
    separator = "&" if "?" in path else "?"
    items: list[dict[str, Any]] = []
    total: int | None = None
    for page in range(1, MAX_PAGES + 1):
        body = fetch(f"{path}{separator}page={page}&limit={PAGE_LIMIT}")
        data = body.get("data")
        if not isinstance(data, list):
            raise CollectError("清單的 data 必須是陣列")
        meta = _object(body.get("meta"), "meta")
        if total is None:
            total = _int(meta, "total")
        elif _int(meta, "total") != total:
            raise CollectError("分頁期間總數改變了")
        items.extend(_object(item, "item") for item in data)
        if len(items) >= total or not data:
            break
    else:
        raise CollectError("頁數超過上限")
    ids = [_str(item, "id") if "id" in item else _str(item, "finding_id") for item in items]
    if len(items) != total or len(set(ids)) != len(ids):
        raise CollectError("分頁的項目數與總數不符或有重複")
    return items


def normalize_scan(
    scan: Mapping[str, Any], findings: Sequence[Mapping[str, Any]], observation_count: int
) -> ScanRecord:
    status = _str(scan, "status")
    if status not in TERMINAL_SCAN_STATUSES:
        raise CollectError("scan 還沒結束")
    if _bool(scan, "fixture"):
        raise CollectError("fake 引擎的 scan（fixture）不能用於實驗")
    budget = _object(scan.get("budget"), "budget")
    coverage = _object(scan.get("coverage"), "coverage")
    engines = scan.get("engines")
    if not isinstance(engines, list) or not engines:
        raise CollectError("engines 必須是非空的陣列")
    if isinstance(observation_count, bool) or observation_count < 0:
        raise CollectError("觀察數必須是非負整數")
    return ScanRecord(
        id=_str(scan, "id"),
        status=status,
        fixture=False,
        profile=_str(scan, "profile"),
        auth_role=_str(scan, "auth_role"),
        requests_per_second=_int(budget, "requests_per_second"),
        max_requests=_int(budget, "max_requests"),
        max_duration_seconds=_int(budget, "max_duration_seconds"),
        runs=tuple(normalize_run(_object(run, "engine run")) for run in engines),
        findings=tuple(normalize_finding(item) for item in findings),
        observation_count=observation_count,
        coverage_measured=_bool(coverage, "coverage_measured"),
        eligible_operations=_optional_int(coverage, "eligible_operations"),
        observed_operations=_optional_int(coverage, "observed_operations"),
        created_at=_str(scan, "created_at"),
        finished_at=_optional_str(scan, "finished_at"),
    )


def normalize_run(run: Mapping[str, Any]) -> RunRecord:
    usage = _object(run.get("usage"), "usage")
    budget = run.get("budget")
    cap = None
    if budget is not None:
        cap_fields = _object(budget, "budget")
        cap = EngineCap(_int(cap_fields, "max_requests"), _int(cap_fields, "max_duration_seconds"))
    result = run.get("result")
    observations = limit = exhausted = None
    if result is not None:
        details = _object(result, "result")
        observations = _int(details, "observation_count")
        limit = _bool(details, "time_limit_reached")
        traffic = details.get("guard_traffic")
        if traffic is not None:
            exhausted = _bool(_object(traffic, "guard_traffic"), "exhausted")
    return RunRecord(
        engine=_str(run, "engine"),
        sequence=_int(run, "sequence"),
        status=_str(run, "status"),
        error_code=_optional_str(run, "error_code"),
        plan_hash=_optional_str(run, "plan_hash"),
        cap=cap,
        requests_allotted=_optional_int(usage, "requests_allotted"),
        seconds_allotted=_optional_int(usage, "duration_allotted_seconds"),
        requests_sent=_optional_int(usage, "requests_sent"),
        requests_denied=_optional_int(usage, "requests_denied"),
        traffic_seconds=_optional_int(usage, "traffic_duration_seconds"),
        observation_count=observations,
        time_limit_reached=limit,
        guard_exhausted=exhausted,
    )


def normalize_finding(finding: Mapping[str, Any]) -> FindingRecord:
    location = _object(finding.get("location"), "location")
    sources = finding.get("sources")
    if not isinstance(sources, list) or not sources:
        raise CollectError("finding 的 sources 必須是非空的陣列")
    parsed = [_object(source, "source") for source in sources]
    return FindingRecord(
        id=_str(finding, "id"),
        kind=_str(finding, "kind"),
        signature=Signature(
            rule_group=_str(finding, "rule_group"),
            method=_str(location, "method"),
            route=_str(location, "route"),
            parameter_location=_optional_str(location, "parameter_location"),
            parameter_name=_optional_str(location, "parameter_name"),
        ),
        engines=tuple(sorted({_str(source, "engine") for source in parsed})),
        observations=sum(_int(source, "observations") for source in parsed),
    )


def normalize_comparison(
    snapshot: Mapping[str, Any], findings: Sequence[Mapping[str, Any]]
) -> ComparisonRecord:
    return ComparisonRecord(
        id=_str(snapshot, "id"),
        baseline_scan_id=_str(snapshot, "baseline_scan_id"),
        current_scan_id=_str(snapshot, "current_scan_id"),
        comparability=_str(snapshot, "comparability"),
        manual_review_required=_bool(snapshot, "manual_review_required"),
        items=tuple(
            ComparisonItem(
                finding_id=_str(item, "finding_id"),
                classification=_str(item, "classification"),
                manual_review_required=_bool(item, "manual_review_required"),
            )
            for item in findings
        ),
    )


def _data(body: Mapping[str, Any]) -> Any:
    if body.get("success") is not True:
        raise CollectError("API 回應不是成功的 envelope")
    return body.get("data")


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CollectError(f"{label} 必須是物件")
    return value


def _str(container: Mapping[str, Any], key: str) -> str:
    value = container.get(key)
    if not isinstance(value, str):
        raise CollectError(f"{key} 必須是字串")
    return value


def _optional_str(container: Mapping[str, Any], key: str) -> str | None:
    if key not in container:
        raise CollectError(f"缺少 {key}")
    value = container[key]
    if value is not None and not isinstance(value, str):
        raise CollectError(f"{key} 必須是字串或 null")
    return value


def _int(container: Mapping[str, Any], key: str) -> int:
    value = container.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CollectError(f"{key} 必須是非負整數")
    return value


def _optional_int(container: Mapping[str, Any], key: str) -> int | None:
    if key not in container:
        raise CollectError(f"缺少 {key}")
    if container[key] is None:
        return None
    return _int(container, key)


def _bool(container: Mapping[str, Any], key: str) -> bool:
    value = container.get(key)
    if not isinstance(value, bool):
        raise CollectError(f"{key} 必須是布林值")
    return value
