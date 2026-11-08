"""API 的 JSON → 紀錄（BENCH-04 的單元部分；integration 在 tests/integration）。"""

from collections.abc import Mapping
from typing import Any
from uuid import uuid4

import pytest

from benchmarks.collect import (
    CollectError,
    collect_comparison,
    collect_scan,
    normalize_comparison,
    normalize_scan,
    pages,
)
from benchmarks.models import EngineCap, Signature
from secscan.scans.domain.lifecycle import ScanStatus
from tests.unit.bench.samples import (
    comparison_json,
    finding_json,
    nuclei_run,
    scan_json,
    zap_run,
)


def test_a_scan_is_normalized_with_caps_allotments_and_guard_counts() -> None:
    findings = [
        finding_json("sqli", route="/search", parameter_location="query", parameter_name="q")
    ]

    record = normalize_scan(scan_json(), findings, observation_count=14)

    zap, nuclei = record.runs
    assert (zap.engine, zap.cap, zap.requests_allotted, zap.seconds_allotted) == (
        "zap",
        EngineCap(760, 380),
        760,
        380,
    )
    assert (zap.requests_sent, zap.requests_denied, zap.traffic_seconds) == (700, 4, 375)
    assert (zap.observation_count, zap.time_limit_reached, zap.guard_exhausted) == (12, True, False)
    assert (nuclei.status, nuclei.error_code, nuclei.observation_count) == (
        "timed_out",
        "TIME_LIMIT_EXCEEDED",
        None,
    )
    assert record.findings[0].signature == Signature("sqli", "GET", "/search", "query", "q")
    assert (record.observation_count, record.profile, record.auth_role) == (
        14,
        "web_active_lab",
        "anonymous",
    )
    assert (record.max_requests, record.coverage_measured, record.eligible_operations) == (
        1_200,
        False,
        None,
    )


def test_engines_and_observations_of_a_finding_cover_this_scan_only() -> None:
    finding = finding_json("security-headers", engines=("zap", "nuclei"))

    [record] = normalize_scan(scan_json(), [finding], observation_count=4).findings

    assert (record.engines, record.observations, record.kind) == (("nuclei", "zap"), 4, "security")


def test_an_uncapped_run_has_no_cap() -> None:
    scan_id = uuid4()
    scan = scan_json(
        scan_id=scan_id, runs=(zap_run(scan_id, capped=False), nuclei_run(scan_id, capped=False))
    )

    assert [run.cap for run in normalize_scan(scan, [], 0).runs] == [None, None]


@pytest.mark.parametrize(
    "status", [ScanStatus.QUEUED, ScanStatus.RUNNING, ScanStatus.NORMALIZING, ScanStatus.CANCELLING]
)
def test_an_unfinished_scan_is_rejected(status: ScanStatus) -> None:
    scan = scan_json(status=status, finished_at=None)

    with pytest.raises(CollectError, match="還沒結束"):
        normalize_scan(scan, [], 0)


def test_a_fixture_scan_is_rejected() -> None:
    scan = {**scan_json(), "fixture": True}

    with pytest.raises(CollectError, match="fixture"):
        normalize_scan(scan, [], 0)


def _without(document: dict[str, Any], *path: str) -> dict[str, Any]:
    copy: Any = document
    for key in path[:-1]:
        copy = copy[key] if isinstance(copy, dict) else copy[int(key)]
    del copy[path[-1]]
    return document


@pytest.mark.parametrize(
    "path",
    [
        ("status",),
        ("budget",),
        ("budget", "max_requests"),
        ("coverage", "coverage_measured"),
        ("engines", "0", "usage"),
        ("engines", "0", "usage", "requests_sent"),
        ("engines", "1", "budget", "max_requests"),
        ("finished_at",),
    ],
)
def test_a_missing_field_fails_instead_of_defaulting(path: tuple[str, ...]) -> None:
    with pytest.raises(CollectError):
        normalize_scan(_without(scan_json(), *path), [], 0)


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        (lambda s: s["engines"][0]["usage"].update(requests_sent=True), "requests_sent"),
        (lambda s: s["engines"][0]["usage"].update(requests_sent=-1), "requests_sent"),
        (lambda s: s["engines"][0]["usage"].update(requests_sent="7"), "requests_sent"),
        (lambda s: s.update(engines=[]), "engines"),
        (lambda s: s.update(fixture="false"), "fixture"),
        (lambda s: s["engines"][0]["result"].update(guard_traffic="x"), "guard_traffic"),
        (lambda s: s.update(finished_at=7), "finished_at"),
    ],
)
def test_wrong_types_fail(change: Any, problem: str) -> None:
    scan = scan_json()
    change(scan)

    with pytest.raises(CollectError, match=problem):
        normalize_scan(scan, [], 0)


def test_a_finding_without_sources_fails() -> None:
    finding = {**finding_json("sqli"), "sources": []}

    with pytest.raises(CollectError, match="sources"):
        normalize_scan(scan_json(), [finding], 1)


def test_a_negative_observation_count_fails() -> None:
    with pytest.raises(CollectError, match="觀察數"):
        normalize_scan(scan_json(), [], -1)


def test_a_comparison_is_normalized() -> None:
    first, second = str(uuid4()), str(uuid4())
    snapshot, items = comparison_json(
        str(uuid4()), str(uuid4()), [(first, "persistent"), (second, "inconclusive")]
    )

    record = normalize_comparison(snapshot, items)

    assert record.comparability == "comparable"
    assert [(item.finding_id, item.classification) for item in record.items] == [
        (first, "persistent"),
        (second, "inconclusive"),
    ]


# --- 經 fetch 取得（分頁）----------------------------------------------------------------


class FakeApi:
    """以 path 回應的假 API（記下每次的 path）。"""

    def __init__(self, routes: Mapping[str, Any]) -> None:
        self.routes = routes
        self.calls: list[str] = []

    def __call__(self, path: str) -> Mapping[str, Any]:
        self.calls.append(path)
        response: Mapping[str, Any] = self.routes[path]
        return response


def _page(items: list[dict[str, Any]], total: int, page: int = 1) -> dict[str, Any]:
    return {
        "success": True,
        "data": items,
        "error": None,
        "meta": {"page": page, "limit": 100, "total": total},
    }


def test_pages_follow_the_total() -> None:
    items = [{"id": str(index)} for index in range(150)]
    api = FakeApi(
        {
            "/x?page=1&limit=100": _page(items[:100], 150),
            "/x?page=2&limit=100": _page(items[100:], 150, 2),
        }
    )

    assert pages(api, "/x") == items
    assert api.calls == ["/x?page=1&limit=100", "/x?page=2&limit=100"]


def test_pages_keep_existing_query_parameters() -> None:
    api = FakeApi({"/x?engine=zap&page=1&limit=100": _page([], 0)})

    assert pages(api, "/x?engine=zap") == []


@pytest.mark.parametrize(
    "routes",
    [
        {
            "/x?page=1&limit=100": _page([{"id": "1"}], 2),
            "/x?page=2&limit=100": _page([{"id": "2"}], 3),
        },
        {
            "/x?page=1&limit=100": _page([{"id": "1"}], 2),
            "/x?page=2&limit=100": _page([{"id": "1"}], 2),
        },
        {"/x?page=1&limit=100": _page([{"id": "1"}], 2), "/x?page=2&limit=100": _page([], 2)},
        {"/x?page=1&limit=100": {"success": True, "data": {}, "meta": {"total": 0}}},
        {"/x?page=1&limit=100": {"success": True, "data": [], "meta": None}},
    ],
)
def test_inconsistent_pages_fail(routes: dict[str, Any]) -> None:
    with pytest.raises(CollectError):
        pages(FakeApi(routes), "/x")


def test_too_many_pages_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("benchmarks.collect.MAX_PAGES", 2)
    routes = {f"/x?page={n}&limit=100": _page([{"id": str(n)}], 5, n) for n in (1, 2)}

    with pytest.raises(CollectError, match="頁數"):
        pages(FakeApi(routes), "/x")


def test_collect_scan_reads_the_scan_its_findings_and_the_observation_total() -> None:
    scan = scan_json()
    scan_id = scan["id"]
    finding = finding_json("sqli")
    api = FakeApi(
        {
            f"/scans/{scan_id}": {"success": True, "data": scan, "error": None, "meta": None},
            f"/scans/{scan_id}/findings?page=1&limit=100": _page([finding], 1),
            f"/scans/{scan_id}/observations?page=1&limit=1": _page([{"id": "o"}], 9),
        }
    )

    raw_scan, raw_findings, observations = collect_scan(api, scan_id)

    assert (raw_scan, raw_findings, observations) == (scan, [finding], 9)


def test_collect_comparison_reads_the_snapshot_and_its_findings() -> None:
    snapshot, items = comparison_json(str(uuid4()), str(uuid4()), [(str(uuid4()), "new")])
    path = f"/scan-comparisons/{snapshot['id']}"
    api = FakeApi(
        {
            path: {"success": True, "data": snapshot, "error": None, "meta": None},
            f"{path}/findings?page=1&limit=100": _page(items, 1),
        }
    )

    assert collect_comparison(api, snapshot["id"]) == (snapshot, items)


def test_a_failed_envelope_is_rejected() -> None:
    api = FakeApi({"/scans/x": {"success": False, "data": None, "error": {"code": "X"}}})

    with pytest.raises(CollectError, match="envelope"):
        collect_scan(api, "x")
