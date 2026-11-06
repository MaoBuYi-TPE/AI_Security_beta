"""T22：同一核准 target 換版後，真實 ZAP + Nuclei 的比較不把漏掃當成修補。

依序重建弱點版、弱點版對照、修補版、小預算弱點版；host、IP、port、target 與 grant 不變。
SECSCAN_RECORD_DIR 保存每次量測及不可變比較 API 的回應。不記固定告警數、不改 golden fixture。
"""

import time
import uuid
from collections import Counter
from typing import Any

import pytest

from tests.live.engine_assertions import assert_engine_outcome
from tests.live.lab_support import Target, fixture_records, start_fixture, stop_target
from tests.live.recordings import reserve_recording_directory, write_measurement
from tests.live.rescan_assertions import (
    assert_calibrated_structure,
    assert_conservative_comparison,
    check_patched_cases,
)
from tests.live.support import Api, admin_key, scan_containers, wait_for
from tests.live.test_fixture_findings_live import (
    ENGINES,
    PROFILE,
    TERMINAL_SCANS,
    WEB_METHODS,
    Combined,
    _container,
    _create,
    _pages,
    _record,
    _run,
)
from tests.live.test_lab_zap_live import Measured, _assert_invariants
from tests.live.zap_support import RUN_TIMEOUT, Lab, lab, now, requests_since, wait_for_zap

pytestmark = [pytest.mark.live, pytest.mark.enable_socket]
PARTIAL_SECONDS = 240
URL = "/scan-comparisons"


def _finished(item: Lab, scan_id: str) -> dict[str, Any] | None:
    scan = item.operator.data("GET", f"/scans/{scan_id}")
    return dict(scan) if scan["status"] in TERMINAL_SCANS else None


def _partial(item: Lab) -> Combined:
    started, clock = now(), time.monotonic()
    scan_id = _create(item, {"max_duration_seconds": PARTIAL_SECONDS})
    container = _container(scan_id, "zap")
    scan = wait_for(lambda: _finished(item, scan_id), timeout=RUN_TIMEOUT, interval=3)
    seconds = time.monotonic() - clock
    measured = Measured(
        label="partial-zap",
        scan_id=scan_id,
        run_id=container.removeprefix("secscan-run-"),
        engine=next(run for run in scan["engines"] if run["engine"] == "zap"),
        scan=scan,
        observations=_pages(item, f"/scans/{scan_id}/observations?engine=zap"),
        decisions=requests_since(started),
        seconds=seconds,
        report_bytes=None,
        memory={},
    )
    result = Combined(
        "partial", scan, {"zap": measured}, _pages(item, f"/scans/{scan_id}/findings"), seconds
    )
    _record(result)
    assert scan["results_complete"] is False, scan
    assert any(run["status"] != "succeeded" for run in scan["engines"])
    assert scan["budget_usage"]["traffic_duration_seconds"] <= PARTIAL_SECONDS
    return result


def _validate_run(measured: Combined, target: Target, definitions: dict[str, str]) -> None:
    for engine, run in measured.runs.items():
        assert_engine_outcome(run.engine, measured.scan)
        _assert_invariants(run, target, definitions[engine])
    assert all("x-zap-scan-id" not in record["headers"] for record in fixture_records(target))
    for engine in ENGINES:
        assert not scan_containers(measured.scan["id"], engine)


def _compare(item: Lab, baseline: Combined, current: Combined, label: str) -> dict[str, Any]:
    body = {"baseline_scan_id": baseline.scan["id"], "current_scan_id": current.scan["id"]}
    status, response = item.operator.call("POST", URL, body)
    assert status == 201, response
    snapshot = response["data"]
    findings = _pages(item, f"{URL}/{snapshot['id']}/findings")
    assert "不等於已修補" in snapshot["notice"]
    before, after = ({f["id"] for f in run.findings} for run in (baseline, current))
    assert {f["finding_id"] for f in findings} == before | after
    counts = Counter(f["classification"] for f in findings)
    assert snapshot["counts"] == {key: counts[key] for key in snapshot["counts"]}
    for finding in findings:
        evidence = finding["evidence"]
        assert evidence["baseline_observed"] is (finding["finding_id"] in before)
        assert evidence["current_observed"] is (finding["finding_id"] in after)
        if finding["classification"] == "persistent":
            assert finding["finding_id"] in before & after
        else:
            assert finding["reasons"]
    assert_conservative_comparison(snapshot, findings)
    assert_calibrated_structure(label, snapshot)
    status, replay = item.operator.call("POST", URL, body)
    assert status == 200
    assert replay["data"] == snapshot
    document = {"snapshot": snapshot, "findings": findings}
    write_measurement(label, document)
    print(  # noqa: T201
        f"[複掃] {label}：{snapshot['comparability']} {snapshot['counts']} "
        f"manual_review={snapshot['manual_review_required']}"
    )
    return document


def _measure_variant(
    item: Lab,
    host: str,
    *,
    vulnerable: bool,
    label: str,
    definitions: dict[str, str],
) -> Combined:
    target = start_fixture(vulnerable=vulnerable, host=host)
    try:
        assert target.host == host
        assert item.origin == f"http://{target.host}:{target.port}"
        measured = _partial(item) if label == "partial" else _run(label, item)
        _validate_run(measured, target, definitions)
        return measured
    finally:
        stop_target(target)


def test_same_target_control_patch_and_partial_scans_never_claim_false_repair() -> None:
    reserve_recording_directory()
    admin = Api(admin_key())
    wait_for_zap(admin)
    definitions = {
        engine["engine"]: engine["definition_sha256"]
        for profile in admin.data("GET", "/scan-profiles")
        if profile["profile"] == PROFILE
        for engine in profile["engines"]
    }
    assert set(definitions) >= set(ENGINES)
    host = f"lab-rescan-{uuid.uuid4().hex[:6]}"
    target = start_fixture(vulnerable=True, host=host)
    try:
        item = lab(
            admin,
            kind="web",
            paths=None,
            methods=WEB_METHODS,
            host=host,
            ip=target.ip,
            port=target.port,
        )
        baseline = _run("baseline", item)
        _validate_run(baseline, target, definitions)
    finally:
        stop_target(target)
    assert baseline.findings, "沒有 baseline finding，無法驗證差異分類"
    control = _measure_variant(
        item, host, vulnerable=True, label="control", definitions=definitions
    )
    unchanged = _compare(item, baseline, control, "unchanged")
    # 對照組沒有修補任何程式；工具變異或漏掃也不應變成負面結論。
    assert unchanged["snapshot"]["counts"]["not_observed"] == 0
    secure = _measure_variant(item, host, vulnerable=False, label="secure", definitions=definitions)
    patched = _compare(item, baseline, secure, "patched")
    write_measurement(
        "patched-ground-truth",
        check_patched_cases(baseline.findings, patched["findings"]),
        filename="ground-truth.json",
    )
    partial = _measure_variant(
        item, host, vulnerable=True, label="partial", definitions=definitions
    )
    incomplete = _compare(item, baseline, partial, "partial-comparison")
    assert incomplete["snapshot"]["counts"]["not_observed"] == 0
    # 後續 scan 更新 target 的 finding 聚合後，原本比較快照與分頁內容仍原封不動。
    snapshot = unchanged["snapshot"]
    assert item.operator.data("GET", f"{URL}/{snapshot['id']}") == snapshot
    assert _pages(item, f"{URL}/{snapshot['id']}/findings") == unchanged["findings"]
