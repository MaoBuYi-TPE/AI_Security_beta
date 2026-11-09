"""T22：同一核准 target 換版後，真實 ZAP + Nuclei 的比較不把漏掃當成修補。

依序重建弱點版、弱點版對照、修補版、小預算弱點版；host、IP、port、target 與 grant 不變。
SECSCAN_RECORD_DIR 保存每次量測及不可變比較 API 的回應。不記固定告警數、不改 golden fixture。
"""

import functools
import time
import uuid
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest

from tests.live.engine_assertions import assert_engine_outcome
from tests.live.evidence_assertions import assert_scan_sealed
from tests.live.lab_support import Target, fixture_records, lab_call, start_fixture, stop_target
from tests.live.recordings import reserve_recording_directory, write_measurement
from tests.live.report_assertions import (
    check_document,
    check_headers,
    check_markdown,
    download,
)
from tests.live.rescan_assertions import (
    _case_id,
    assert_calibrated_structure,
    assert_conservative_comparison,
    check_patched_cases,
)
from tests.live.support import API, Api, admin_key, scan_containers, wait_for
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
from tests.live.triage_support import (
    RETESTS,
    Observed,
    assert_rejected_for,
    attestation,
    confirm_body,
    located_attestation,
    passes,
    platform_problems,
    resolve_body,
)
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
    during: Callable[[Target], None] | None = None,
) -> Combined:
    target = start_fixture(vulnerable=vulnerable, host=host)
    try:
        assert target.host == host
        assert item.origin == f"http://{target.host}:{target.port}"
        measured = _partial(item) if label == "partial" else _run(label, item)
        _validate_run(measured, target, definitions)
        if during is not None:
            # T21：修補版還在執行時做人工複測（lab_call 不經 guard，也不屬於任何 scan）。
            during(target)
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
    observed: dict[str, Observed] = {}
    secure = _measure_variant(
        item,
        host,
        vulnerable=False,
        label="secure",
        definitions=definitions,
        during=lambda target: observed.update(_retest(target)),
    )
    patched = _compare(item, baseline, secure, "patched")
    write_measurement(
        "patched-ground-truth",
        check_patched_cases(baseline.findings, patched["findings"]),
        filename="ground-truth.json",
    )
    resolved = _resolve_cases(item, baseline, patched, observed)
    _rejected_cases(item, baseline, unchanged, patched, observed, resolved)
    partial = _measure_variant(
        item, host, vulnerable=True, label="partial", definitions=definitions
    )
    incomplete = _compare(item, baseline, partial, "partial-comparison")
    assert incomplete["snapshot"]["counts"]["not_observed"] == 0
    _check_reopen(admin, item, partial, resolved)
    _check_reports(item, (baseline, partial))
    # T23a（DECISIONS §30.3、§30.4）：原始證據只剩密文；報告解密之後的 sha256 已在
    # check_headers 核對。
    for scanned in (baseline, partial):
        assert_scan_sealed(item.operator, scanned.scan["id"], [item.host.encode()])
    # 後續 scan 更新 target 的 finding 聚合後，原本比較快照與分頁內容仍原封不動。
    snapshot = unchanged["snapshot"]
    assert item.operator.data("GET", f"{URL}/{snapshot['id']}") == snapshot
    assert _pages(item, f"{URL}/{snapshot['id']}/findings") == unchanged["findings"]


# --- T21：人工複測、resolve、反例、自動重開與報告（計畫 §6.3）-------------------------------
REPORT_TIMEOUT = 180


def _retest(target: Target) -> dict[str, Observed]:
    """逐案複測；修補後的行為成立才當成證據，不把 inconclusive 直接當成已修補。"""
    results: dict[str, Observed] = {}
    for case_id, retest in RETESTS.items():
        performed_at = datetime.now(UTC)
        status, body = lab_call(target, retest.method, retest.path)
        item = Observed(case_id, retest.method, retest.path, status, body, performed_at)
        assert passes(item), (case_id, status)
        results[case_id] = item
    return results


def _detail(item: Lab, finding_id: str) -> dict[str, Any]:
    detail: dict[str, Any] = item.operator.data("GET", f"/findings/{finding_id}")
    return detail


def _confirmed(item: Lab, finding_id: str) -> int:
    detail = _detail(item, finding_id)
    version = int(detail["triage_version"])
    if detail["triage_state"] == "confirmed":
        return version
    item.operator.data("PATCH", f"/findings/{finding_id}/triage", confirm_body(version))
    return version + 1


def _host_port(item: Lab) -> tuple[str, int]:
    origin = item.origin.removeprefix("http://")
    host, _, port = origin.partition(":")
    return host, int(port)


def _resolve_cases(
    item: Lab, baseline: Combined, patched: dict[str, Any], observed: dict[str, Observed]
) -> list[str]:
    """符合人工複測平台條件的案例 finding 逐一 resolve；不符的必須被拒絕。比較快照不變。"""
    snapshot = patched["snapshot"]
    rows = {row["finding_id"]: row for row in patched["findings"]}
    host, port = _host_port(item)
    resolved: list[str] = []
    outcomes: list[dict[str, Any]] = []
    for finding in baseline.findings:
        case_id = _case_id(finding)
        if case_id is None or case_id not in RETESTS:
            continue
        finding_id = finding["id"]
        version = _confirmed(item, finding_id)
        claim = attestation(observed[case_id], host, port, finding["auth_role"])
        url = f"/findings/{finding_id}/triage"
        rescan = resolve_body(version, snapshot["id"], None, basis="rescan_not_observed")
        status, response = item.operator.call("PATCH", url, rescan)
        assert status == 422, response
        assert "not_observed_required" in response["error"]["message"]
        problems = platform_problems(snapshot, rows.get(finding_id))
        status, response = item.operator.call(
            "PATCH", url, resolve_body(version, snapshot["id"], claim)
        )
        outcomes.append({"case_id": case_id, "finding_id": finding_id, "problems": problems})
        if problems:
            assert status == 422, response
            assert_rejected_for(response, problems)
            continue
        assert status == 200, response
        resolution = response["data"]["resolution"]
        assert response["data"]["lifecycle_state"] == "resolved"
        assert resolution["basis"] == "manual_retest"
        assert resolution["evidence_provenance"] == "operator_supplied"
        assert "未驗證其真實性" in resolution["notice"]
        resolved.append(finding_id)
    unchanged_rows = _pages(item, f"{URL}/{snapshot['id']}/findings")
    assert unchanged_rows == patched["findings"], "人工判定不可改寫比較快照"
    write_measurement(
        "triage-resolve", {"outcomes": outcomes, "resolved": resolved}, filename="triage.json"
    )
    assert resolved, "沒有任何案例符合人工複測的平台條件"
    return resolved


def _rejected_cases(
    item: Lab,
    baseline: Combined,
    unchanged: dict[str, Any],
    patched: dict[str, Any],
    observed: dict[str, Observed],
    resolved: list[str],
) -> None:
    """反例：帶 Nuclei 失敗來源的 CSP、unchanged 中 persistent 的 finding、缺少摘錄。

    每個反例的聲明都對準該 finding 自己的 method、route、參數與身分，拒絕原因必須包含平台
    條件算出的每個代碼，而且不含位置或身分不符（否則反例沒有鑑別力）。
    """
    host, port = _host_port(item)
    sample = next(iter(observed.values()))
    by_id = {finding["id"]: finding for finding in baseline.findings}
    csp = [
        finding["id"]
        for finding in baseline.findings
        if finding["rule_group"] == "csp-header-missing"
        and finding["location"]["route"] == "/"
        and finding["id"] not in resolved
    ]
    persistent = [
        row["finding_id"]
        for row in unchanged["findings"]
        if row["classification"] == "persistent"
        and row["finding_id"] not in resolved
        and row["finding_id"] in by_id
    ]
    outcomes: list[dict[str, Any]] = []
    negatives = [(finding_id, patched) for finding_id in csp[:1]]
    negatives += [(finding_id, unchanged) for finding_id in persistent[:1]]
    for finding_id, cited in negatives:
        rows = {row["finding_id"]: row for row in cited["findings"]}
        expected = platform_problems(cited["snapshot"], rows.get(finding_id))
        claim = located_attestation(by_id[finding_id], sample, host, port)
        version = _confirmed(item, finding_id)
        status, response = item.operator.call(
            "PATCH",
            f"/findings/{finding_id}/triage",
            resolve_body(version, cited["snapshot"]["id"], claim),
        )
        assert status == 422, response
        codes = assert_rejected_for(response, expected)
        outcomes.append({"finding_id": finding_id, "expected": expected, "codes": sorted(codes)})
    assert len(outcomes) == len(negatives)
    write_measurement("triage-rejected", {"outcomes": outcomes}, filename="triage-rejected.json")
    if persistent:
        finding_id = persistent[0]
        version = int(_detail(item, finding_id)["triage_version"])
        claim = located_attestation(by_id[finding_id], sample, host, port)
        partial_claim = {key: value for key, value in claim.items() if key != "response_excerpt"}
        status, response = item.operator.call(
            "PATCH",
            f"/findings/{finding_id}/triage",
            resolve_body(version, unchanged["snapshot"]["id"], partial_claim),
        )
        assert status == 422, response
        assert response["error"]["code"] == "INVALID_REQUEST"
        assert "response_excerpt" in response["error"]["message"]


def _check_reopen(admin: Api, item: Lab, partial: Combined, resolved: list[str]) -> None:
    """resolve 之後建立的小預算弱點版 scan：有連結到的 finding 必須自動重開。"""
    linked = {finding["id"] for finding in partial.findings}
    reopened = []
    for finding_id in resolved:
        detail = _detail(item, finding_id)
        if finding_id not in linked:
            assert detail["lifecycle_state"] == "resolved"
            continue
        assert detail["lifecycle_state"] == "reopened", detail["lifecycle_state"]
        events = _pages(item, f"/findings/{finding_id}/triage-events")
        assert events[-1]["actor_kind"] == "system"
        assert events[-1]["scan_id"] == partial.scan["id"]
        assert events[-1]["reason_code"] == "auto_reopen_new_observation"
        reopened.append(finding_id)
    project = item.operator.data("GET", f"/targets/{item.target_id}")["project_id"]
    audits = admin.data(
        "GET", f"/audit-events?project_id={project}&action=finding.reopen&limit=100"
    )
    assert {event["object_id"] for event in audits} >= set(reopened)
    write_measurement(
        "triage-reopen", {"resolved": resolved, "reopened": reopened}, filename="triage.json"
    )
    assert reopened, "小預算 scan 沒有重開任何已 resolve 的 finding"


def _check_reports(item: Lab, scans: tuple[Combined, ...]) -> None:
    measured = []
    for scanned in scans:
        for report_format in ("json", "markdown"):
            status, response = item.operator.call(
                "POST",
                f"/scans/{scanned.scan['id']}/reports",
                {"format": report_format},
                headers={"Idempotency-Key": uuid.uuid4().hex},
            )
            assert status == 202, response
            report_id = response["data"]["id"]
            meta = wait_for(
                functools.partial(_finished_report, item, report_id),
                timeout=REPORT_TIMEOUT,
                interval=2,
            )
            assert meta["status"] == "succeeded", meta
            assert meta["expires_at"] is not None
            assert meta["content_purged_at"] is None
            code, headers, content = download(API, item.operator.key, report_id)
            assert code == 200
            check_headers(meta, headers, content)
            if report_format == "json":
                document = check_document(content, complete=scanned.scan["results_complete"])
                assert document.summary.findings_total == len(scanned.findings)
            else:
                check_markdown(content.decode("utf-8"))
            measured.append(
                {
                    "scan": scanned.label,
                    "format": report_format,
                    "size_bytes": meta["size_bytes"],
                    "truncated": meta["truncated"],
                    "attempts": meta["attempts"],
                }
            )
    write_measurement("reports", {"reports": measured}, filename="reports.json")


def _finished_report(item: Lab, report_id: str) -> dict[str, Any] | None:
    meta: dict[str, Any] = item.operator.data("GET", f"/reports/{report_id}")
    return meta if meta["status"] in {"succeeded", "failed"} else None
