"""錄製 ZAP 的真實輸出（make record-fixtures；docs/DECISIONS.md §19.9）。

需要 ENABLE_LIVE_LAB_TESTS=1 與 SECSCAN_RECORD_DIR（Makefile 設為 gitignore 的 recordings/zap）。
每個情境掃描 live 自己 lab 網路上的小型網站（zap_site.py），把 runner 收集的 manifest、報告、
zap.log，guard 的 telemetry 與決策 log、網站的收包紀錄與 API 看到的 run 複製到
<SECSCAN_RECORD_DIR>/<情境>/。人工審查之後才搬進 tests/fixtures/zap/（不自動更新 fixture）。
情境都是 anonymous：沒有目標的 secret 可以寫進輸出。
- findings：web 的 active scan，grant 排除 /admin（guard 拒絕的回應也在裡面）。
- clean：api profile，只有加了安全 header 的 JSON 端點。
- timeout：預算小到 plan 的 maxDuration 先到。
- unanswered：target 的 port 沒有人聽，每個請求都由 mitmproxy 回 502（沒有上游的回應）。
"""

import json
import os
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.live.support import TELEMETRY_VOLUME, Api, admin_key, scan_containers, wait_for
from tests.live.zap_support import (
    RUNS_VOLUME,
    SITE_IP,
    SITE_PORT,
    Lab,
    Site,
    lab,
    now,
    requests_since,
    start_site,
    stop_site,
    volume_file,
    wait_for_zap,
)

pytestmark = [pytest.mark.live, pytest.mark.enable_socket]

HARDENED_SPEC: dict[str, Any] = {
    "openapi": "3.0.3",
    "info": {"title": "hardened items", "version": "1"},
    "paths": {
        "/items": {
            "get": {"operationId": "listItems", "responses": {"200": {"description": "ok"}}}
        },
        "/items/{id}": {
            "parameters": [
                {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}
            ],
            "get": {"operationId": "getItem", "responses": {"200": {"description": "ok"}}},
        },
    },
}


def _destination(scenario: str) -> Path:
    root = os.environ.get("SECSCAN_RECORD_DIR")
    if not root:
        pytest.skip("沒有設定 SECSCAN_RECORD_DIR（make record-fixtures）")
    directory = Path(root) / scenario
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _run_id(scan_id: str) -> str:
    def find() -> str | None:
        names = scan_containers(scan_id, "zap")
        return names[0].removeprefix("secscan-run-") if names else None

    return wait_for(find, timeout=180)


def _record(
    scenario: str, item: Lab, site: Site, scan_id: str, *, started: float, run_id: str
) -> dict[str, Any]:
    destination = _destination(scenario)
    engine = item.finished_zap(scan_id)
    copies = {
        "manifest.json": (RUNS_VOLUME, f"{uuid.UUID(run_id)}/manifest.json"),
        "report.json": (RUNS_VOLUME, f"{uuid.UUID(run_id)}/out/zap-report.json"),
        "zap.log": (RUNS_VOLUME, f"{uuid.UUID(run_id)}/out/zap.log"),
        "telemetry.jsonl": (TELEMETRY_VOLUME, f"{uuid.UUID(run_id)}.jsonl"),
    }
    for name, (volume, path) in copies.items():
        content = volume_file(volume, path)
        if content is not None:
            (destination / name).write_bytes(content)
    ours = {run_id, None}
    decisions = [entry for entry in requests_since(started) if entry.get("run_id") in ours]
    (destination / "guard.jsonl").write_text("".join(json.dumps(e) + "\n" for e in decisions))
    (destination / "site.jsonl").write_text("".join(json.dumps(r) + "\n" for r in site.records()))
    (destination / "engine.json").write_text(json.dumps(engine, indent=1) + "\n")
    print(f"[錄製] {scenario}：{engine['status']} {engine['error_code']} → {destination}")  # noqa: T201
    return engine


@pytest.fixture(scope="module")
def admin() -> Api:
    return Api(admin_key())


@pytest.fixture
def sites() -> Iterator[list[Site]]:
    started: list[Site] = []
    yield started
    for site in started:
        stop_site(site)


def _site(sites: list[Site], item: Lab, *, port: int = SITE_PORT) -> Site:
    site = start_site(item.host, ip=SITE_IP, alias=item.host, port=port)
    sites.append(site)
    return site


def _web(
    admin: Api,
    sites: list[Site],
    scenario: str,
    budget: dict[str, int],
    expected: str,
    **options: Any,
) -> None:
    wait_for_zap(admin)
    item = lab(admin, kind="web", paths=None, excluded=["/admin"], methods=["GET", "HEAD"])
    site = _site(sites, item, **options)
    started = now()
    scan_id = item.scan("web_active_lab", budget=budget)
    run_id = _run_id(scan_id)
    engine = _record(scenario, item, site, scan_id, started=started, run_id=run_id)
    assert engine["status"] == expected, engine


def test_record_findings(admin: Api, sites: list[Site]) -> None:
    _web(admin, sites, "findings", {"max_duration_seconds": 240}, "succeeded")


def test_record_timeout(admin: Api, sites: list[Site]) -> None:
    # plan 的 maxDuration 是 120 - 60 = 60 秒：spider 的上限是 1 分鐘，active scan 來不及跑完。
    _web(admin, sites, "timeout", {"max_duration_seconds": 120}, "timed_out")


def test_record_unanswered(admin: Api, sites: list[Site]) -> None:
    _web(admin, sites, "unanswered", {"max_duration_seconds": 180}, "failed", port=SITE_PORT + 1)


def test_record_clean(admin: Api, sites: list[Site]) -> None:
    wait_for_zap(admin)
    paths = ["/hardened/items", "/hardened/items/{id}"]
    item = lab(admin, kind="api", paths=paths, methods=["GET"])
    site = _site(sites, item)
    spec = {**HARDENED_SPEC, "servers": [{"url": "/hardened"}]}
    uploaded = item.operator.data(
        "POST",
        f"/targets/{item.target_id}/api-specs",
        raw=json.dumps(spec).encode(),
        content_type="application/json",
    )
    started = now()
    scan_id = item.scan("api_active_lab", spec_id=str(uploaded["id"]), budget={"max_requests": 300})
    run_id = _run_id(scan_id)
    engine = _record("clean", item, site, scan_id, started=started, run_id=run_id)
    assert engine["status"] == "succeeded", engine
