"""T18：真的 Nuclei 經平台掃描自製的 fixture app（docs/SECURITY_AND_TESTING.md §5；
make test-live-fixture-nuclei）。

fixture app 在 live 自己的 lab 網路上、一次一個（lab_support.start_fixture），跑在 guard 映像的
python（stdlib）。弱點版（insecure）加 CORS 萬用字元、沒有安全 header；修補版（secure）補安全
header、沒有 CORS → nuclei 的乾淨正負對照：
- cors-misconfig：insecure 反射 Origin → 命中；secure 沒有 ACAO → 不命中。
- http-missing-security-headers：insecure 缺很多 header → 命中較多（negative matcher）。

量測機制與 T16 相同（plan_hash、和 /scan-profiles 相同的 nuclei 定義、observed ⊆ forwarded、
guard 只看到 target），重用 test_lab_zap_live 的 Measured 與 _assert_invariants。guard 合成的 403
（negative matcher 會誤報）由 parser 以 X-Secscan-Guard 濾掉，所以 observed ⊆ forwarded 必成立。
SECSCAN_RECORD_DIR 有設定時另外錄製到 recordings/fixture-nuclei/<情境>/，人工審查後才搬進 fixture。
"""

import json
import os
import time
import uuid
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.live.lab_support import Target, start_fixture, stop_target
from tests.live.support import Api, admin_key, scan_containers, wait_for
from tests.live.test_lab_zap_live import Measured, _assert_invariants
from tests.live.zap_support import (
    RUN_TIMEOUT,
    RUNS_VOLUME,
    Lab,
    lab,
    now,
    requests_since,
    volume_file,
    wait_for_zap,
)

pytestmark = [pytest.mark.live, pytest.mark.enable_socket]

WEB_METHODS = ["GET", "HEAD", "POST"]
# 乾淨的正負對照（fixture 的 insecure 反射 Origin、secure 沒有 ACAO）。
CORS_RULE = "cors-misconfig"
HEADERS_RULE = "http-missing-security-headers"


@pytest.fixture(scope="module")
def admin() -> Api:
    return Api(admin_key())


@pytest.fixture(scope="module")
def definition(admin: Api) -> dict[str, str]:
    """/scan-profiles 的 nuclei 定義：先等 runner 的 probe 通過（清單才會列出 nuclei）。"""
    wait_for_zap(admin)
    profiles = admin.data("GET", "/scan-profiles")
    return {
        item["profile"]: engine["definition_sha256"]
        for item in profiles
        for engine in item["engines"]
        if engine["engine"] == "nuclei"
    }


def _web_lab(admin: Api, target: Target) -> Lab:
    return lab(
        admin,
        kind="web",
        paths=None,
        methods=WEB_METHODS,
        host=target.host,
        ip=target.ip,
        port=target.port,
    )


def _scan(item: Lab, profile: str, **options: Any) -> str:
    status, payload = item.operator.call(
        "POST",
        "/scans",
        {
            "target_id": item.target_id,
            "scope_grant_id": item.grant_id,
            "api_spec_id": options.get("spec_id"),
            "auth_profile_id": options.get("auth_profile_id"),
            "profile": profile,
            "engines": ["nuclei"],
            "budget": options.get("budget", {}),
        },
        headers={"Idempotency-Key": str(uuid.uuid4())},
    )
    assert status == 202, (status, payload.get("error"))
    return str(payload["data"]["id"])


def _finished(item: Lab, scan_id: str) -> dict[str, Any]:
    done = {"succeeded", "failed", "cancelled", "timed_out", "interrupted"}

    def check() -> dict[str, Any] | None:
        engines = item.operator.data("GET", f"/scans/{scan_id}")["engines"]
        [engine] = [engine for engine in engines if engine["engine"] == "nuclei"]
        return dict(engine) if engine["status"] in done else None

    return wait_for(check, timeout=RUN_TIMEOUT, interval=3)


def _observations(item: Lab, scan_id: str) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    page = 1
    while True:
        status, payload = item.operator.call(
            "GET", f"/scans/{scan_id}/observations?engine=nuclei&limit=100&page={page}"
        )
        assert status == 200, payload
        collected += payload["data"]
        if len(collected) >= payload["meta"]["total"] or not payload["data"]:
            return collected
        page += 1


def _run_scan(label: str, item: Lab, target: Target, profile: str, **options: Any) -> Measured:
    started, clock = now(), time.monotonic()
    scan_id = _scan(item, profile, **options)

    def find() -> str | None:
        names = scan_containers(scan_id, "nuclei")
        return names[0] if names else None

    container = wait_for(find, timeout=300, interval=2)
    engine = _finished(item, scan_id)
    run_id = container.removeprefix("secscan-run-")
    measured = Measured(
        label=label,
        scan_id=scan_id,
        run_id=run_id,
        engine=engine,
        scan=item.operator.data("GET", f"/scans/{scan_id}"),
        observations=_observations(item, scan_id),
        decisions=requests_since(started),
        seconds=time.monotonic() - clock,
        report_bytes=None,
        memory={},
    )
    _print(measured)
    _record(measured)
    return measured


def _print(measured: Measured) -> None:
    engine = measured.engine
    result = engine.get("result") or {}
    rules = Counter(o["source_rule"] for o in measured.observations)
    for line in (
        f"{engine['status']} {engine['error_code']}，{measured.seconds:.0f} 秒",
        f"plan_hash {engine['plan_hash']}，定義 {engine['profile_definition_sha256']}",
        f"guard_traffic {json.dumps(result.get('guard_traffic') or {}, ensure_ascii=False)}",
        f"excluded {json.dumps(result.get('excluded') or {})}",
        f"觀察 {len(measured.observations)}（依模板）{dict(rules)}",
    ):
        print(f"[量測] {measured.label}：{line}")  # noqa: T201


def _record(measured: Measured) -> None:
    """SECSCAN_RECORD_DIR 有設定時保存輸出（只保存解析過的 run：out/ 已遮罩）。"""
    root = os.environ.get("SECSCAN_RECORD_DIR")
    if not root or measured.engine.get("result") is None:
        return
    directory = Path(root) / measured.label
    directory.mkdir(parents=True, exist_ok=True)
    run = uuid.UUID(measured.run_id)
    files = {
        "manifest.json": volume_file(RUNS_VOLUME, f"{run}/manifest.json"),
        "results.jsonl": volume_file(RUNS_VOLUME, f"{run}/out/results.jsonl"),
    }
    for name, content in files.items():
        if content is not None:
            (directory / name).write_bytes(content)
    (directory / "scan.json").write_text(
        json.dumps(
            {
                "engine": measured.engine,
                "coverage": measured.scan["coverage"],
                "observations": measured.observations,
                "seconds": round(measured.seconds),
            },
            ensure_ascii=False,
            indent=1,
        )
        + "\n"
    )


def _rules(measured: Measured) -> set[str]:
    return {o["source_rule"] for o in measured.observations}


class TestFixtureVulnerable:
    @pytest.fixture(scope="class")
    def vuln(self) -> Iterator[Target]:
        target = start_fixture(vulnerable=True)
        yield target
        stop_target(target)

    def test_nuclei_finds_the_cors_misconfiguration(
        self, admin: Api, definition: dict[str, str], vuln: Target
    ) -> None:
        wait_for_zap(admin)
        item = _web_lab(admin, vuln)

        measured = _run_scan("fixture-nuclei-vuln", item, vuln, "web_active_lab")

        assert measured.engine["status"] in {"succeeded", "timed_out"}, measured.engine
        _assert_invariants(measured, vuln, definition["web_active_lab"])
        # 正例：insecure 反射 Origin → cors-misconfig 命中；缺安全 header → headers 模板也命中。
        assert CORS_RULE in _rules(measured), measured.rules
        assert HEADERS_RULE in _rules(measured), measured.rules


class TestFixtureSecure:
    @pytest.fixture(scope="class")
    def secure(self) -> Iterator[Target]:
        target = start_fixture(vulnerable=False)
        yield target
        stop_target(target)

    def test_the_patched_build_has_no_cors_finding(
        self, admin: Api, definition: dict[str, str], secure: Target
    ) -> None:
        wait_for_zap(admin)
        item = _web_lab(admin, secure)

        measured = _run_scan("fixture-nuclei-secure", item, secure, "web_active_lab")

        assert measured.engine["status"] in {"succeeded", "timed_out"}, measured.engine
        _assert_invariants(measured, secure, definition["web_active_lab"])
        # 負例：修補版補了安全 header、沒有 CORS → cors-misconfig 不命中。
        assert CORS_RULE not in _rules(measured), measured.rules
