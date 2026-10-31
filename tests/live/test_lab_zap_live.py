"""T16：真的 ZAP 經平台掃描 Juice Shop 與 VAmPI（docs/DECISIONS.md §20；make test-live-lab）。

靶機在 live 自己的 lab 網路上、一次一個（lab_support.py）；每個情境用新的 project、target 與 grant。
- VAmPI 弱點版（vulnerable=1）與安全版（vulnerable=0）以相同的設定掃描：正例與負例的對照。
- token 失效：縮短 VAmPI 的 tokentimetolive，掃描中途過期 → coverage 標 AUTHENTICATION_LOST，
  result 的 guard_traffic.auth 記下被拒絕的數量（不重新登入，§20.4）。
- 工具超時：預算小到 plan 的 maxDuration 先到 → timed_out（ENGINE_TIMEOUT），觀察仍入庫。
- 取消：ZAP 送出流量之後取消 → cancelled，容器刪除，guard 之後不再轉送。
- Juice Shop：web profile，anonymous 與 bearer。
每個 run 都要有 plan_hash、和 /scan-profiles 相同的 profile 定義與 guard 的流量明細；guard 只看到
target；觀察的 (method, path) 都是 guard 為這個 run 轉送過的請求。量測（時間、請求、拒絕的原因、
報告大小、記憶體）印在輸出、記在 docs/TOOLS.md §7.7；SECSCAN_RECORD_DIR 有設定時另外錄製檔案。
"""

import json
import os
import re
import threading
import time
import uuid
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from secscan.scanners.domain.zap.policy import API_RULES
from secscan.scanners.domain.zap.report import MAX_REPORT_BYTES
from tests.live.lab_support import (
    Target,
    juice_shop_token,
    start_juice_shop,
    start_vampi,
    stop_target,
    vampi_token,
)
from tests.live.support import (
    SPEC,
    TELEMETRY_VOLUME,
    Api,
    admin_key,
    docker,
    scan_containers,
    wait_for,
)
from tests.live.zap_support import (
    RUNS_VOLUME,
    Lab,
    lab,
    now,
    requests_since,
    volume_file,
    wait_for_zap,
)

pytestmark = [pytest.mark.live, pytest.mark.enable_socket]

# VAmPI 的規格中除了 /createdb（重設資料庫）以外的 path；method 只允許 GET 與 POST
# （DELETE 與改密碼、email 的 PUT 都不允許）。
VAMPI_PATHS = [
    "/",
    "/users/v1",
    "/users/v1/_debug",
    "/users/v1/register",
    "/users/v1/login",
    "/me",
    "/users/v1/{username}",
    "/users/v1/{username}/email",
    "/users/v1/{username}/password",
    "/books/v1",
    "/books/v1/{book_title}",
]
VAMPI_METHODS = ["GET", "POST"]
SHA256 = re.compile(r"[0-9a-f]{64}")
# 已知正例（S103）：弱點版的 /users/v1/{username} 以字串組 SQL。ZAP 的 SQLi 探測是 name1'。
SQLI_PROBE = "/users/v1/name1%27"
ACTIVE_RULES = frozenset(str(rule) for rule in API_RULES)
# JVM、spider、active scan、報告與 worker 的解析：比 plan 的 maxDuration（最多 1440 秒）多留一些。
RUN_TIMEOUT = 1800.0


@dataclass
class MemorySampler:
    """背景每 10 秒取一次容器的記憶體（docker stats；MiB），記下最大值。"""

    containers: list[str]
    peaks: dict[str, float] = field(default_factory=dict)
    _stop: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread | None = None

    def start(self) -> "MemorySampler":
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> dict[str, float]:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=30)
        return self.peaks

    def _loop(self) -> None:
        while not self._stop.wait(10):
            output = docker(
                "stats", "--no-stream", "--format", "{{.Name}} {{.MemUsage}}", check=False
            )
            for line in output.splitlines():
                name, _, usage = line.partition(" ")
                if name in self.containers:
                    self.peaks[name] = max(self.peaks.get(name, 0.0), _mebibytes(usage))


def _mebibytes(usage: str) -> float:
    value = usage.split("/")[0].strip()
    number = float(re.sub(r"[^0-9.]", "", value) or 0)
    if value.endswith("GiB"):
        return number * 1024
    if value.endswith("KiB"):
        return number / 1024
    return number


@dataclass(frozen=True)
class Measured:
    label: str
    scan_id: str
    run_id: str
    engine: dict[str, Any]
    scan: dict[str, Any]
    observations: list[dict[str, Any]]
    decisions: list[dict[str, Any]]
    seconds: float
    report_bytes: int | None
    memory: dict[str, float]

    @property
    def rules(self) -> Counter[str]:
        return Counter(f"{o['source_rule']} {o['title']}" for o in self.observations)

    def denied(self, reason: str) -> set[str]:
        return {
            str(entry["path"])
            for entry in self.decisions
            if entry.get("reason") == reason and entry.get("run_id") == self.run_id
        }

    def forwarded(self) -> set[tuple[str, str]]:
        return {
            (str(entry["method"]), str(entry["path"]))
            for entry in self.decisions
            if entry["decision"] == "allow" and entry.get("run_id") == self.run_id
        }


@pytest.fixture(scope="module")
def admin() -> Api:
    return Api(admin_key())


@pytest.fixture(scope="module")
def definitions(admin: Api) -> dict[str, str]:
    """/scan-profiles 只列可用的引擎：先等 runner 的 probe 通過（第一次量測時漏了，清單是空的）。"""
    wait_for_zap(admin)
    profiles = admin.data("GET", "/scan-profiles")
    return {
        item["profile"]: engine["definition_sha256"]
        for item in profiles
        for engine in item["engines"]
        if engine["engine"] == "zap"
    }


def _vampi_lab(admin: Api, target: Target) -> tuple[Lab, str]:
    item = lab(
        admin,
        kind="api",
        paths=VAMPI_PATHS,
        methods=VAMPI_METHODS,
        host=target.host,
        ip=target.ip,
        port=target.port,
    )
    spec = item.operator.data(
        "POST",
        f"/targets/{item.target_id}/api-specs",
        raw=SPEC.read_bytes(),
        content_type="application/yaml",
    )
    return item, str(spec["id"])


def _bearer(item: Lab, token: str, preflight: dict[str, Any]) -> str:
    created = item.operator.data(
        "POST",
        f"/targets/{item.target_id}/auth-profiles",
        {
            "name": "lab-user",
            "role_label": "standard_user",
            "type": "bearer",
            "secret": token,
            "preflight": preflight,
        },
    )
    return str(created["id"])


VAMPI_ME = {
    "method": "GET",
    "path": "/me",
    "expected_status": 200,
    "expected_json": {"/status": "success"},
}
# Juice Shop 的 /rest/user/whoami 只看 cookie（帶 bearer 與匿名都回 200 {"user":{}}）：第一次
# 量測以它當 preflight，平台正確地判定 failed。改用以 Authorization 驗證的端點（路由就是這個拼法）。
JUICE_SHOP_ADDRESSES = {
    "method": "GET",
    "path": "/api/Addresss",
    "expected_status": 200,
    "expected_json": {"/status": "success"},
}
# Juice Shop 的 REST 搜尋（前端呼叫的 API；S104 的 Database Schema、User Credentials）：
# q 以字串組 SQL。traditional spider 走不到（Angular 的前端路由），以操作者提供的規格掃描。
SEARCH_PATH = "/rest/products/search"
SEARCH_SPEC: dict[str, Any] = {
    "openapi": "3.0.3",
    "info": {"title": "juice shop search", "version": "1"},
    "servers": [{"url": "/rest"}],
    "paths": {
        "/products/search": {
            "get": {
                "operationId": "searchProducts",
                "parameters": [
                    {
                        "name": "q",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "string", "example": "apple"},
                    }
                ],
                "responses": {"200": {"description": "ok"}},
            }
        }
    },
}


def _zap_container(scan_id: str) -> str:
    def find() -> str | None:
        names = scan_containers(scan_id, "zap")
        return names[0] if names else None

    return wait_for(find, timeout=300, interval=2)


def _all_observations(item: Lab, scan_id: str) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    page = 1
    while True:
        status, payload = item.operator.call(
            "GET", f"/scans/{scan_id}/observations?engine=zap&limit=100&page={page}"
        )
        assert status == 200, payload
        collected += payload["data"]
        if len(collected) >= payload["meta"]["total"] or not payload["data"]:
            return collected
        page += 1


def _run_scan(
    label: str,
    item: Lab,
    target: Target,
    profile: str,
    **options: Any,
) -> Measured:
    started, clock = now(), time.monotonic()
    scan_id = item.scan(profile, **options)
    container = _zap_container(scan_id)
    sampler = MemorySampler([container, target.container]).start()
    engine = item.finished_zap(scan_id, timeout=RUN_TIMEOUT)
    memory = sampler.stop()
    run_id = container.removeprefix("secscan-run-")
    report = volume_file(RUNS_VOLUME, f"{uuid.UUID(run_id)}/out/zap-report.json")
    measured = Measured(
        label=label,
        scan_id=scan_id,
        run_id=run_id,
        engine=engine,
        scan=item.operator.data("GET", f"/scans/{scan_id}"),
        observations=_all_observations(item, scan_id),
        decisions=requests_since(started),
        seconds=time.monotonic() - clock,
        report_bytes=len(report) if report is not None else None,
        memory={name.removeprefix("secscan-"): value for name, value in memory.items()},
    )
    _print(measured)
    _record(measured, report)
    return measured


def _print(measured: Measured) -> None:
    engine, result = measured.engine, measured.engine.get("result") or {}
    traffic = result.get("guard_traffic") or {}
    denied = Counter(
        f"{entry.get('reason')}/{entry.get('method')}"
        for entry in measured.decisions
        if entry["decision"] == "deny" and entry.get("run_id") == measured.run_id
    )
    unattributed = sum(1 for entry in measured.decisions if entry.get("run_id") is None)
    ambiguous = sorted(
        {str(e.get("path")) for e in measured.decisions if e.get("reason") == "PATH_AMBIGUOUS"}
    )
    lines = [
        f"{engine['status']} {engine['error_code']}，{measured.seconds:.0f} 秒",
        f"plan_hash {engine['plan_hash']}，profile {engine['profile_definition_sha256']}",
        f"guard_traffic {json.dumps(traffic, ensure_ascii=False)}",
        f"拒絕（log）{dict(denied)}；沒有 run 的（407）{unattributed}",
        f"PATH_AMBIGUOUS 的 path（前 5 個）{ambiguous[:5]}",
        f"報告 {measured.report_bytes} bytes；記憶體峰值 MiB {measured.memory}",
        f"result {json.dumps({k: v for k, v in result.items() if k != 'guard_traffic'})}",
        f"coverage {json.dumps(measured.scan['coverage'])}",
        f"觀察 {len(measured.observations)}：{dict(measured.rules)}",
    ]
    for line in lines:
        print(f"[量測] {measured.label}：{line}")  # noqa: T201


def _record(measured: Measured, report: bytes | None) -> None:
    """SECSCAN_RECORD_DIR 有設定時，保存這個情境的輸出（人工審查之後才搬進 fixture）。

    只保存解析過的 run：沒有收集的 run 的 out/ 沒有遮罩，可能含靶機的 token（T16 的安全審查）。
    """
    root = os.environ.get("SECSCAN_RECORD_DIR")
    if not root or measured.engine.get("result") is None:
        return
    directory = Path(root) / measured.label
    directory.mkdir(parents=True, exist_ok=True)
    run = uuid.UUID(measured.run_id)
    files = {
        "manifest.json": volume_file(RUNS_VOLUME, f"{run}/manifest.json"),
        "zap.log": volume_file(RUNS_VOLUME, f"{run}/out/zap.log"),
        "telemetry.jsonl": volume_file(TELEMETRY_VOLUME, f"{run}.jsonl"),
        "summary.json": volume_file(TELEMETRY_VOLUME, f"{run}.summary.json"),
        "report.json": report,
    }
    for name, content in files.items():
        if content is not None:
            (directory / name).write_bytes(content)
    summary = {
        "engine": measured.engine,
        "coverage": measured.scan["coverage"],
        "budget_usage": measured.scan["budget_usage"],
        "observations": measured.observations,
        "seconds": round(measured.seconds),
        "memory": measured.memory,
    }
    (directory / "scan.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1) + "\n")


def _assert_invariants(measured: Measured, target: Target, definition: str) -> None:
    engine = measured.engine
    assert engine["plan_hash"] is not None
    assert SHA256.fullmatch(engine["plan_hash"])
    assert engine["profile_definition_sha256"] == definition
    hosts = {
        (entry.get("host"), entry.get("port")) for entry in measured.decisions if "host" in entry
    }
    assert hosts <= {(target.host, target.port)}, hosts
    result = engine["result"]
    assert result is not None
    assert result["traffic_verified"] is True
    traffic = result["guard_traffic"]
    assert traffic is not None
    assert traffic["forwarded"] > 0
    assert traffic["answered"] is not None
    observed = {(o["method"], o["path"]) for o in measured.observations}
    assert observed <= measured.forwarded(), observed - measured.forwarded()
    if measured.report_bytes is not None:
        assert measured.report_bytes <= MAX_REPORT_BYTES


# --- VAmPI ---------------------------------------------------------------------------------


@pytest.fixture(scope="class")
def vampi_vuln() -> Iterator[Target]:
    target = start_vampi(vulnerable=True)
    yield target
    stop_target(target)


class TestVampiVulnerable:
    def test_an_authenticated_api_scan(
        self, admin: Api, definitions: dict[str, str], vampi_vuln: Target
    ) -> None:
        wait_for_zap(admin)
        item, spec_id = _vampi_lab(admin, vampi_vuln)
        profile_id = _bearer(item, vampi_token(vampi_vuln), VAMPI_ME)

        measured = _run_scan(
            "vampi-vuln",
            item,
            vampi_vuln,
            "api_active_lab",
            spec_id=spec_id,
            auth_profile_id=profile_id,
        )

        assert measured.engine["status"] in {"succeeded", "timed_out"}, measured.engine
        _assert_invariants(measured, vampi_vuln, definitions["api_active_lab"])
        auth = measured.engine["result"]["guard_traffic"]["auth"]
        assert auth["accepted"] > 0
        assert auth["lost"] is False
        assert "AUTHENTICATION_LOST" not in measured.scan["coverage"]["limitations"]
        assert measured.scan["auth"]["preflight"] == "passed"
        # 已知正例：ZAP 送出了 SQLi 的探測，guard 以 PATH_AMBIGUOUS 拒絕（§15.10 的取捨）。這是平台
        # 造成的漏報：探測沒有到達靶機，沒有 SQLi 的觀察（量化與對照在 DECISIONS §20.6）。
        assert SQLI_PROBE in measured.denied("PATH_AMBIGUOUS")

    def test_the_plan_time_limit_keeps_the_observations(
        self, admin: Api, definitions: dict[str, str], vampi_vuln: Target
    ) -> None:
        """plan 的 maxDuration 是 180 - 60 = 120 秒（完整的掃描約 280 秒）：ZAP 被 plan 中斷、收集，
        不是 runner 的時間上限。

        第一次量測用 150 秒：當時 activeScan 自己的上限（1 分鐘）先到，AF 回報成功，截斷的掃描看起來
        是完整的；之後 job 的上限一律是 0，只由 plan 限制（DECISIONS §20.5）。
        """
        wait_for_zap(admin)
        item, spec_id = _vampi_lab(admin, vampi_vuln)

        measured = _run_scan(
            "vampi-timeout",
            item,
            vampi_vuln,
            "api_active_lab",
            spec_id=spec_id,
            budget={"max_duration_seconds": 180},
        )

        assert (measured.engine["status"], measured.engine["error_code"]) == (
            "timed_out",
            "ENGINE_TIMEOUT",
        ), measured.engine
        _assert_invariants(measured, vampi_vuln, definitions["api_active_lab"])
        assert measured.engine["result"]["time_limit_reached"] is True

    def test_cancelling_stops_the_scan(
        self, admin: Api, definitions: dict[str, str], vampi_vuln: Target
    ) -> None:
        wait_for_zap(admin)
        item, spec_id = _vampi_lab(admin, vampi_vuln)
        started = now()
        scan_id = item.scan("api_active_lab", spec_id=spec_id)
        container = _zap_container(scan_id)
        run_id = container.removeprefix("secscan-run-")

        def forwarded() -> bool:
            return any(
                entry.get("run_id") == run_id and entry["decision"] == "allow"
                for entry in requests_since(started)
            )

        wait_for(forwarded, timeout=180, interval=2)
        cancelled_at = now()
        item.operator.data("POST", f"/scans/{scan_id}/cancel")
        engine = item.finished_zap(scan_id, timeout=120)

        assert engine["status"] == "cancelled", engine
        assert SHA256.fullmatch(engine["plan_hash"] or "")
        assert engine["profile_definition_sha256"] == definitions["api_active_lab"]
        assert scan_containers(scan_id) == []
        late = [
            entry
            for entry in requests_since(cancelled_at + 15)
            if entry.get("run_id") == run_id and entry["decision"] == "allow"
        ]
        assert late == []
        print(f"[量測] vampi-cancel：{engine['status']}，取消後 {now() - cancelled_at:.0f} 秒結束")  # noqa: T201


@pytest.fixture(scope="class")
def vampi_secure() -> Iterator[Target]:
    target = start_vampi(vulnerable=False)
    yield target
    stop_target(target)


class TestVampiSecure:
    def test_the_same_scan_on_the_secure_build(
        self, admin: Api, definitions: dict[str, str], vampi_secure: Target
    ) -> None:
        wait_for_zap(admin)
        item, spec_id = _vampi_lab(admin, vampi_secure)
        profile_id = _bearer(item, vampi_token(vampi_secure), VAMPI_ME)

        measured = _run_scan(
            "vampi-secure",
            item,
            vampi_secure,
            "api_active_lab",
            spec_id=spec_id,
            auth_profile_id=profile_id,
        )

        assert measured.engine["status"] in {"succeeded", "timed_out"}, measured.engine
        _assert_invariants(measured, vampi_secure, definitions["api_active_lab"])
        # 負例：安全版沒有任何 active scan 規則的告警（只有 passive 的 header）。
        active = [o for o in measured.observations if o["source_rule"] in ACTIVE_RULES]
        assert active == []


# token 在掃描中途過期：preflight 與 openapi 的匯入在期限內，active scan 大多在期限之後。
SHORT_TOKEN_SECONDS = 90


@pytest.fixture(scope="class")
def vampi_short_token() -> Iterator[Target]:
    target = start_vampi(vulnerable=True, token_seconds=SHORT_TOKEN_SECONDS)
    yield target
    stop_target(target)


class TestTokenExpiry:
    def test_a_token_that_expires_mid_scan_is_disclosed(
        self, admin: Api, definitions: dict[str, str], vampi_short_token: Target
    ) -> None:
        wait_for_zap(admin)
        item, spec_id = _vampi_lab(admin, vampi_short_token)
        profile_id = _bearer(item, vampi_token(vampi_short_token), VAMPI_ME)

        measured = _run_scan(
            "vampi-token-expiry",
            item,
            vampi_short_token,
            "api_active_lab",
            spec_id=spec_id,
            auth_profile_id=profile_id,
        )

        assert measured.engine["status"] in {"succeeded", "timed_out"}, measured.engine
        _assert_invariants(measured, vampi_short_token, definitions["api_active_lab"])
        assert measured.scan["auth"]["preflight"] == "passed"
        auth = measured.engine["result"]["guard_traffic"]["auth"]
        assert auth["lost"] is True, auth
        coverage = measured.scan["coverage"]
        assert "AUTHENTICATION_LOST" in coverage["limitations"]
        # 失效之後的 token 打到公開端點仍是 200：不以已認證的數字呈現。
        assert coverage["authenticated_operations"] is None


# --- Juice Shop ----------------------------------------------------------------------------


@pytest.fixture(scope="class")
def juice_shop() -> Iterator[Target]:
    target = start_juice_shop()
    yield target
    stop_target(target)


class TestJuiceShop:
    def test_an_anonymous_web_scan(
        self, admin: Api, definitions: dict[str, str], juice_shop: Target
    ) -> None:
        wait_for_zap(admin)
        item = lab(
            admin,
            kind="web",
            paths=None,
            host=juice_shop.host,
            ip=juice_shop.ip,
            port=juice_shop.port,
        )

        measured = _run_scan("juice-shop", item, juice_shop, "web_active_lab")

        assert measured.engine["status"] in {"succeeded", "timed_out"}, measured.engine
        _assert_invariants(measured, juice_shop, definitions["web_active_lab"])

    def test_an_authenticated_web_scan(
        self, admin: Api, definitions: dict[str, str], juice_shop: Target
    ) -> None:
        wait_for_zap(admin)
        item = lab(
            admin,
            kind="web",
            paths=None,
            host=juice_shop.host,
            ip=juice_shop.ip,
            port=juice_shop.port,
        )
        profile_id = _bearer(item, juice_shop_token(juice_shop), JUICE_SHOP_ADDRESSES)

        measured = _run_scan(
            "juice-shop-bearer",
            item,
            juice_shop,
            "web_active_lab",
            auth_profile_id=profile_id,
            budget={"max_duration_seconds": 900},
        )

        assert measured.engine["status"] in {"succeeded", "timed_out"}, measured.engine
        _assert_invariants(measured, juice_shop, definitions["web_active_lab"])
        assert measured.scan["auth"]["preflight"] == "passed"
        assert measured.engine["result"]["guard_traffic"]["auth"]["accepted"] > 0

    def test_the_rest_search_api_scan(
        self, admin: Api, definitions: dict[str, str], juice_shop: Target
    ) -> None:
        """已知正例：q 的 SQLi（S104）。query 參數不受 path 的 % 規則影響。"""
        wait_for_zap(admin)
        item = lab(
            admin,
            kind="api",
            paths=[SEARCH_PATH],
            methods=["GET"],
            host=juice_shop.host,
            ip=juice_shop.ip,
            port=juice_shop.port,
        )
        spec = item.operator.data(
            "POST",
            f"/targets/{item.target_id}/api-specs",
            raw=json.dumps(SEARCH_SPEC).encode(),
            content_type="application/json",
        )

        measured = _run_scan(
            "juice-shop-search", item, juice_shop, "api_active_lab", spec_id=str(spec["id"])
        )

        assert measured.engine["status"] in {"succeeded", "timed_out"}, measured.engine
        _assert_invariants(measured, juice_shop, definitions["api_active_lab"])
        sqli = [
            o
            for o in measured.observations
            if o["source_rule"] == "40018" and o["path"] == SEARCH_PATH and o["parameter"] == "q"
        ]
        assert sqli, measured.rules
