"""T19：同一個 scan 以真的 ZAP 與 Nuclei 掃自製的 fixture app，worker 把觀察連結到 finding
（docs/DECISIONS.md §25；make test-live-fixture-findings）。

fixture app 在 live 自己的 lab 網路上、一次一個（lab_support.start_fixture）。這裡驗證整條路徑
（API → 兩個引擎依序共用預算 → worker 解析與連結 → GET findings），規則依使用者的簽核
（2026-11-04，docs/DECISIONS.md §25.14）：
- 弱點版：缺 CSP／XCTO／anti-clickjacking 的 header 以 ZAP 為準，nuclei 在同一次 scan 的同一個位置
  佐證時併入同一個 finding，等級是兩者正規化之後的最高值並標衝突。CORS 兩個工具偵測的行為不同
  （ZAP 看到 `*`、nuclei 看到反射任意 Origin 並允許 credentials），同一個位置各自一個 finding、互相
  標示相關。
- 每個觀察恰好連結一次；只有佐證的 header 群組會有兩個引擎的來源；fallback 永遠單一引擎。
- 修補版：沒有任何 CORS 的 finding。
量測機制與 T16／T18 相同（plan_hash、和 /scan-profiles 相同的定義、observed ⊆ forwarded、guard 只
看到 target），每個引擎各檢查一次。SECSCAN_RECORD_DIR 有設定時錄製到 recordings/fixture-findings/。
"""

import json
import os
import time
import uuid
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from tests.live.lab_support import Target, start_fixture, stop_target
from tests.live.support import Api, admin_key, scan_containers, wait_for
from tests.live.test_lab_zap_live import Measured, _assert_invariants
from tests.live.zap_support import RUN_TIMEOUT, Lab, lab, now, requests_since, wait_for_zap

pytestmark = [pytest.mark.live, pytest.mark.enable_socket]

WEB_METHODS = ["GET", "HEAD", "POST"]
ENGINES = ("zap", "nuclei")
PROFILE = "web_active_lab"
ZAP_CORS = "zap-cors-wildcard-origin"
NUCLEI_CORS = "nuclei-cors-arbitrary-origin-with-credentials"
# 審查過的跨引擎群組（rule_groups.yaml；只有它們可能有兩個引擎的來源）。
CROSS_ENGINE_GROUPS = frozenset(
    {"csp-header-missing", "x-content-type-options-missing", "anti-clickjacking-header-missing"}
)
SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
TERMINAL_SCANS = {"completed", "partially_completed", "failed", "timed_out", "cancelled"}
TERMINAL_SCANS |= {"interrupted"}


@dataclass(frozen=True)
class Combined:
    label: str
    scan: dict[str, Any]
    runs: dict[str, Measured]
    findings: list[dict[str, Any]]
    seconds: float

    def finding(self, group: str, route: str = "/") -> dict[str, Any] | None:
        matches = [
            item
            for item in self.findings
            if item["rule_group"] == group and item["location"]["route"] == route
        ]
        assert len(matches) <= 1, matches
        return matches[0] if matches else None


@pytest.fixture(scope="module")
def admin() -> Api:
    return Api(admin_key())


@pytest.fixture(scope="module")
def definitions(admin: Api) -> dict[str, str]:
    """/scan-profiles 的 zap 與 nuclei 定義：先等 runner 的 probe 通過（清單才會列出引擎）。"""
    wait_for_zap(admin)
    profiles = admin.data("GET", "/scan-profiles")
    return {
        engine["engine"]: engine["definition_sha256"]
        for item in profiles
        if item["profile"] == PROFILE
        for engine in item["engines"]
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


def _create(item: Lab) -> str:
    status, payload = item.operator.call(
        "POST",
        "/scans",
        {
            "target_id": item.target_id,
            "scope_grant_id": item.grant_id,
            "api_spec_id": None,
            "auth_profile_id": None,
            "profile": PROFILE,
            "engines": list(ENGINES),
            "budget": {},
        },
        headers={"Idempotency-Key": str(uuid.uuid4())},
    )
    assert status == 202, (status, payload.get("error"))
    return str(payload["data"]["id"])


def _container(scan_id: str, engine: str) -> str:
    """nuclei 在 zap 結束之後才開始：等它的容器出現（容器存在的時間遠長於輪詢的間隔）。"""

    def find() -> str | None:
        names = scan_containers(scan_id, engine)
        return names[0] if names else None

    return wait_for(find, timeout=RUN_TIMEOUT, interval=2)


def _pages(item: Lab, path: str) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    page = 1
    separator = "&" if "?" in path else "?"
    while True:
        status, payload = item.operator.call("GET", f"{path}{separator}limit=100&page={page}")
        assert status == 200, payload
        collected += payload["data"]
        if len(collected) >= payload["meta"]["total"] or not payload["data"]:
            return collected
        page += 1


def _run(label: str, item: Lab) -> Combined:
    started, clock = now(), time.monotonic()
    scan_id = _create(item)
    containers = {engine: _container(scan_id, engine) for engine in ENGINES}

    def finished() -> dict[str, Any] | None:
        scan = item.operator.data("GET", f"/scans/{scan_id}")
        return dict(scan) if scan["status"] in TERMINAL_SCANS else None

    scan = wait_for(finished, timeout=RUN_TIMEOUT, interval=3)
    decisions = requests_since(started)
    seconds = time.monotonic() - clock
    runs = {
        engine: Measured(
            label=f"{label}-{engine}",
            scan_id=scan_id,
            run_id=containers[engine].removeprefix("secscan-run-"),
            engine=next(run for run in scan["engines"] if run["engine"] == engine),
            scan=scan,
            observations=_pages(item, f"/scans/{scan_id}/observations?engine={engine}"),
            decisions=decisions,
            seconds=seconds,
            report_bytes=None,
            memory={},
        )
        for engine in ENGINES
    }
    combined = Combined(
        label=label,
        scan=scan,
        runs=runs,
        findings=_pages(item, f"/scans/{scan_id}/findings"),
        seconds=seconds,
    )
    _print(combined)
    _record(combined)
    return combined


def _engines(finding: dict[str, Any]) -> set[str]:
    return {source["engine"] for source in finding["sources"]}


def _print(combined: Combined) -> None:
    lines = [f"scan {combined.scan['status']}，{combined.seconds:.0f} 秒"]
    for engine, measured in combined.runs.items():
        result = measured.engine.get("result") or {}
        traffic = result.get("guard_traffic") or {}
        lines.append(
            f"{engine} {measured.engine['status']} {measured.engine['error_code']}，"
            f"觀察 {len(measured.observations)}，forwarded {traffic.get('forwarded')}，"
            f"exhausted {traffic.get('exhausted')}"
        )
    kinds = Counter(item["kind"] for item in combined.findings)
    lines.append(f"finding {len(combined.findings)}（依 kind）{dict(kinds)}")
    for item in combined.findings:
        sources = ", ".join(
            f"{s['engine']}:{s['source_rule']}:{s['rule_variant']}"
            f"={s['raw_severity']} x{s['observations']}"
            for s in item["sources"]
        )
        lines.append(
            f"  {item['normalized_severity']:<6} conflict={item['severity_conflict']!s:<5} "
            f"{item['category']:<16} {item['rule_group']} "
            f"{item['location']['method']} {item['location']['route']} "
            f"{item['owasp']['top10_2025']} [{sources}]"
        )
    for line in lines:
        print(f"[量測] {combined.label}：{line}")  # noqa: T201


def _record(combined: Combined) -> None:
    root = os.environ.get("SECSCAN_RECORD_DIR")
    if not root:
        return
    directory = Path(root) / combined.label
    directory.mkdir(parents=True, exist_ok=True)
    document = {
        "scan": combined.scan,
        "observations": {engine: run.observations for engine, run in combined.runs.items()},
        "findings": combined.findings,
        "seconds": round(combined.seconds),
    }
    (directory / "findings.json").write_text(
        json.dumps(document, ensure_ascii=False, indent=1) + "\n"
    )


def _assert_common(combined: Combined, target: Target, definitions: dict[str, str]) -> None:
    for engine, measured in combined.runs.items():
        assert measured.engine["status"] in {"succeeded", "timed_out"}, measured.engine
        _assert_invariants(measured, target, definitions[engine])
        traffic = measured.engine["result"]["guard_traffic"]
        # 兩個引擎依序共用 scan 的預算：保守的預設值足夠跑完兩者。
        assert traffic["exhausted"] is False, (engine, traffic)
    observations = sum(len(run.observations) for run in combined.runs.values())
    linked = sum(source["observations"] for item in combined.findings for source in item["sources"])
    # 每個觀察恰好連結一次（同一個 target 第一次掃描：所有來源都在這個 scan）。
    assert linked == observations, (linked, observations)
    for item in combined.findings:
        severities = {source["normalized_severity"] for source in item["sources"]}
        assert item["normalized_severity"] == max(severities, key=SEVERITY_ORDER.index), item
        assert item["severity_conflict"] is (len(severities) > 1), item
        if len(_engines(item)) > 1:
            assert item["rule_group"] in CROSS_ENGINE_GROUPS, item
        if item["category"] == "unclassified":
            assert len(_engines(item)) == 1, item
            assert item["needs_review"] is True, item


class TestFixtureVulnerable:
    @pytest.fixture(scope="class")
    def vuln(self) -> Iterator[Target]:
        target = start_fixture(vulnerable=True)
        yield target
        stop_target(target)

    def test_corroborated_hits_merge_and_cors_stays_related(
        self, admin: Api, definitions: dict[str, str], vuln: Target
    ) -> None:
        item = _web_lab(admin, vuln)

        combined = _run("fixture-findings-vuln", item)

        _assert_common(combined, vuln, definitions)
        zap_cors, nuclei_cors = combined.finding(ZAP_CORS), combined.finding(NUCLEI_CORS)
        assert zap_cors is not None, [f["rule_group"] for f in combined.findings]
        assert nuclei_cors is not None, [f["rule_group"] for f in combined.findings]
        # 偵測的行為不同：各自一個 finding、只有自己的引擎，互相標示相關，不合併也不升級。
        assert (_engines(zap_cors), _engines(nuclei_cors)) == ({"zap"}, {"nuclei"})
        assert zap_cors["related_finding_ids"] == [nuclei_cors["id"]]
        assert nuclei_cors["related_finding_ids"] == [zap_cors["id"]]
        assert (zap_cors["normalized_severity"], zap_cors["severity_conflict"]) == ("medium", False)
        assert (nuclei_cors["normalized_severity"], nuclei_cors["category"]) == (
            "info",
            "vulnerability",
        )
        # 保留原始 CWE：ZAP 的 CWE-264 不在 Top 10:2025 的清單；nuclei 群組取模板分類的 CWE-942。
        assert (zap_cors["cwe_ids"], zap_cors["owasp"]["top10_2025_unmapped_reason"]) == (
            ["CWE-264"],
            "cwe_not_listed",
        )
        assert (nuclei_cors["cwe_ids"], nuclei_cors["tool_cwe_ids"]) == (["CWE-942"], ["CWE-346"])
        assert nuclei_cors["owasp"]["top10_2025"] == "A02:2025"
        assert {zap_cors["owasp"]["api_2023"], nuclei_cors["owasp"]["api_2023"]} == {"API8:2023"}
        assert (zap_cors["auth_role"], zap_cors["auth_verified"]) == ("anonymous", True)
        # 缺安全 header 的群組：兩個工具都在 GET / 回報時，nuclei 的佐證併入 ZAP 的 finding。
        merged = 0
        for group in CROSS_ENGINE_GROUPS:
            finding = combined.finding(group)
            if finding is not None and _hit_by_both(combined, group):
                assert _engines(finding) == {"zap", "nuclei"}, (group, finding["sources"])
                assert finding["severity_conflict"] is True
                merged += 1
        assert merged >= 1


class TestFixtureSecure:
    @pytest.fixture(scope="class")
    def secure(self) -> Iterator[Target]:
        target = start_fixture(vulnerable=False)
        yield target
        stop_target(target)

    def test_the_patched_build_has_no_cors_finding(
        self, admin: Api, definitions: dict[str, str], secure: Target
    ) -> None:
        item = _web_lab(admin, secure)

        combined = _run("fixture-findings-secure", item)

        _assert_common(combined, secure, definitions)
        assert not [f for f in combined.findings if f["rule_group"] in {ZAP_CORS, NUCLEI_CORS}]


_MEMBERS = {
    "csp-header-missing": {("zap", "10038"), ("nuclei", "http-missing-security-headers")},
    "x-content-type-options-missing": {
        ("zap", "10021"),
        ("nuclei", "http-missing-security-headers"),
    },
    "anti-clickjacking-header-missing": {
        ("zap", "10020"),
        ("nuclei", "http-missing-security-headers"),
    },
}
_VARIANTS = {
    "csp-header-missing": {"10038-1", "content-security-policy"},
    "x-content-type-options-missing": {"10021", "x-content-type-options"},
    "anti-clickjacking-header-missing": {"10020-1", "x-frame-options"},
}


def _hit_by_both(combined: Combined, group: str) -> bool:
    """兩個引擎都在 GET / 回報了這個群組的成員（觀察本身，與連結的結果無關）。"""
    engines = set()
    for engine, run in combined.runs.items():
        for observation in run.observations:
            key = (engine, observation["source_rule"])
            if (
                key in _MEMBERS[group]
                and observation["rule_variant"] in _VARIANTS[group]
                and (observation["method"], observation["path"]) == ("GET", "/")
            ):
                engines.add(engine)
    return engines == {"zap", "nuclei"}
