"""T19：同一個 scan 以真的 ZAP 與 Nuclei 掃自製的 fixture app，worker 把觀察連結到 finding
（docs/DECISIONS.md §25；make test-live-fixture-findings）。

fixture app 在 live 自己的 lab 網路上、一次一個（lab_support.start_fixture）。T18 的實證：弱點版的
GET / 上，ZAP 10098 與 nuclei cors-misconfig 對同一個 CORS 政策同時命中，等級不一致（Medium 對
info）。這裡驗證整條路徑（API → 兩個引擎依序共用預算 → worker 解析與連結 → GET findings）：
- 弱點版：CORS 是一個 finding、有兩個引擎的來源，等級是兩者正規化之後的最高值並標衝突，對應
  A02:2025（official）與 API8:2023（curated）。
- 每個觀察恰好連結一次；只有審查過的跨引擎群組會有兩個引擎的來源；fallback 永遠單一引擎。
- 修補版：沒有 CORS 的 finding。
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
CORS_GROUP = "cors-permissive-policy"
# 審查過的跨引擎群組（rule_groups.yaml；只有它們可能有兩個引擎的來源）。
CROSS_ENGINE_GROUPS = frozenset(
    {
        CORS_GROUP,
        "csp-header-missing",
        "x-content-type-options-missing",
        "anti-clickjacking-header-missing",
    }
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
            f"{item['rule_group']} {item['location']['method']} {item['location']['route']} "
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
        if ":" in item["rule_group"]:
            assert len(_engines(item)) == 1, item
            assert item["needs_review"] is True, item


class TestFixtureVulnerable:
    @pytest.fixture(scope="class")
    def vuln(self) -> Iterator[Target]:
        target = start_fixture(vulnerable=True)
        yield target
        stop_target(target)

    def test_co_located_hits_become_one_finding(
        self, admin: Api, definitions: dict[str, str], vuln: Target
    ) -> None:
        item = _web_lab(admin, vuln)

        combined = _run("fixture-findings-vuln", item)

        _assert_common(combined, vuln, definitions)
        cors = combined.finding(CORS_GROUP)
        assert cors is not None, [f["rule_group"] for f in combined.findings]
        assert _engines(cors) == {"zap", "nuclei"}, cors["sources"]
        # 兩個工具同時命中不提高等級：最高值是 ZAP 的 medium（nuclei 是 info），標成衝突。
        assert (cors["normalized_severity"], cors["severity_conflict"]) == ("medium", True)
        assert cors["cwe_ids"] == ["CWE-942"]
        assert cors["owasp"] == {
            "top10_2025": "A02:2025",
            "top10_2025_source": "official",
            "api_2023": "API8:2023",
            "api_2023_source": "curated",
        }
        assert (cors["kind"], cors["auth_role"], cors["auth_verified"]) == (
            "security",
            "anonymous",
            True,
        )
        # 缺安全 header 的群組：兩個工具都在 GET / 回報時是同一個 finding。
        for group in CROSS_ENGINE_GROUPS - {CORS_GROUP}:
            finding = combined.finding(group)
            if finding is not None and _hit_by_both(combined, group):
                assert _engines(finding) == {"zap", "nuclei"}, (group, finding["sources"])


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
        assert not [f for f in combined.findings if f["rule_group"] == CORS_GROUP]


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
