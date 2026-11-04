"""GET /api/v1/scans/{id}/findings（T19；docs/API_CONTRACT.md §17.9）。

列的內容以 SQL 寫入：連結的流程在 test_finding_linker.py 與 test_worker_*.py，這裡只驗證 API。
跨 project 與不存在的一樣回 404（SEC-16）；sources 只有這個 scan 的來源；沒有 CVE／CVSS 欄位。
"""

from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from secscan.api_keys.domain import Role
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.targets.domain import Target
from tests.integration.api_support import Caller, Seeder, World
from tests.integration.finding_support import link_by_sql, web_scan, web_target

pytestmark = pytest.mark.integration

SCANS = "/api/v1/scans"
SHA = "ab" * 32
INSERT_OBSERVATION = (
    "INSERT INTO observations (scanner_run_id, scan_id, ordinal, source_event_id, source_index, "
    "source_rule, rule_variant, title, raw_severity, severity_label, raw_confidence, "
    "confidence_label, cwe_id, method, path, parameter_location, auth_role, parser_version) "
    "VALUES (:run, :scan, :ordinal, :event, 0, :rule, :variant, 'title', :severity, :label, "
    ":confidence, 'Medium', :cwe, 'GET', '/', 'unknown', 'anonymous', 'test/1') RETURNING id"
)
INSERT_FINDING = (
    "INSERT INTO findings (target_id, fingerprint, kind, category, rule_group, title, method, "
    "route, "
    "route_source, auth_role, auth_verified, normalized_severity, severity_conflict, "
    "needs_review, cwe_id, cwe_source, owasp_top10_2025, owasp_top10_2025_source, "
    "owasp_api_2023, owasp_api_2023_source, mapping_version, taxonomy_sha256, "
    "first_seen_run_id, first_seen_scan_id, last_seen_run_id, last_seen_scan_id) VALUES "
    "(:target, :fingerprint, :kind, :category, :group, :title, 'GET', :route, 'literal', "
    "'anonymous', true, "
    ":severity, :conflict, :review, :cwe, :cwe_source, :top10, :top10_source, :api, "
    ":api_source, 'rules-1', :sha, :run, :scan, :run, :scan) RETURNING id"
)


class Scan:
    """一個 web scan（zap 與 nuclei 兩個 run），以 SQL 寫入觀察與 finding。

    after：同一個 target 的下一次 scan（先結束前一次；一個 target 同時只有一個進行中的 scan）。
    finding 與連結的觀察必須屬於同一個 target（v0015 的 trigger）。
    """

    def __init__(self, seed: Seeder, world: World, after: "Scan | None" = None) -> None:
        if after is None:
            target, grant_id = web_target(seed, world)
        else:
            after.finish()
            target, grant_id = after.target, after.grant_id
        self.seed = seed
        self.target: Target = target
        self.grant_id: UUID = grant_id
        self.target_id = target.id
        self.id = web_scan(seed, world, target, grant_id, (ScanEngine.ZAP, ScanEngine.NUCLEI))
        rows = seed.query("SELECT id, engine FROM scanner_runs WHERE scan_id = :id", id=self.id)
        self.runs = {row.engine: row.id for row in rows}
        self._ordinal = 0

    def finish(self) -> None:
        """模擬 scan 已結束（佇列的轉換由 queue 的測試負責）。"""
        self.seed.execute(
            "UPDATE scanner_runs SET status = 'cancelled', finished_at = now() "
            "WHERE scan_id = :id AND status = 'queued'",
            id=self.id,
        )
        self.seed.execute(
            "UPDATE scans SET status = 'cancelled', cancel_requested_at = now(), "
            "finished_at = now() WHERE id = :id",
            id=self.id,
        )

    def observe(
        self,
        engine: str,
        rule: str,
        variant: str | None,
        severity: str,
        label: str,
        cwe: int | None,
    ) -> UUID:
        self._ordinal += 1
        [row] = self.seed.query(
            INSERT_OBSERVATION,
            run=self.runs[engine],
            scan=self.id,
            ordinal=self._ordinal,
            event=uuid4().hex * 2,
            rule=rule,
            variant=variant,
            severity=severity,
            label=label,
            confidence="2" if engine == "zap" else "unknown",
            cwe=cwe,
        )
        return UUID(str(row.id))

    def finding(self, group: str, severity: str, **over: Any) -> UUID:
        params: dict[str, Any] = {
            "target": self.target_id,
            "fingerprint": uuid4().hex * 2,
            "kind": "security",
            "category": "misconfiguration",
            "route": "/",
            "group": group,
            "title": f"title of {group}",
            "severity": severity,
            "conflict": False,
            "review": False,
            "cwe": None,
            "cwe_source": None,
            "top10": None,
            "top10_source": "none",
            "api": None,
            "api_source": "none",
            "sha": SHA,
            "run": self.runs["zap"],
            "scan": self.id,
        }
        params.update(over)
        [row] = self.seed.query(INSERT_FINDING, **params)
        return UUID(str(row.id))

    def link(self, finding: UUID, observation: UUID, severity: str, confidence: str) -> None:
        link_by_sql(
            self.seed, finding, observation, severity=severity, confidence=confidence, sha=SHA
        )


def _list(client: TestClient, caller: Caller, scan_id: object, query: str = "") -> Any:
    return client.get(f"{SCANS}/{scan_id}/findings{query}", headers=caller.headers)


def _xcto(scan: Scan) -> UUID:
    """同一次 scan 的佐證合併（§25.14）：ZAP 10021 兩次（Low）與 nuclei 的 XCTO（info）。"""
    finding = scan.finding(
        "x-content-type-options-missing",
        "low",
        conflict=True,
        cwe=693,
        cwe_source="rule_group",
        top10="A06:2025",
        top10_source="official",
        api="API8:2023",
        api_source="curated",
    )
    for _ in range(2):
        observed = scan.observe("zap", "10021", "10021", "1", "Low", 693)
        scan.link(finding, observed, "low", "medium")
    nuclei = scan.observe(
        "nuclei",
        "http-missing-security-headers",
        "x-content-type-options",
        "info",
        "Informational",
        693,
    )
    scan.link(finding, nuclei, "info", "unknown")
    return finding


def test_findings_are_listed_with_mapping_and_sources(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    scan = Scan(seed, world)
    finding = _xcto(scan)

    response = _list(api_client, world.viewer_a, scan.id)

    assert response.status_code == 200
    body = response.json()
    assert body["meta"] == {"page": 1, "limit": 25, "total": 1}
    [item] = body["data"]
    assert item.pop("created_at").endswith("Z")
    assert item.pop("last_seen_at").endswith("Z")
    assert item == {
        "id": str(finding),
        "target_id": str(scan.target_id),
        "kind": "security",
        "category": "misconfiguration",
        "rule_group": "x-content-type-options-missing",
        "title": "title of x-content-type-options-missing",
        "normalized_severity": "low",
        "scan_severity": "low",
        "severity_conflict": True,
        "needs_review": False,
        "cwe_ids": ["CWE-693"],
        "cwe_source": "rule_group",
        "tool_cwe_ids": ["CWE-693"],
        "location": {
            "method": "GET",
            "route": "/",
            "route_source": "literal",
            "parameter_location": None,
            "parameter_name": None,
            "resource": None,
        },
        "auth_role": "anonymous",
        "auth_verified": True,
        "owasp": {
            "top10_2025": "A06:2025",
            "top10_2025_source": "official",
            "top10_2025_unmapped_reason": None,
            "api_2023": "API8:2023",
            "api_2023_source": "curated",
            "api_2023_unmapped_reason": None,
        },
        "mapping_version": "rules-1",
        "triage_state": "unreviewed",
        "lifecycle_state": "open",
        "first_seen_scan_id": str(scan.id),
        "last_seen_scan_id": str(scan.id),
        # 各來源的原值並列（等級衝突的依據）；同一個來源的觀察合計。
        "sources": [
            {
                "engine": "zap",
                "source_rule": "10021",
                "rule_variant": "10021",
                "raw_severity": "1",
                "severity_label": "Low",
                "normalized_severity": "low",
                "raw_confidence": "2",
                "confidence_label": "Medium",
                "normalized_confidence": "medium",
                "cwe_id": 693,
                "observations": 2,
            },
            {
                "engine": "nuclei",
                "source_rule": "http-missing-security-headers",
                "rule_variant": "x-content-type-options",
                "raw_severity": "info",
                "severity_label": "Informational",
                "normalized_severity": "info",
                "raw_confidence": "unknown",
                "confidence_label": "Medium",
                "normalized_confidence": "unknown",
                "cwe_id": 693,
                "observations": 1,
            },
        ],
        "related_finding_ids": [],
    }


def test_findings_are_ordered_by_severity_then_group(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    scan = Scan(seed, world)
    for group, severity in (("b-group", "low"), ("a-group", "low"), ("c-group", "high")):
        finding = scan.finding(group, severity)
        raw = {"low": "1", "high": "3"}[severity]
        scan.link(finding, scan.observe("zap", "1", None, raw, "x", None), severity, "medium")

    body = _list(api_client, world.viewer_a, scan.id).json()

    assert [item["rule_group"] for item in body["data"]] == ["c-group", "a-group", "b-group"]


def test_within_a_severity_security_comes_first(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    """工具標 info 的高風險項目（Werkzeug debugger）不排在技術識別之後（安全審查）。"""
    scan = Scan(seed, world)
    tech = scan.finding(
        "nuclei-tech-detect/python", "info", kind="informational", category="technology"
    )
    observed = scan.observe("nuclei", "tech-detect", "python", "info", "Info", None)
    scan.link(tech, observed, "info", "unknown")
    debugger = scan.finding("nuclei-werkzeug-debugger-detected", "info", review=True)
    observed = scan.observe("nuclei", "werkzeug-debugger-detect", None, "info", "Info", None)
    scan.link(debugger, observed, "info", "unknown")

    body = _list(api_client, world.viewer_a, scan.id).json()

    assert [item["rule_group"] for item in body["data"]] == [
        "nuclei-werkzeug-debugger-detected",
        "nuclei-tech-detect/python",
    ]


def _three(scan: Scan) -> None:
    _xcto(scan)
    sqli = scan.finding("zap-sql-injection", "high", category="vulnerability")
    scan.link(sqli, scan.observe("zap", "40018", "40018", "3", "High", 89), "high", "low")
    unknown = scan.finding(
        UNKNOWN, "info", kind="informational", category="unclassified", review=True
    )
    observed = scan.observe("nuclei", "unknown-template", None, "info", "Info", None)
    scan.link(unknown, observed, "info", "unknown")


UNKNOWN = "nuclei:unknown-template"
XCTO = "x-content-type-options-missing"


@pytest.mark.parametrize(
    ("query", "groups"),
    [
        ("?kind=informational", [UNKNOWN]),
        ("?severity=high", ["zap-sql-injection"]),
        # 引擎：這個引擎在這個 scan 中有來源的 finding（sources 仍列出全部來源）。
        ("?engine=nuclei", [XCTO, UNKNOWN]),
        ("?engine=zap", ["zap-sql-injection", XCTO]),
        ("?triage_state=unreviewed&severity=low", [XCTO]),
        ("?triage_state=confirmed", []),
        # 分類與需要確認：fallback（unclassified）在人工確認前分開統計（使用者簽核）。
        ("?category=vulnerability", ["zap-sql-injection"]),
        ("?category=unclassified", [UNKNOWN]),
        ("?needs_review=true", [UNKNOWN]),
        ("?needs_review=false", ["zap-sql-injection", XCTO]),
    ],
)
def test_filters(
    api_client: TestClient, seed: Seeder, world: World, query: str, groups: list[str]
) -> None:
    scan = Scan(seed, world)
    _three(scan)

    body = _list(api_client, world.viewer_a, scan.id, query).json()

    assert [item["rule_group"] for item in body["data"]] == groups
    assert body["meta"]["total"] == len(groups)


def test_the_engine_filter_keeps_every_source(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    scan = Scan(seed, world)
    _xcto(scan)

    [item] = _list(api_client, world.viewer_a, scan.id, "?engine=nuclei").json()["data"]

    assert [source["engine"] for source in item["sources"]] == ["zap", "nuclei"]


def test_pages(api_client: TestClient, seed: Seeder, world: World) -> None:
    scan = Scan(seed, world)
    _three(scan)

    body = _list(api_client, world.viewer_a, scan.id, "?page=2&limit=2").json()

    assert body["meta"] == {"page": 2, "limit": 2, "total": 3}
    assert [item["rule_group"] for item in body["data"]] == [UNKNOWN]


@pytest.mark.parametrize(
    "query",
    [
        "?limit=101",
        "?page=0",
        "?kind=finding",
        "?severity=severe",
        "?engine=burp",
        "?triage_state=x",
        "?category=fixed",
        "?needs_review=maybe",
    ],
)
def test_invalid_queries_are_rejected(
    api_client: TestClient, seed: Seeder, world: World, query: str
) -> None:
    scan = Scan(seed, world)

    response = _list(api_client, world.viewer_a, scan.id, query)

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_REQUEST"


def test_only_this_scans_findings_and_sources(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    """另一個 scan 的觀察連結到的 finding 不列出；同一個 finding 的來源只算這個 scan 的。"""
    first = Scan(seed, world)
    shared = _xcto(first)
    second = Scan(seed, world, after=first)
    observed = second.observe("zap", "10021", "10021", "1", "Low", 693)
    second.link(shared, observed, "low", "medium")
    _xcto(second)

    first_body = _list(api_client, world.viewer_a, first.id).json()
    second_body = _list(api_client, world.viewer_a, second.id).json()

    assert [item["id"] for item in first_body["data"]] == [str(shared)]
    assert [s["observations"] for s in first_body["data"][0]["sources"]] == [2, 1]
    listed = {item["id"]: item for item in second_body["data"]}
    assert str(shared) in listed
    assert [s["observations"] for s in listed[str(shared)]["sources"]] == [1]


def test_scan_severity_is_this_scans_highest_source(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    """finding 的等級是所有掃描的最高值；scan_severity 只看這個 scan 的來源（安全審查）。"""
    first = Scan(seed, world)
    sqli = first.finding("zap-sql-injection", "high", conflict=True)
    first.link(sqli, first.observe("zap", "40018", "40018", "3", "High", 89), "high", "low")
    second = Scan(seed, world, after=first)
    second.link(sqli, second.observe("zap", "40018", "40018", "2", "Medium", 89), "medium", "low")

    [item] = _list(api_client, world.viewer_a, second.id, "?severity=high").json()["data"]

    assert (item["normalized_severity"], item["scan_severity"]) == ("high", "medium")
    assert [source["raw_severity"] for source in item["sources"]] == ["2"]


def test_related_findings_are_listed_but_not_merged(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    """CORS 兩個工具偵測的行為不同（使用者簽核）：同一個位置各自一個 finding，互相列出 id。"""
    scan = Scan(seed, world)
    cors = {"api": "API8:2023", "api_source": "curated"}
    zap = scan.finding(
        "zap-cors-wildcard-origin", "medium", cwe=264, cwe_source="rule_group", **cors
    )
    scan.link(zap, scan.observe("zap", "10098", "10098", "2", "Medium", 264), "medium", "medium")
    nuclei_group = "nuclei-cors-arbitrary-origin-with-credentials"
    mapped = {"top10": "A02:2025", "top10_source": "official", **cors}
    nuclei = scan.finding(
        nuclei_group, "info", category="vulnerability", cwe=942, cwe_source="rule_group", **mapped
    )
    observed = scan.observe("nuclei", "cors-misconfig", "arbitrary-origin", "info", "Info", 346)
    scan.link(nuclei, observed, "info", "unknown")
    # 不同位置的相關群組不列出。
    elsewhere = scan.finding(nuclei_group, "info", category="vulnerability", route="/api")
    observed = scan.observe("nuclei", "cors-misconfig", "arbitrary-origin", "info", "Info", 346)
    scan.link(elsewhere, observed, "info", "unknown")

    body = _list(api_client, world.viewer_a, scan.id).json()
    items = {item["id"]: item for item in body["data"]}

    assert items[str(zap)]["related_finding_ids"] == [str(nuclei)]
    assert items[str(nuclei)]["related_finding_ids"] == [str(zap)]
    assert items[str(elsewhere)]["related_finding_ids"] == []
    # 保留原始 CWE、交代未對應的原因：CWE-264 不在 Top 10:2025 的清單。
    assert items[str(zap)]["owasp"]["top10_2025_unmapped_reason"] == "cwe_not_listed"
    assert (items[str(nuclei)]["cwe_ids"], items[str(nuclei)]["tool_cwe_ids"]) == (
        ["CWE-942"],
        ["CWE-346"],
    )


def test_unmapped_items_say_why(api_client: TestClient, seed: Seeder, world: World) -> None:
    scan = Scan(seed, world)
    finding = scan.finding(
        "zap-modern-web-application", "info", kind="informational", category="technology"
    )
    observed = scan.observe("zap", "10109", "10109", "0", "Info", None)
    scan.link(finding, observed, "info", "medium")

    [item] = _list(api_client, world.viewer_a, scan.id).json()["data"]

    assert (item["cwe_ids"], item["tool_cwe_ids"]) == ([], [])
    assert item["owasp"] == {
        "top10_2025": None,
        "top10_2025_source": "none",
        "top10_2025_unmapped_reason": "no_cwe",
        "api_2023": None,
        "api_2023_source": "none",
        "api_2023_unmapped_reason": "not_curated",
    }


def test_a_scan_without_findings_is_an_empty_list(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    scan = Scan(seed, world)

    body = _list(api_client, world.viewer_a, scan.id).json()

    assert (body["data"], body["meta"]["total"]) == ([], 0)


def test_another_projects_scan_is_not_found(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    """SEC-16：B 的 key 讀 A 的 scan 的 finding，和不存在的 scan 一樣 404、沒有資訊洩漏。"""
    scan = Scan(seed, world)
    _xcto(scan)
    other = seed.member(world.admin, world.project_b.id, Role.VIEWER)

    foreign = _list(api_client, other, scan.id)
    missing = _list(api_client, other, uuid4())

    assert foreign.status_code == missing.status_code == 404
    strip = ("request_id",)
    assert {k: v for k, v in foreign.json()["error"].items() if k not in strip} == {
        k: v for k, v in missing.json()["error"].items() if k not in strip
    }


def test_a_key_is_required(api_client: TestClient, seed: Seeder, world: World) -> None:
    scan = Scan(seed, world)

    assert api_client.get(f"{SCANS}/{scan.id}/findings").status_code == 401
