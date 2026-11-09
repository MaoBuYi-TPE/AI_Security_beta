"""finding 的明細與來源追溯（T20；docs/API_CONTRACT.md §17.10、DECISIONS.md §26）。

資料經真的佇列與 FindingLinker 寫入（每個測試用自己的資料庫）：觀察引用自己的報告 artifact，
run 有映像與 parser 的版本。驗證追溯鏈（連結 → 觀察 → artifact → run）、快照翻頁不重複也不遺漏、
跨多次 scan、大量觀察、部分失敗，以及 SEC-16（其他 project 與不存在的一樣 404）。
"""

from collections.abc import Iterator, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, event
from sqlalchemy.orm import Session, sessionmaker

from secscan.api_keys.domain import Role
from secscan.findings.domain.provenance import Snapshot
from secscan.findings.domain.taxonomy import mapping_identity
from secscan.findings.models import FindingModel
from secscan.findings.provenance import ProvenanceIntegrityError, ProvenanceRepository
from secscan.findings.service import FindingLinker
from secscan.main import create_app
from secscan.runner.plans import ENGINE_IMAGES
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.domain.model import Lease
from secscan.scans.domain.observation import ObservationInput, RunOutcome
from secscan.scans.queue import ScanQueue
from tests.integration.api_support import LAB, Caller, Seeder, World
from tests.integration.database import ProvisionedDatabase
from tests.integration.finding_support import (
    NUCLEI_XCTO,
    REPORT,
    ZAP_SQLI,
    ZAP_XCTO,
    link_by_sql,
    parsed_run,
    web_scan,
    web_target,
)

pytestmark = pytest.mark.integration

FINDINGS = "/api/v1/findings"
ZAP, NUCLEI = ScanEngine.ZAP, ScanEngine.NUCLEI


@pytest.fixture
def client(queue_database: ProvisionedDatabase) -> Iterator[TestClient]:
    with TestClient(create_app(queue_database.app_settings())) as opened:
        yield opened


@pytest.fixture
def queue(queue_engine: Engine) -> ScanQueue:
    sessions = sessionmaker(queue_engine, expire_on_commit=False)
    return ScanQueue(sessions, lab=LAB, clock=lambda: datetime.now(UTC))


@pytest.fixture
def linker(queue_engine: Engine) -> FindingLinker:
    return FindingLinker(sessionmaker(queue_engine, expire_on_commit=False))


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


class Lab:
    """同一個 target 依序掃描：每次 scan 結束之後才建立下一次（一個 target 一次一個 scan）。"""

    def __init__(self, seed: Seeder, world: World, queue: ScanQueue, linker: FindingLinker):
        self.seed, self.world, self.queue, self.linker = seed, world, queue, linker
        self.target, self.grant_id = web_target(seed, world)
        self.scans: list[UUID] = []

    @property
    def target_id(self) -> UUID:
        return self.target.id

    def scan(
        self,
        observations: Sequence[ObservationInput],
        *,
        status: RunStatus = RunStatus.SUCCEEDED,
        error_code: RunErrorCode | None = None,
    ) -> Lease:
        """一次只有 ZAP 的 scan：寫入觀察、連結、結束 run。"""
        self.scans.append(web_scan(self.seed, self.world, self.target, self.grant_id, (ZAP,)))
        lease = parsed_run(self.queue, ZAP, observations)
        self.linker.link(lease)
        self.queue.advance(lease, status, error_code=error_code)
        return lease


def _get(client: TestClient, caller: Caller, path: str, **params: str | int) -> Any:
    return client.get(f"{FINDINGS}{path}", params=params, headers=caller.headers)


def _finding_of(client: TestClient, caller: Caller, scan_id: UUID, group: str) -> str:
    listed = client.get(f"/api/v1/scans/{scan_id}/findings", headers=caller.headers).json()
    [finding_id] = [item["id"] for item in listed["data"] if item["rule_group"] == group]
    return str(finding_id)


def _run_row(seed: Seeder, run_id: UUID) -> Any:
    [row] = seed.query(
        "SELECT id, image_ref, plan_hash, profile_definition_sha256, engine_version, "
        "parser_version, status, error_code FROM scanner_runs WHERE id = :id",
        id=run_id,
    )
    return row


def test_the_detail_is_a_bounded_summary(
    client: TestClient, queue_seed: Seeder, world: World, queue: ScanQueue, linker: FindingLinker
) -> None:
    lab = Lab(queue_seed, world, queue, linker)
    lease = lab.scan((ZAP_SQLI,))
    finding = _finding_of(client, world.viewer_a, lease.scan_id, "zap-sql-injection")

    response = _get(client, world.viewer_a, f"/{finding}")

    assert response.status_code == 200
    body = response.json()["data"]
    assert (body["id"], body["target_id"], body["rule_group"]) == (
        finding,
        str(lab.target_id),
        "zap-sql-injection",
    )
    assert len(body["fingerprint"]) == 64
    assert body["taxonomy_sha256"] == mapping_identity()[1]
    assert body["observations_as_of"] == 1
    assert body["seen"] == {
        "scans": 1,
        "observations": 1,
        "first_seen_scan_id": str(lease.scan_id),
        "first_seen_run_id": str(lease.run_id),
        "last_seen_scan_id": str(lease.scan_id),
        "last_seen_run_id": str(lease.run_id),
    }
    assert body["engines"] == [{"engine": "zap", "observations": 1, "scans": 1}]
    [recent] = body["recent_scans"]
    assert (recent["scan_id"], recent["status"], recent["observations"]) == (
        str(lease.scan_id),
        "completed",
        1,
    )
    assert recent["scan_severity"] == "high"
    assert [(run["engine"], run["status"], run["observations"]) for run in recent["runs"]] == [
        ("zap", "succeeded", 1)
    ]
    # 明細沒有無上限的欄位：來源、相關 finding 與完整的歷史另外查詢。
    assert not {"sources", "related_finding_ids", "scan_severity"} & set(body)
    assert "storage_key" not in response.text


def test_each_observation_traces_to_its_report_and_run(
    client: TestClient, queue_seed: Seeder, world: World, queue: ScanQueue, linker: FindingLinker
) -> None:
    lab = Lab(queue_seed, world, queue, linker)
    lease = lab.scan((ZAP_SQLI,))
    finding = _finding_of(client, world.viewer_a, lease.scan_id, "zap-sql-injection")
    [listed] = client.get(
        f"/api/v1/scans/{lease.scan_id}/observations", headers=world.viewer_a.headers
    ).json()["data"]

    response = _get(client, world.viewer_a, f"/{finding}/observations")

    assert response.status_code == 200
    body = response.json()
    assert body["meta"] == {"page": 1, "limit": 25, "total": 1, "as_of": 1}
    [traced] = body["data"]
    # 遮罩後的觀察和 scan 的觀察清單相同。
    assert traced["observation"] == listed
    link = traced["link"]
    assert link.pop("linked_at").endswith("Z")
    assert link == {
        "sequence": 1,
        "normalized_severity": "high",
        "normalized_confidence": "medium",
        "needs_review": False,
        "taxonomy_sha256": mapping_identity()[1],
    }
    [artifact_row] = queue_seed.query(
        "SELECT id, storage_key FROM artifacts WHERE scanner_run_id = :run", run=lease.run_id
    )
    assert traced["artifact"] == {
        "id": str(artifact_row.id),
        "kind": "output",
        "path": REPORT.path,
        "sha256": REPORT.sha256,
        "size_bytes": REPORT.size,
        "redactions": 0,
        "classification": "masked",
        "encrypted": False,
        "purged_at": None,
    }
    run = _run_row(queue_seed, lease.run_id)
    shown = traced["run"]
    assert (shown["id"], shown["engine"], shown["sequence"]) == (str(lease.run_id), "zap", 1)
    assert shown["image_ref"] == run.image_ref == str(ENGINE_IMAGES[ZAP])
    assert (shown["plan_hash"], shown["engine_version"], shown["parser_version"]) == (
        run.plan_hash,
        run.engine_version,
        run.parser_version,
    )
    assert shown["parser_version"] == "test-1"
    assert shown["status"] == "succeeded"
    assert "storage_key" not in response.text
    assert artifact_row.storage_key not in response.text


def test_link_values_are_the_ones_written_when_linking(
    client: TestClient, queue_seed: Seeder, world: World, queue: ScanQueue, linker: FindingLinker
) -> None:
    """連結的列不以目前的 taxonomy 重算：以舊版 taxonomy_sha256 寫入的連結原樣回傳。"""
    lab = Lab(queue_seed, world, queue, linker)
    lease = lab.scan((ZAP_SQLI,))
    finding = _finding_of(client, world.viewer_a, lease.scan_id, "zap-sql-injection")
    older = "cd" * 32
    [observation] = queue_seed.query(
        "INSERT INTO observations (scanner_run_id, scan_id, ordinal, source_event_id, "
        "source_index, source_rule, rule_variant, title, raw_severity, severity_label, "
        "raw_confidence, confidence_label, method, path, parameter_location, auth_role, "
        "parser_version) VALUES (:run, :scan, 99, :event, 0, '40018', '40018', 't', '1', 'Low', "
        "'1', 'Low', 'GET', '/search', 'unknown', 'anonymous', 'old/0') RETURNING id",
        run=lease.run_id,
        scan=lease.scan_id,
        event=uuid4().hex * 2,
    )
    link_by_sql(
        queue_seed,
        finding,
        observation.id,
        severity="low",
        confidence="low",
        review=True,
        sha=older,
    )

    traced = _get(client, world.viewer_a, f"/{finding}/observations").json()["data"]

    assert [item["link"]["taxonomy_sha256"] for item in traced] == [mapping_identity()[1], older]
    assert [item["link"]["normalized_severity"] for item in traced] == ["high", "low"]
    # 沒有引用報告的舊觀察：artifact 是 null（LEFT JOIN，不丟掉這一列、不補造）。
    assert [item["artifact"] is None for item in traced] == [False, True]
    assert traced[1]["observation"]["parser_version"] == "old/0"


def test_history_pages_from_a_snapshot_across_scans(
    client: TestClient, queue_seed: Seeder, world: World, queue: ScanQueue, linker: FindingLinker
) -> None:
    """跨 3 次 scan：歷史由舊到新分頁；翻頁之間又有新的 scan 連結，同一個 as_of 不重複也不遺漏。"""
    lab = Lab(queue_seed, world, queue, linker)
    leases = [lab.scan((ZAP_SQLI,)) for _ in range(3)]
    finding = _finding_of(client, world.viewer_a, leases[0].scan_id, "zap-sql-injection")

    detail = _get(client, world.viewer_a, f"/{finding}").json()["data"]
    first = _get(client, world.viewer_a, f"/{finding}/scans", limit=2).json()
    late = lab.scan((ZAP_SQLI,))
    second = _get(
        client, world.viewer_a, f"/{finding}/scans", limit=2, page=2, as_of=first["meta"]["as_of"]
    ).json()

    assert (detail["observations_as_of"], detail["seen"]["scans"]) == (3, 3)
    assert [scan["scan_id"] for scan in detail["recent_scans"]] == [
        str(lease.scan_id) for lease in reversed(leases)
    ]
    assert first["meta"] == {"page": 1, "limit": 2, "total": 3, "as_of": 3}
    assert second["meta"] == {"page": 2, "limit": 2, "total": 3, "as_of": 3}
    paged = [scan["scan_id"] for scan in first["data"] + second["data"]]
    assert paged == [str(lease.scan_id) for lease in leases]
    # 舊的快照：明細的 seen、engines 與 recent_scans 都是 as_of 時的值。
    older = _get(client, world.viewer_a, f"/{finding}", as_of=3).json()["data"]
    assert (older["observations_as_of"], older["seen"]["scans"]) == (3, 3)
    assert older["seen"]["last_seen_scan_id"] == str(leases[-1].scan_id)
    assert older["engines"] == [{"engine": "zap", "observations": 3, "scans": 3}]
    assert len(older["recent_scans"]) == 3
    # 沒有 as_of：新的快照才看得到第 4 次 scan。
    current = _get(client, world.viewer_a, f"/{finding}/scans", limit=100).json()
    assert current["meta"]["as_of"] == 4
    assert current["data"][-1]["scan_id"] == str(late.scan_id)
    assert _get(client, world.viewer_a, f"/{finding}").json()["data"]["seen"][
        "last_seen_scan_id"
    ] == str(late.scan_id)


def test_observations_page_from_a_snapshot_while_links_grow(
    client: TestClient, queue_seed: Seeder, world: World, queue: ScanQueue, linker: FindingLinker
) -> None:
    lab = Lab(queue_seed, world, queue, linker)
    for _ in range(3):
        lab.scan((ZAP_SQLI,))
    finding = _finding_of(client, world.viewer_a, lab.scans[0], "zap-sql-injection")

    first = _get(client, world.viewer_a, f"/{finding}/observations", limit=2).json()
    lab.scan((ZAP_SQLI,))
    second = _get(
        client, world.viewer_a, f"/{finding}/observations", limit=2, page=2, as_of=3
    ).json()

    sequences = [item["link"]["sequence"] for item in first["data"] + second["data"]]
    assert sequences == [1, 2, 3]
    assert (first["meta"]["total"], second["meta"]["total"]) == (3, 3)
    scans = [item["observation"]["scan_id"] for item in first["data"] + second["data"]]
    assert scans == [str(scan_id) for scan_id in lab.scans[:3]]


def test_the_detail_keeps_only_the_five_most_recent_scans(
    client: TestClient, queue_seed: Seeder, world: World, queue: ScanQueue, linker: FindingLinker
) -> None:
    lab = Lab(queue_seed, world, queue, linker)
    leases = [lab.scan((ZAP_SQLI,)) for _ in range(6)]
    finding = _finding_of(client, world.viewer_a, leases[0].scan_id, "zap-sql-injection")

    detail = _get(client, world.viewer_a, f"/{finding}").json()["data"]

    assert detail["seen"]["scans"] == 6
    assert [scan["scan_id"] for scan in detail["recent_scans"]] == [
        str(lease.scan_id) for lease in reversed(leases[1:])
    ]
    history = _get(client, world.viewer_a, f"/{finding}/scans").json()
    assert history["meta"]["total"] == 6


def _many(count: int) -> tuple[ObservationInput, ...]:
    """同一個問題、只有 query 不同的觀察（query 不是身分）：全部連到一個 finding。"""
    return tuple(
        replace(ZAP_SQLI, source_event_id=uuid4().hex * 2, query=f"q={index}")
        for index in range(count)
    )


class StatementCounter:
    def __init__(self) -> None:
        self.count = 0

    def __call__(self, *_: object) -> None:
        self.count += 1


def _statements(client: TestClient, caller: Caller, path: str, **params: str | int) -> int:
    counter = StatementCounter()
    event.listen(Engine, "before_cursor_execute", counter)
    try:
        assert _get(client, caller, path, **params).status_code == 200
    finally:
        event.remove(Engine, "before_cursor_execute", counter)
    return counter.count


# 一個請求的 SQL 數上限（含認證與授權）：和每頁的筆數、連結數都無關。
MAX_STATEMENTS = 12


def test_a_large_finding_pages_completely_with_a_fixed_number_of_statements(
    client: TestClient, queue_seed: Seeder, world: World, queue: ScanQueue, linker: FindingLinker
) -> None:
    lab = Lab(queue_seed, world, queue, linker)
    lab.scan(_many(1500))
    finding = _finding_of(client, world.viewer_a, lab.scans[0], "zap-sql-injection")
    pages: list[list[dict[str, Any]]] = []
    statements: list[int] = []

    for page in range(1, 16):
        counter = StatementCounter()
        event.listen(Engine, "before_cursor_execute", counter)
        try:
            body = _get(
                client, world.viewer_a, f"/{finding}/observations", limit=100, page=page
            ).json()
        finally:
            event.remove(Engine, "before_cursor_execute", counter)
        assert body["meta"] == {"page": page, "limit": 100, "total": 1500, "as_of": 1500}
        pages.append(body["data"])
        statements.append(counter.count)

    items = [item for page_items in pages for item in page_items]
    assert [item["link"]["sequence"] for item in items] == list(range(1, 1501))
    assert len({item["observation"]["id"] for item in items}) == 1500
    assert len(set(statements)) == 1, statements
    # 每列的 lazy load 會讓 SQL 數隨筆數增加：1 筆與 100 筆的頁必須相同，而且有上限。
    one = _statements(client, world.viewer_a, f"/{finding}/observations", limit=1)
    assert one == statements[0] <= MAX_STATEMENTS
    assert _statements(client, world.viewer_a, f"/{finding}") <= MAX_STATEMENTS
    assert _statements(client, world.viewer_a, f"/{finding}/scans") <= MAX_STATEMENTS
    assert (
        _get(client, world.viewer_a, f"/{finding}/observations", page=16, limit=100).json()["data"]
        == []
    )


def _two_engines(lab: Lab, zap: RunStatus, zap_error: RunErrorCode | None) -> tuple[Lease, Lease]:
    """ZAP 有觀察並以 zap 的狀態結束；nuclei 在準備時因預算不足失敗（沒有觀察）。"""
    lab.scans.append(web_scan(lab.seed, lab.world, lab.target, lab.grant_id, (ZAP, NUCLEI)))
    zap_lease = parsed_run(
        lab.queue, ZAP, (ZAP_SQLI,), outcome=RunOutcome(zap, error_code=zap_error)
    )
    lab.linker.link(zap_lease)
    lab.queue.advance(zap_lease, zap, error_code=zap_error)
    nuclei = lab.queue.claim("runner-1", frozenset({NUCLEI}))
    assert nuclei is not None
    lab.queue.advance(nuclei, RunStatus.FAILED, error_code=RunErrorCode.BUDGET_EXHAUSTED)
    return zap_lease, nuclei


@pytest.mark.parametrize(
    ("zap", "zap_error", "scan_status"),
    [
        (RunStatus.TIMED_OUT, RunErrorCode.ENGINE_TIMEOUT, "timed_out"),
        (RunStatus.SUCCEEDED, None, "partially_completed"),
    ],
)
def test_a_partial_failure_keeps_the_trace_and_shows_every_run(
    client: TestClient,
    queue_seed: Seeder,
    world: World,
    queue: ScanQueue,
    linker: FindingLinker,
    zap: RunStatus,
    zap_error: RunErrorCode | None,
    scan_status: str,
) -> None:
    """部分 run 失敗：已取得的觀察仍可追溯；歷史列出失敗、沒有觀察的引擎，scan 不是 completed。"""
    lab = Lab(queue_seed, world, queue, linker)
    zap_lease, nuclei = _two_engines(lab, zap, zap_error)
    finding = _finding_of(client, world.viewer_a, zap_lease.scan_id, "zap-sql-injection")

    [scan] = _get(client, world.viewer_a, f"/{finding}/scans").json()["data"]
    [traced] = _get(client, world.viewer_a, f"/{finding}/observations").json()["data"]

    assert scan["status"] == scan_status
    assert [
        (run["engine"], run["status"], run["error_code"], run["observations"])
        for run in scan["runs"]
    ] == [
        ("zap", zap.value, zap_error.value if zap_error else None, 1),
        ("nuclei", "failed", "BUDGET_EXHAUSTED", 0),
    ]
    assert traced["run"]["id"] == str(zap_lease.run_id)
    assert traced["run"]["status"] == zap.value
    assert traced["artifact"]["sha256"] == REPORT.sha256
    assert {run["id"] for run in scan["runs"]} == {str(zap_lease.run_id), str(nuclei.run_id)}


def test_linking_again_after_an_interruption_adds_no_duplicates(
    client: TestClient, queue_seed: Seeder, world: World, queue: ScanQueue, linker: FindingLinker
) -> None:
    """worker 連結之後、run 結束之前中斷：重試只補上沒連結的觀察，追溯中每個觀察只出現一次。"""
    lab = Lab(queue_seed, world, queue, linker)
    lab.scans.append(web_scan(queue_seed, world, lab.target, lab.grant_id, (ZAP,)))
    lease = parsed_run(queue, ZAP, (ZAP_SQLI, replace(ZAP_SQLI, source_event_id="e" * 64)))
    assert linker.link(lease) == 2
    assert linker.link(lease) == 0
    queue.advance(lease, RunStatus.SUCCEEDED)
    finding = _finding_of(client, world.viewer_a, lease.scan_id, "zap-sql-injection")

    body = _get(client, world.viewer_a, f"/{finding}/observations").json()

    assert body["meta"]["total"] == 2
    assert len({item["observation"]["id"] for item in body["data"]}) == 2
    assert {item["run"]["id"] for item in body["data"]} == {str(lease.run_id)}


def test_filters_by_scan_and_engine(
    client: TestClient, queue_seed: Seeder, world: World, queue: ScanQueue, linker: FindingLinker
) -> None:
    """佐證合併的 header（同一次 scan 的 ZAP 與 nuclei）：篩選同一個快照的集合。"""
    lab = Lab(queue_seed, world, queue, linker)
    lab.scans.append(web_scan(queue_seed, world, lab.target, lab.grant_id, (ZAP, NUCLEI)))
    zap = parsed_run(queue, ZAP, (ZAP_XCTO,))
    linker.link(zap)
    queue.advance(zap, RunStatus.SUCCEEDED)
    nuclei = parsed_run(queue, NUCLEI, (NUCLEI_XCTO,))
    linker.link(nuclei)
    queue.advance(nuclei, RunStatus.SUCCEEDED)
    first_scan = zap.scan_id
    lab.scan((ZAP_XCTO,))
    finding = _finding_of(client, world.viewer_a, first_scan, "x-content-type-options-missing")

    def engines(**params: str) -> list[str]:
        body = _get(client, world.viewer_a, f"/{finding}/observations", **params).json()
        assert body["meta"]["total"] == len(body["data"])
        return [item["run"]["engine"] for item in body["data"]]

    assert engines() == ["zap", "nuclei", "zap"]
    assert engines(engine="nuclei") == ["nuclei"]
    assert engines(scan_id=str(first_scan)) == ["zap", "nuclei"]
    assert engines(scan_id=str(first_scan), engine="zap") == ["zap"]
    assert engines(scan_id=str(uuid4())) == []
    detail = _get(client, world.viewer_a, f"/{finding}").json()["data"]
    assert detail["engines"] == [
        {"engine": "nuclei", "observations": 1, "scans": 1},
        {"engine": "zap", "observations": 2, "scans": 2},
    ]


@pytest.mark.parametrize(
    ("path", "params"),
    [
        ("", {"as_of": 0}),
        ("", {"as_of": 2}),
        ("/scans", {"as_of": 2}),
        ("/scans", {"limit": 101}),
        ("/observations", {"page": 0}),
        ("/observations", {"engine": "burp"}),
        ("/observations", {"scan_id": "not-a-uuid"}),
        ("/observations", {"as_of": 2**63}),
    ],
)
def test_invalid_queries_are_rejected(
    client: TestClient,
    queue_seed: Seeder,
    world: World,
    queue: ScanQueue,
    linker: FindingLinker,
    path: str,
    params: dict[str, str | int],
) -> None:
    lab = Lab(queue_seed, world, queue, linker)
    lease = lab.scan((ZAP_SQLI,))
    finding = _finding_of(client, world.viewer_a, lease.scan_id, "zap-sql-injection")

    response = _get(client, world.viewer_a, f"/{finding}{path}", **params)

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_REQUEST"


@pytest.mark.parametrize(
    ("path", "params"),
    [
        ("", {}),
        ("/scans", {}),
        ("/observations", {}),
        # as_of 與篩選的檢查在權限之後：其他 project 的 finding 不會因此回 422 或洩漏連結數。
        ("", {"as_of": 10**6}),
        ("/scans", {"as_of": 10**6}),
        ("/observations", {"as_of": 10**6, "engine": "zap", "scan_id": str(uuid4())}),
    ],
)
def test_another_projects_finding_is_not_found(
    client: TestClient,
    queue_seed: Seeder,
    world: World,
    queue: ScanQueue,
    linker: FindingLinker,
    path: str,
    params: dict[str, str | int],
) -> None:
    """SEC-16：B 的 key 讀 A 的 finding，和不存在的 finding 一樣 404；A 的 viewer 可以讀。"""
    lab = Lab(queue_seed, world, queue, linker)
    lease = lab.scan((ZAP_SQLI,))
    finding = _finding_of(client, world.viewer_a, lease.scan_id, "zap-sql-injection")
    other = queue_seed.member(world.admin, world.project_b.id, Role.VIEWER)

    foreign = _get(client, other, f"/{finding}{path}", **params)
    missing = _get(client, other, f"/{uuid4()}{path}", **params)

    assert foreign.status_code == missing.status_code == 404
    strip = ("request_id",)
    assert {k: v for k, v in foreign.json()["error"].items() if k not in strip} == {
        k: v for k, v in missing.json()["error"].items() if k not in strip
    }
    if not params:
        assert _get(client, world.viewer_a, f"/{finding}{path}").status_code == 200
    assert client.get(f"{FINDINGS}/{finding}{path}", params=params).status_code == 401


def test_a_finding_without_links_and_pages_past_the_end(
    client: TestClient, queue_seed: Seeder, world: World, queue: ScanQueue, linker: FindingLinker
) -> None:
    """沒有連結的 finding（linker 不會產生）回 404；超出範圍的頁是空的清單。"""
    lab = Lab(queue_seed, world, queue, linker)
    lease = lab.scan((ZAP_SQLI,))
    finding = _finding_of(client, world.viewer_a, lease.scan_id, "zap-sql-injection")
    empty = uuid4()
    columns = [column.name for column in FindingModel.__table__.columns]
    values = {"id": empty, "fingerprint": uuid4().hex * 2, "observations_linked": 0}
    selected = ", ".join(f":{name}" if name in values else name for name in columns)
    queue_seed.execute(
        f"INSERT INTO findings ({', '.join(columns)}) SELECT {selected} "  # noqa: S608
        "FROM findings WHERE id = :source",
        **values,
        source=finding,
    )

    assert _get(client, world.viewer_a, f"/{empty}").status_code == 404
    beyond = _get(client, world.viewer_a, f"/{finding}/scans", page=2, limit=100).json()
    assert (beyond["data"], beyond["meta"]["total"]) == ([], 1)


def test_an_incomplete_snapshot_is_an_integrity_error(
    queue_engine: Engine, queue_seed: Seeder, world: World, queue: ScanQueue, linker: FindingLinker
) -> None:
    """repository 不回傳半套的摘要：快照中缺少序號時是明確的錯誤（DB 的 commit 核對擋在前面）。"""
    lab = Lab(queue_seed, world, queue, linker)
    lab.scan((ZAP_SQLI,))
    [row] = queue_seed.query("SELECT id FROM findings WHERE target_id = :id", id=lab.target_id)

    with Session(queue_engine) as session, pytest.raises(ProvenanceIntegrityError):
        ProvenanceRepository(session).seen(Snapshot(row.id, as_of=2))
