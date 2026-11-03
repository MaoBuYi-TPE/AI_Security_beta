"""worker 把觀察連結到 finding（T19；docs/DECISIONS.md §25.7、§25.8）：真的 DB、真的 trigger。

觀察以佇列的 record_results 寫入（和 parser 寫入的是同一個契約），再以 FindingLinker 連結。
每個測試用自己的資料庫（queue_database）。
"""

import threading
from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID

import pytest
from sqlalchemy import Engine, event
from sqlalchemy.orm import Session, sessionmaker

from secscan.core.db import create_db_engine
from secscan.findings import repository
from secscan.findings.service import FindingLinker
from secscan.runner.plans import ENGINE_IMAGES
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunStatus
from secscan.scans.domain.model import Lease
from secscan.scans.domain.preflight import PreflightResult
from secscan.scans.domain.traffic import AuthHealth, GuardTraffic
from secscan.scans.leases import LeaseLostError
from secscan.scans.queue import RunUsage, ScanQueue
from tests.integration.api_support import LAB, Scannable, Seeder, World
from tests.integration.database import ProvisionedDatabase
from tests.integration.finding_support import (
    NUCLEI_CORS,
    NUCLEI_TECH,
    NUCLEI_XCTO,
    ZAP_CORS,
    ZAP_SQLI,
    ZAP_XCTO,
    observation,
    parsed_run,
    web_scan,
    web_target,
)
from tests.integration.locks import LOCK_WAIT_TIMEOUT_SECONDS, wait_until_waiting_for_a_lock

pytestmark = pytest.mark.integration

ZAP, NUCLEI, PREFLIGHT = ScanEngine.ZAP, ScanEngine.NUCLEI, ScanEngine.PREFLIGHT


def _now() -> datetime:
    return datetime.now(UTC)


@pytest.fixture
def queue(queue_engine: Engine) -> ScanQueue:
    return ScanQueue(sessionmaker(queue_engine, expire_on_commit=False), lab=LAB, clock=_now)


@pytest.fixture
def linker(queue_engine: Engine) -> FindingLinker:
    return FindingLinker(sessionmaker(queue_engine, expire_on_commit=False))


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


def _findings(seed: Seeder, target_id: UUID) -> dict[str, dict[str, object]]:
    rows = seed.query(
        "SELECT f.*, (SELECT count(*) FROM finding_observations o WHERE o.finding_id = f.id) "
        "AS links FROM findings f WHERE target_id = :target",
        target=target_id,
    )
    return {row.rule_group: dict(row._mapping) for row in rows}


def test_co_located_hits_of_both_engines_are_one_finding(
    queue: ScanQueue, linker: FindingLinker, queue_seed: Seeder, world: World
) -> None:
    target, grant_id = web_target(queue_seed, world)
    scan_id = web_scan(queue_seed, world, target, grant_id, (ZAP, NUCLEI))
    zap = parsed_run(queue, ZAP, (ZAP_CORS, ZAP_XCTO, ZAP_SQLI))
    assert linker.link(zap) == 3
    queue.advance(zap, RunStatus.SUCCEEDED)
    nuclei = parsed_run(queue, NUCLEI, (NUCLEI_CORS, NUCLEI_XCTO, NUCLEI_TECH))
    assert linker.link(nuclei) == 3

    findings = _findings(queue_seed, target.id)

    assert set(findings) == {
        "cors-permissive-policy",
        "x-content-type-options-missing",
        "zap-sql-injection",
        "nuclei:tech-detect:python",
    }
    cors = findings["cors-permissive-policy"]
    # 最高值是 ZAP 的 medium，等級不一致；兩個工具同時命中不提高等級。
    assert (cors["normalized_severity"], cors["severity_conflict"], cors["links"]) == (
        "medium",
        True,
        2,
    )
    assert (cors["cwe_id"], cors["cwe_source"]) == (942, "rule_group")
    assert (cors["owasp_top10_2025"], cors["owasp_top10_2025_source"]) == ("A02:2025", "official")
    assert (cors["owasp_api_2023"], cors["owasp_api_2023_source"]) == ("API8:2023", "curated")
    assert (cors["first_seen_run_id"], cors["last_seen_run_id"]) == (zap.run_id, nuclei.run_id)
    assert (cors["first_seen_scan_id"], cors["last_seen_scan_id"]) == (scan_id, scan_id)
    assert (cors["triage_state"], cors["lifecycle_state"]) == ("unreviewed", "open")
    assert (cors["route"], cors["route_source"], cors["auth_verified"]) == ("/", "literal", True)
    xcto = findings["x-content-type-options-missing"]
    assert (xcto["normalized_severity"], xcto["links"], xcto["parameter_name"]) == ("low", 2, None)
    sqli = findings["zap-sql-injection"]
    assert (sqli["parameter_location"], sqli["parameter_name"], sqli["needs_review"]) == (
        "query",
        "q",
        False,
    )
    tech = findings["nuclei:tech-detect:python"]
    assert (tech["needs_review"], tech["kind"], tech["cwe_id"]) == (True, "informational", None)
    # 每個觀察恰好連結一次。
    [row] = queue_seed.query("SELECT count(*) AS n FROM finding_observations")
    assert row.n == 6


def test_linking_again_adds_nothing(
    queue: ScanQueue, linker: FindingLinker, queue_seed: Seeder, world: World
) -> None:
    target, grant_id = web_target(queue_seed, world)
    web_scan(queue_seed, world, target, grant_id, (ZAP,))
    lease = parsed_run(queue, ZAP, (ZAP_CORS, ZAP_SQLI))
    assert linker.link(lease) == 2
    before = _findings(queue_seed, target.id)

    assert linker.link(lease) == 0
    assert _findings(queue_seed, target.id) == before


def test_a_run_without_observations_links_nothing(
    queue: ScanQueue, linker: FindingLinker, queue_seed: Seeder, world: World
) -> None:
    target, grant_id = web_target(queue_seed, world)
    web_scan(queue_seed, world, target, grant_id, (ZAP,))

    assert linker.link(parsed_run(queue, ZAP, ())) == 0
    assert _findings(queue_seed, target.id) == {}


def test_a_rescan_reuses_the_finding_and_only_moves_upwards(
    queue: ScanQueue, linker: FindingLinker, queue_seed: Seeder, world: World
) -> None:
    target, grant_id = web_target(queue_seed, world)
    first_scan = web_scan(queue_seed, world, target, grant_id, (ZAP,))
    first = parsed_run(queue, ZAP, (ZAP_SQLI,))
    linker.link(first)
    queue.advance(first, RunStatus.SUCCEEDED)
    second_scan = web_scan(queue_seed, world, target, grant_id, (ZAP,))
    # 同一個參數、較低的等級：最高值不變，標成衝突。
    second = parsed_run(queue, ZAP, (replace(ZAP_SQLI, raw_severity="2"),))
    linker.link(second)

    [sqli] = _findings(queue_seed, target.id).values()

    assert (sqli["normalized_severity"], sqli["severity_conflict"], sqli["links"]) == (
        "high",
        True,
        2,
    )
    assert (sqli["first_seen_scan_id"], sqli["last_seen_scan_id"]) == (first_scan, second_scan)
    assert sqli["last_seen_at"] >= sqli["created_at"]  # type: ignore[operator]


def test_different_targets_never_share_a_finding(
    queue: ScanQueue, linker: FindingLinker, queue_seed: Seeder, world: World
) -> None:
    targets = []
    for _ in range(2):
        target, grant_id = web_target(queue_seed, world)
        web_scan(queue_seed, world, target, grant_id, (ZAP,))
        linker.link(parsed_run(queue, ZAP, (ZAP_CORS,)))
        targets.append(target.id)

    rows = queue_seed.query("SELECT target_id, fingerprint FROM findings")

    assert sorted(row.target_id for row in rows) == sorted(targets)
    assert len({row.fingerprint for row in rows}) == 2


def test_a_spec_templates_the_route(
    queue: ScanQueue, linker: FindingLinker, queue_seed: Seeder, world: World
) -> None:
    scannable = queue_seed.scannable(world)
    queue_seed.scan(world.operator_a, scannable, engines=(ZAP,))
    by_id = [
        observation("40018", severity="3", path=path, parameter="id", cwe=89)
        for path in ("/items/5", "/items/6")
    ]

    linker.link(parsed_run(queue, ZAP, by_id))

    [finding] = _findings(queue_seed, scannable.target.id).values()
    assert (finding["route"], finding["route_source"], finding["links"]) == (
        "/items/{id}",
        "openapi",
        2,
    )


def _authenticated_scan(
    queue: ScanQueue, seed: Seeder, world: World, scannable: Scannable, preflight: PreflightResult
) -> None:
    seed.scan(world.operator_a, scannable, engines=(ZAP,), auth_profile_id=scannable.profile.id)
    runner = queue.claim("runner-1", frozenset({PREFLIGHT}))
    assert runner is not None
    queue.prepare_launch(runner, image_ref=str(ENGINE_IMAGES[PREFLIGHT]))
    queue.record_usage(runner, RunUsage(requests_sent=2, requests_denied=0, traffic_seconds=1))
    queue.advance(runner, RunStatus.COLLECTING)
    queue.advance(runner, RunStatus.COLLECTED)
    lease = queue.claim_collected("worker-1", frozenset({PREFLIGHT}))
    assert lease is not None
    queue.record_preflight(lease, preflight)
    queue.advance(lease, RunStatus.SUCCEEDED)


def _traffic(*, accepted: int, rejected: int = 0, regressed: int = 0) -> GuardTraffic:
    return GuardTraffic(
        forwarded=10, auth=AuthHealth(accepted=accepted, rejected=rejected, regressed=regressed)
    )


def test_lost_identity_is_a_separate_unverified_finding(
    queue: ScanQueue, linker: FindingLinker, queue_seed: Seeder, world: World
) -> None:
    """T16 的交接：guard 記下身分失效的 run，觀察不併入已驗證身分的 finding。"""
    scannable = queue_seed.scannable(world)
    finding = observation("40018", severity="3", path="/items/5", parameter="id", cwe=89)
    _authenticated_scan(queue, queue_seed, world, scannable, PreflightResult.PASSED)
    healthy = parsed_run(queue, ZAP, (finding,), traffic=_traffic(accepted=5))
    linker.link(healthy)
    queue.advance(healthy, RunStatus.SUCCEEDED)
    _authenticated_scan(queue, queue_seed, world, scannable, PreflightResult.PASSED)
    lost = parsed_run(queue, ZAP, (finding,), traffic=_traffic(accepted=5, regressed=3))
    linker.link(lost)

    rows = queue_seed.query(
        "SELECT auth_role, auth_verified FROM findings ORDER BY auth_verified DESC"
    )

    assert [(row.auth_role, row.auth_verified) for row in rows] == [
        ("standard_user", True),
        ("standard_user", False),
    ]


def test_rejected_requests_mean_unverified_even_when_not_lost(
    queue: ScanQueue, linker: FindingLinker, queue_seed: Seeder, world: World
) -> None:
    """中途過期、之後只打新端點：沒有退化（lost 是 false），但有被拒絕的請求（安全審查）。"""
    scannable = queue_seed.scannable(world)
    _authenticated_scan(queue, queue_seed, world, scannable, PreflightResult.PASSED)
    traffic = _traffic(accepted=5, rejected=40)
    assert traffic.auth is not None
    assert traffic.auth.lost is False
    lease = parsed_run(queue, ZAP, (ZAP_CORS,), traffic=traffic)

    linker.link(lease)

    [row] = queue_seed.query("SELECT auth_verified FROM findings")
    assert row.auth_verified is False


def test_a_failed_preflight_means_unverified(
    queue: ScanQueue, linker: FindingLinker, queue_seed: Seeder, world: World
) -> None:
    scannable = queue_seed.scannable(world)
    _authenticated_scan(queue, queue_seed, world, scannable, PreflightResult.FAILED)
    lease = parsed_run(queue, ZAP, (ZAP_CORS,), traffic=_traffic(accepted=5))

    linker.link(lease)

    [row] = queue_seed.query("SELECT auth_verified FROM findings")
    assert row.auth_verified is False


def test_a_lost_lease_links_nothing(
    queue: ScanQueue, linker: FindingLinker, queue_seed: Seeder, world: World
) -> None:
    target, grant_id = web_target(queue_seed, world)
    web_scan(queue_seed, world, target, grant_id, (ZAP,))
    lease = parsed_run(queue, ZAP, (ZAP_CORS,))

    with pytest.raises(LeaseLostError):
        linker.link(replace(lease, owner="worker-2"))
    assert _findings(queue_seed, target.id) == {}


def test_a_second_run_waits_for_the_first_and_merges_without_duplicates(
    queue: ScanQueue, queue_database: ProvisionedDatabase, queue_seed: Seeder, world: World
) -> None:
    """同一個 scan 的 zap 與 nuclei 同時在解析（兩個 worker）：zap 的連結在 commit 之前停住
    （持有新增的 finding 的列鎖），nuclei 的連結確實在等它（pg_stat_activity），放行之後兩者都完成，
    共用的 fingerprint 只有一列（鎖序固定，§25.7）。
    """
    target, grant_id = web_target(queue_seed, world)
    web_scan(queue_seed, world, target, grant_id, (ZAP, NUCLEI))
    zap = parsed_run(queue, ZAP, (ZAP_CORS, ZAP_XCTO, ZAP_SQLI))
    nuclei = parsed_run(queue, NUCLEI, (NUCLEI_CORS, NUCLEI_XCTO, NUCLEI_TECH))
    paused, release = threading.Event(), threading.Event()
    errors: list[Exception] = []

    def link(lease: Lease, name: str, *, hold: bool) -> None:
        engine = create_db_engine(
            queue_database.app_settings(), application_name=name, pooled=False
        )
        sessions = sessionmaker(engine, expire_on_commit=False)
        if hold:

            def before_commit(_session: Session) -> None:
                paused.set()
                release.wait(timeout=LOCK_WAIT_TIMEOUT_SECONDS)

            event.listen(sessions, "before_commit", before_commit)
        try:
            FindingLinker(sessions).link(lease)
        except Exception as exc:  # noqa: BLE001 - 交給測試檢查
            errors.append(exc)
        finally:
            engine.dispose()

    first = threading.Thread(target=link, args=(zap, "linker-zap"), kwargs={"hold": True})
    second = threading.Thread(target=link, args=(nuclei, "linker-nuclei"), kwargs={"hold": False})
    first.start()
    assert paused.wait(timeout=LOCK_WAIT_TIMEOUT_SECONDS)
    second.start()
    wait_until_waiting_for_a_lock(queue_seed, "linker-nuclei")
    release.set()
    for thread in (first, second):
        thread.join(timeout=LOCK_WAIT_TIMEOUT_SECONDS)
        assert not thread.is_alive()

    assert errors == []
    findings = _findings(queue_seed, target.id)
    assert findings["cors-permissive-policy"]["links"] == 2
    assert findings["cors-permissive-policy"]["severity_conflict"] is True
    assert findings["cors-permissive-policy"]["last_seen_run_id"] == nuclei.run_id
    assert sum(finding["links"] for finding in findings.values()) == 6  # type: ignore[misc]


def test_batches_cover_every_finding_and_link(
    queue: ScanQueue,
    linker: FindingLinker,
    queue_seed: Seeder,
    world: World,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """跨批次的新增、鎖定與連結（BATCH_SIZE 改成 2，7 個 finding、8 個觀察）。"""
    monkeypatch.setattr(repository, "BATCH_SIZE", 2)
    target, grant_id = web_target(queue_seed, world)
    web_scan(queue_seed, world, target, grant_id, (ZAP, NUCLEI))
    paths = [f"/p{index}" for index in range(5)]
    zap = parsed_run(
        queue,
        ZAP,
        [replace(ZAP_CORS, source_event_id=f"{i:064x}", path=path) for i, path in enumerate(paths)]
        + [ZAP_XCTO],
    )
    linker.link(zap)
    queue.advance(zap, RunStatus.SUCCEEDED)
    # 第二個 run 命中既有的 5 個（跨批次鎖定）與一個新的。
    nuclei = parsed_run(
        queue,
        NUCLEI,
        [
            replace(NUCLEI_CORS, source_event_id=f"{i:064x}", path=path)
            for i, path in enumerate(paths)
        ]
        + [NUCLEI_TECH],
    )
    assert linker.link(nuclei) == 6

    assert len(queue_seed.query("SELECT id FROM findings WHERE target_id = :t", t=target.id)) == 7
    [row] = queue_seed.query("SELECT count(*) AS n FROM finding_observations")
    assert row.n == 12
    rows = queue_seed.query(
        "SELECT route, severity_conflict, last_seen_run_id FROM findings "
        "WHERE target_id = :t AND rule_group = 'cors-permissive-policy' ORDER BY route",
        t=target.id,
    )
    assert [(r.route, r.severity_conflict, r.last_seen_run_id) for r in rows] == [
        (path, True, nuclei.run_id) for path in paths
    ]
