"""worker 解析 nuclei 的 JSONL 輸出（T18；docs/DECISIONS.md §19.7、§23）：收集好的輸出走到 DB。

happy path 入庫觀察；空檔是乾淨的成功（零告警）；guard 合成的 403 被排除；壞掉的輸出是判定、不崩潰。
每個測試用自己的資料庫（queue_database）。
"""

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.findings.service import FindingLinker
from secscan.runner.workspace import Workspace
from secscan.scanners.domain.nuclei.plan import RESULTS_NAME
from secscan.scanners.domain.nuclei.policy import NUCLEI_IMAGE, NUCLEI_VERSION
from secscan.scanners.domain.nuclei.results import PARSER_VERSION
from secscan.scanners.domain.plan import InputFile
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.catalog import ScanProfile
from secscan.scans.domain.lifecycle import RunStatus
from secscan.scans.domain.model import Lease
from secscan.scans.domain.request import BudgetRequest, ScanRequest
from secscan.scans.queue import RunUsage, ScanQueue
from secscan.targets.domain import TargetKind
from secscan.worker.artifacts import ArtifactReader
from secscan.worker.service import Worker
from secscan.worker.telemetry import TelemetryReader
from tests.integration.api_support import LAB, Seeder, World

pytestmark = pytest.mark.integration

NUCLEI = frozenset({ScanEngine.NUCLEI})
ORIGIN = "http://nuclei-lab:8080"
INPUT = InputFile("tech-detect.yaml", b"id: tech-detect\n")


def _now() -> datetime:
    return datetime.now(UTC)


@pytest.fixture
def queue(queue_engine: Engine) -> ScanQueue:
    return ScanQueue(sessionmaker(queue_engine, expire_on_commit=False), lab=LAB, clock=_now)


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


@dataclass(frozen=True)
class Dirs:
    runs: Path
    secrets: Path
    telemetry: Path


@pytest.fixture
def dirs(tmp_path: Path) -> Dirs:
    created = Dirs(tmp_path / "runs", tmp_path / "secrets", tmp_path / "telemetry")
    for path in (created.runs, created.secrets, created.telemetry):
        path.mkdir()
    return created


def _finding(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "template-id": "http-missing-security-headers",
        "info": {"name": "Missing Security Headers", "severity": "info"},
        "type": "http",
        "host": "nuclei-lab",
        "port": "8080",
        "scheme": "http",
        "url": ORIGIN,
        "matched-at": f"{ORIGIN}/",
        "request": "GET / HTTP/1.1\r\nHost: nuclei-lab:8080\r\n\r\n",
        "response": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>",
    }
    base.update(over)
    return base


def _jsonl(*findings: dict[str, Any]) -> bytes:
    return ("\n".join(json.dumps(finding) for finding in findings) + "\n").encode("utf-8")


def _scan(seed: Seeder, world: World) -> UUID:
    target = seed.target(world.operator_a, world.project_a.id, ORIGIN, kind=TargetKind.WEB)
    grant = seed.approve(
        world.admin,
        seed.grant(world.operator_a, target, paths=(), allow_all_paths=True, methods=("GET",)),
    )
    request = ScanRequest(
        target_id=target.id,
        scope_grant_id=grant.id,
        api_spec_id=None,
        auth_profile_id=None,
        profile=ScanProfile.WEB_ACTIVE_LAB,
        engines=(ScanEngine.NUCLEI,),
        budget=BudgetRequest(),
    )
    return seed.create_scan(world.operator_a, request).id


def _collected(
    queue: ScanQueue,
    seed: Seeder,
    world: World,
    dirs: Dirs,
    results: bytes | None,
    *,
    exit_code: int = 0,
) -> Lease:
    _scan(seed, world)
    lease = queue.claim("runner-1", NUCLEI)
    assert lease is not None
    queue.prepare_launch(lease, image_ref=str(NUCLEI_IMAGE))
    workspace = Workspace(dirs.runs, dirs.secrets)
    workspace.prepare(lease.run_id, (INPUT,))
    if results is not None:
        (dirs.runs / str(lease.run_id) / "out" / RESULTS_NAME).write_bytes(results)
    queue.record_usage(lease, RunUsage(requests_sent=1, requests_denied=0, traffic_seconds=1))
    queue.advance(lease, RunStatus.COLLECTING)
    workspace.collect(lease.run_id, exit_code=exit_code, inputs=(INPUT,))
    queue.advance(lease, RunStatus.COLLECTED)
    return lease


def _worker(queue: ScanQueue, dirs: Dirs, findings: FindingLinker | None = None) -> Worker:
    return Worker(
        queue,
        owner="worker-1",
        artifacts=ArtifactReader(dirs.runs),
        telemetry=TelemetryReader(dirs.telemetry),
        findings=findings,
    )


def _run(seed: Seeder, run_id: UUID) -> Any:
    [row] = seed.query(
        "SELECT status, error_code, results_recorded, parser_version, engine_version, "
        "observation_count, result_details FROM scanner_runs WHERE id = :id",
        id=run_id,
    )
    return row


def _observations(seed: Seeder, run_id: UUID) -> list[Any]:
    return list(
        seed.query(
            "SELECT * FROM observations WHERE scanner_run_id = :id ORDER BY ordinal", id=run_id
        )
    )


def test_findings_are_recorded_as_observations(
    queue: ScanQueue, queue_seed: Seeder, world: World, dirs: Dirs
) -> None:
    results = _jsonl(
        _finding(),
        _finding(**{"template-id": "tech-detect", "matched-at": f"{ORIGIN}/app"}),
    )
    lease = _collected(queue, queue_seed, world, dirs, results)

    [report] = _worker(queue, dirs).drain()

    assert report.run_status is RunStatus.SUCCEEDED
    run = _run(queue_seed, lease.run_id)
    assert (run.status, run.error_code) == ("succeeded", None)
    assert run.results_recorded is True
    assert (run.parser_version, run.engine_version) == (PARSER_VERSION, NUCLEI_VERSION)
    assert run.observation_count == 2
    rows = _observations(queue_seed, lease.run_id)
    assert [row.source_rule for row in rows] == ["http-missing-security-headers", "tech-detect"]
    assert rows[0].raw_confidence == "unknown"


def _linked(seed: Seeder, run_id: UUID) -> list[Any]:
    return list(
        seed.query(
            "SELECT f.rule_group, f.route, f.normalized_severity, f.needs_review, count(*) AS n "
            "FROM findings f JOIN finding_observations l ON l.finding_id = f.id "
            "JOIN observations o ON o.id = l.observation_id WHERE o.scanner_run_id = :id "
            "GROUP BY f.id ORDER BY f.rule_group",
            id=run_id,
        )
    )


def test_the_worker_links_the_observations_to_findings(
    queue: ScanQueue, queue_engine: Engine, queue_seed: Seeder, world: World, dirs: Dirs
) -> None:
    """T19：解析入庫之後、run 結束之前連結（§25.7）。"""
    results = _jsonl(
        _finding(**{"matcher-name": "x-frame-options"}),
        _finding(**{"template-id": "tech-detect", "matcher-name": "python"}),
    )
    lease = _collected(queue, queue_seed, world, dirs, results)
    linker = FindingLinker(sessionmaker(queue_engine, expire_on_commit=False))

    [report] = _worker(queue, dirs, linker).drain()

    assert report.run_status is RunStatus.SUCCEEDED
    rows = _linked(queue_seed, lease.run_id)
    # 沒有 ZAP 的佐證：XFO 留在 nuclei 自己的群組（不看 frame-ancestors，不標 clickjacking）；
    # 技術識別保留技術名（使用者簽核，§25.14）。
    assert [(row.rule_group, row.route, row.n) for row in rows] == [
        ("nuclei-tech-detect/python", "/", 1),
        ("nuclei-x-frame-options-missing", "/", 1),
    ]
    assert [row.needs_review for row in rows] == [False, False]


class _FailingOnce:
    """第一次連結時失敗（模擬 worker 在寫入觀察之後、連結之前中斷）。"""

    def __init__(self, real: FindingLinker) -> None:
        self._real = real
        self.calls = 0

    def link(self, lease: Lease) -> int:
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("中斷")
        return self._real.link(lease)


def test_a_retry_links_what_the_interrupted_attempt_left(
    queue: ScanQueue, queue_engine: Engine, queue_seed: Seeder, world: World, dirs: Dirs
) -> None:
    lease = _collected(queue, queue_seed, world, dirs, _jsonl(_finding()))
    linker = _FailingOnce(FindingLinker(sessionmaker(queue_engine, expire_on_commit=False)))
    worker = _worker(queue, dirs, linker)  # type: ignore[arg-type]

    assert worker.drain() == []
    assert _linked(queue_seed, lease.run_id) == []
    queue_seed.execute(
        "UPDATE scanner_runs SET lease_expires_at = now() - interval '1 second' WHERE id = :id",
        id=lease.run_id,
    )
    [report] = worker.drain()

    # 已記錄的判定不再解析；沒有連結的觀察在重試時補上，而且只連結一次。
    assert report.run_status is RunStatus.SUCCEEDED
    assert [row.n for row in _linked(queue_seed, lease.run_id)] == [1]
    assert len(_observations(queue_seed, lease.run_id)) == 1


def test_a_long_matcher_name_does_not_crash_the_worker(
    queue: ScanQueue, queue_seed: Seeder, world: World, dirs: Dirs
) -> None:
    # 簽章模板有 76 字元的 matcher-name：要截斷進 VARCHAR(64)、不讓 worker 因 DataError 結束。
    report_bytes = _jsonl(_finding(**{"matcher-name": "c" * 76}))
    lease = _collected(queue, queue_seed, world, dirs, report_bytes)

    [report] = _worker(queue, dirs).drain()

    assert report.run_status is RunStatus.SUCCEEDED
    [row] = _observations(queue_seed, lease.run_id)
    assert len(row.rule_variant) <= 64


def test_empty_output_is_a_clean_success(
    queue: ScanQueue, queue_seed: Seeder, world: World, dirs: Dirs
) -> None:
    lease = _collected(queue, queue_seed, world, dirs, b"")

    [report] = _worker(queue, dirs).drain()

    assert report.run_status is RunStatus.SUCCEEDED
    run = _run(queue_seed, lease.run_id)
    assert (run.status, run.observation_count) == ("succeeded", 0)
    assert _observations(queue_seed, lease.run_id) == []


def test_a_guard_synthetic_403_is_not_recorded(
    queue: ScanQueue, queue_seed: Seeder, world: World, dirs: Dirs
) -> None:
    blocked = _finding(
        response="HTTP/1.1 403 Forbidden\r\nX-Secscan-Guard: RATE_LIMITED\r\n\r\nblocked"
    )
    lease = _collected(queue, queue_seed, world, dirs, _jsonl(blocked))

    _worker(queue, dirs).drain()

    run = _run(queue_seed, lease.run_id)
    assert (run.status, run.observation_count) == ("succeeded", 0)
    assert run.result_details["excluded"]["guard_response"] == 1
    assert _observations(queue_seed, lease.run_id) == []


def test_a_broken_line_is_invalid_output_not_a_crash(
    queue: ScanQueue, queue_seed: Seeder, world: World, dirs: Dirs
) -> None:
    lease = _collected(queue, queue_seed, world, dirs, _jsonl(_finding()) + b"not json\n")

    [report] = _worker(queue, dirs).drain()

    assert report.run_status is RunStatus.FAILED
    run = _run(queue_seed, lease.run_id)
    assert (run.status, run.error_code) == ("failed", "OUTPUT_INVALID")
    assert run.result_details["problem"] == "report_not_jsonl"


def _collected_without_report(queue: ScanQueue, seed: Seeder, world: World, dirs: Dirs) -> Lease:
    return _collected(queue, seed, world, dirs, None)


def test_a_missing_report_is_invalid_output(
    queue: ScanQueue, queue_seed: Seeder, world: World, dirs: Dirs
) -> None:
    lease = _collected_without_report(queue, queue_seed, world, dirs)

    _worker(queue, dirs).drain()

    run = _run(queue_seed, lease.run_id)
    assert (run.status, run.error_code) == ("failed", "OUTPUT_INVALID")
