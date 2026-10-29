"""worker（docs/DECISIONS.md §14.6）：T10 只把 fake 的 collected 標成 succeeded，不讀任何檔案。

每個測試用自己的資料庫（queue_database）。
"""

from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.runner.workspace import Workspace
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunStatus, ScanStatus
from secscan.scans.domain.model import Lease
from secscan.scans.domain.preflight import PreflightResult
from secscan.scans.queue import LeaseLostError, RunReport, ScanQueue
from secscan.worker.artifacts import ArtifactReader
from secscan.worker.service import Worker
from tests.integration.api_support import LAB, Seeder, World

pytestmark = pytest.mark.integration

FAKE = frozenset({ScanEngine.FAKE})
IMAGE = "busybox:1.38.0@sha256:" + "ab" * 32


def _now() -> datetime:
    return datetime.now(UTC)


@pytest.fixture
def queue(queue_engine: Engine) -> ScanQueue:
    return ScanQueue(sessionmaker(queue_engine, expire_on_commit=False), lab=LAB, clock=_now)


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


def _collected(queue: ScanQueue, seed: Seeder, world: World) -> Lease:
    seed.scan(world.operator_a, seed.scannable(world))
    lease = queue.claim("runner-1", FAKE)
    assert lease is not None
    queue.prepare_launch(lease, image_ref=IMAGE)
    queue.advance(lease, RunStatus.COLLECTING)
    queue.advance(lease, RunStatus.COLLECTED)
    return lease


def test_the_worker_completes_collected_fake_runs(
    queue: ScanQueue, queue_seed: Seeder, world: World
) -> None:
    first = _collected(queue, queue_seed, world)
    second = _collected(queue, queue_seed, world)
    seen: list[RunReport] = []

    reports = Worker(queue, owner="worker-1").drain(on_report=seen.append)

    assert {report.run_id for report in reports} == {first.run_id, second.run_id}
    assert all(report.run_status is RunStatus.SUCCEEDED for report in reports)
    assert all(report.scan_status is ScanStatus.COMPLETED for report in reports)
    assert seen == reports


def test_the_worker_stops_at_the_limit(queue: ScanQueue, queue_seed: Seeder, world: World) -> None:
    _collected(queue, queue_seed, world)
    _collected(queue, queue_seed, world)

    assert len(Worker(queue, owner="worker-1").drain(limit=1)) == 1
    assert len(Worker(queue, owner="worker-1").drain()) == 1
    assert Worker(queue, owner="worker-1").drain() == []


def test_the_worker_retries_expired_parsing(
    queue: ScanQueue, queue_seed: Seeder, world: World
) -> None:
    lease = _collected(queue, queue_seed, world)
    parsing = queue.claim_collected("crashed-worker", FAKE)
    assert parsing is not None
    queue_seed.execute(
        "UPDATE scanner_runs SET lease_expires_at = now() - interval '1 second' WHERE id = :id",
        id=lease.run_id,
    )

    [report] = Worker(queue, owner="worker-1").drain()

    assert (report.run_id, report.run_status) == (lease.run_id, RunStatus.SUCCEEDED)


def test_the_worker_ignores_engines_it_cannot_parse(
    queue: ScanQueue, queue_seed: Seeder, world: World
) -> None:
    _collected(queue, queue_seed, world)

    assert Worker(queue, owner="worker-1", engines=frozenset({ScanEngine.ZAP})).drain() == []


def test_the_worker_leaves_expired_runner_stages_alone(
    queue: ScanQueue, queue_seed: Seeder, world: World
) -> None:
    """runner 階段的 run 是否停止只有 runner 知道：worker 不把它們標成 interrupted。"""
    queue_seed.scan(world.operator_a, queue_seed.scannable(world))
    lease = queue.claim("runner-1", FAKE)
    assert lease is not None
    queue.prepare(lease)
    queue_seed.execute(
        "UPDATE scanner_runs SET lease_expires_at = now() - interval '1 second' WHERE id = :id",
        id=lease.run_id,
    )

    assert Worker(queue, owner="worker-1").drain() == []
    [row] = queue_seed.query("SELECT status FROM scanner_runs WHERE id = :id", id=lease.run_id)
    assert row.status == "running"


# --- preflight（docs/DECISIONS.md §16.5）-----------------------------------------------------

ME = b'{"data": {"username": "name1"}, "status": "success"}'
DENIED = b'{"status": "fail", "message": "Invalid token"}'


def _http(status: int, body: bytes, headers: str = "") -> bytes:
    return f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n{headers}\r\n".encode() + body


def _collected_preflight(
    queue: ScanQueue, seed: Seeder, world: World, runs: Path, outputs: dict[str, bytes]
) -> Lease:
    """綁定 auth profile 的 scan：preflight 的 run 收集好 outputs（runner 的 workspace）。"""
    scannable = seed.scannable(world)
    seed.scan(world.operator_a, scannable, auth_profile_id=scannable.profile.id)
    lease = queue.claim("runner-1", frozenset({ScanEngine.PREFLIGHT}))
    assert lease is not None
    queue.prepare_launch(lease, image_ref=IMAGE)
    workspace = Workspace(runs, runs.parent / "secrets")
    workspace.prepare(lease.run_id, ())
    for name, content in outputs.items():
        (runs / str(lease.run_id) / "out" / name).write_bytes(content)
    queue.advance(lease, RunStatus.COLLECTING)
    workspace.collect(lease.run_id)
    queue.advance(lease, RunStatus.COLLECTED)
    return lease


@pytest.fixture
def runs(tmp_path: Path) -> Path:
    (tmp_path / "runs").mkdir()
    (tmp_path / "secrets").mkdir()
    return tmp_path / "runs"


def _result(seed: Seeder, run_id: UUID) -> tuple[str, str | None]:
    [row] = seed.query(
        "SELECT status, preflight_result FROM scanner_runs WHERE id = :id", id=run_id
    )
    return row.status, row.preflight_result


@pytest.mark.parametrize(
    ("outputs", "expected"),
    [
        ({"authenticated.http": _http(200, ME), "anonymous.http": _http(401, DENIED)}, "passed"),
        ({"authenticated.http": _http(200, ME), "anonymous.http": _http(200, ME)}, "inconclusive"),
        (
            {"authenticated.http": _http(401, DENIED), "anonymous.http": _http(401, DENIED)},
            "failed",
        ),
        (
            {
                "authenticated.http": _http(403, b"blocked", "X-Secscan-Guard: RUN_BLOCKED\r\n"),
                "anonymous.http": _http(403, b"blocked", "X-Secscan-Guard: RUN_BLOCKED\r\n"),
            },
            "blocked",
        ),
        ({}, "not_executed"),
    ],
    ids=["passed", "inconclusive", "failed", "blocked", "no-output"],
)
def test_the_worker_judges_the_preflight(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    runs: Path,
    outputs: dict[str, bytes],
    expected: str,
) -> None:
    lease = _collected_preflight(queue, queue_seed, world, runs, outputs)

    [report] = Worker(queue, owner="worker-1", artifacts=ArtifactReader(runs)).drain()

    assert report.run_id == lease.run_id
    assert _result(queue_seed, lease.run_id) == ("succeeded", expected)


def test_without_a_reader_the_preflight_was_not_executed(
    queue: ScanQueue, queue_seed: Seeder, world: World, runs: Path
) -> None:
    outputs = {"authenticated.http": _http(200, ME), "anonymous.http": _http(401, DENIED)}
    lease = _collected_preflight(queue, queue_seed, world, runs, outputs)

    Worker(queue, owner="worker-1").drain()

    assert _result(queue_seed, lease.run_id) == ("succeeded", "not_executed")


def test_only_preflight_runs_can_have_a_result(
    queue: ScanQueue, queue_seed: Seeder, world: World
) -> None:
    lease = _collected(queue, queue_seed, world)
    parsing = queue.claim_collected("worker-1", FAKE)
    assert parsing is not None

    with pytest.raises(LeaseLostError):
        queue.record_preflight(parsing, PreflightResult.PASSED)
    assert _result(queue_seed, lease.run_id) == ("normalizing", None)
