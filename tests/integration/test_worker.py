"""worker（docs/DECISIONS.md §14.6）：T10 只把 fake 的 collected 標成 succeeded，不讀任何檔案。

每個測試用自己的資料庫（queue_database）。
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.guard.domain.telemetry import (
    ForwardedRequest,
    UpstreamResponse,
    encode_line,
    telemetry_file_name,
)
from secscan.runner.workspace import Workspace
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus, ScanStatus
from secscan.scans.domain.model import Lease
from secscan.scans.domain.preflight import PreflightResult
from secscan.scans.queue import LeaseLostError, RunReport, RunUsage, ScanQueue
from secscan.worker.artifacts import ArtifactReader
from secscan.worker.service import Worker
from secscan.worker.telemetry import TelemetryReader
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
    queue: ScanQueue,
    seed: Seeder,
    world: World,
    runs: Path,
    outputs: dict[str, bytes],
    *,
    sent: int | None = 2,
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
    queue.record_usage(lease, RunUsage(requests_sent=sent, requests_denied=0, traffic_seconds=1))
    queue.advance(lease, RunStatus.COLLECTING)
    workspace.collect(lease.run_id, exit_code=0, inputs=())
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


def test_a_succeeded_preflight_does_not_make_a_failed_scan_partial(
    queue: ScanQueue, queue_seed: Seeder, world: World
) -> None:
    """preflight 不是結果引擎（docs/DECISIONS.md §19.8）：掃描引擎失敗時 scan 是 failed。"""
    scannable = queue_seed.scannable(world)
    scan = queue_seed.scan(world.operator_a, scannable, auth_profile_id=scannable.profile.id)
    preflight = queue.claim("runner-1", frozenset({ScanEngine.PREFLIGHT}))
    assert preflight is not None
    queue.prepare(preflight)
    queue.advance(preflight, RunStatus.COLLECTING)
    queue.advance(preflight, RunStatus.COLLECTED)
    parsing = queue.claim_collected("worker-1", frozenset({ScanEngine.PREFLIGHT}))
    assert parsing is not None
    queue.advance(parsing, RunStatus.SUCCEEDED)
    fake = queue.claim("runner-1", FAKE)
    assert fake is not None
    queue.prepare(fake)

    progress = queue.advance(fake, RunStatus.FAILED, error_code=RunErrorCode.ENGINE_FAILED)

    assert progress.scan_status is ScanStatus.FAILED
    [row] = queue_seed.query("SELECT status FROM scans WHERE id = :id", id=scan.id)
    assert row.status == "failed"


# --- coverage（docs/DECISIONS.md §16.6）------------------------------------------------------


def _forwarded(telemetry: Path, run_id: UUID, *requests: tuple[str, bool]) -> None:
    """guard 寫的 telemetry：每個請求一行，接著上游的 200 回應一行。"""
    lines = b"".join(
        encode_line(
            ForwardedRequest(sequence=index, at=1.0, method="GET", path=path, authenticated=auth)
        )
        + encode_line(UpstreamResponse(sequence=index, at=1.1, status=200))
        for index, (path, auth) in enumerate(requests, 1)
    )
    (telemetry / telemetry_file_name(run_id)).write_bytes(lines)


def _coverage(seed: Seeder, run_id: UUID) -> tuple[bool, list[tuple[int, bool]]]:
    [run] = seed.query("SELECT coverage_recorded FROM scanner_runs WHERE id = :id", id=run_id)
    rows = seed.query(
        "SELECT ordinal, authenticated FROM run_coverage WHERE scanner_run_id = :id "
        "ORDER BY ordinal",
        id=run_id,
    )
    return run.coverage_recorded, [(row.ordinal, row.authenticated) for row in rows]


def _worker(queue: ScanQueue, runs: Path, telemetry: Path) -> Worker:
    return Worker(
        queue,
        owner="worker-1",
        artifacts=ArtifactReader(runs),
        telemetry=TelemetryReader(telemetry),
    )


def _collected_engine_run(
    queue: ScanQueue, seed: Seeder, world: World, *, sent: int | None
) -> Lease:
    """匿名的 scan：fake 的容器 run 轉送了 sent 個請求之後收集好（M3 的引擎同樣的路徑）。"""
    seed.scan(world.operator_a, seed.scannable(world))
    lease = queue.claim("runner-1", FAKE)
    assert lease is not None
    queue.prepare_launch(lease, image_ref=IMAGE)
    queue.record_usage(lease, RunUsage(requests_sent=sent, requests_denied=0, traffic_seconds=1))
    queue.advance(lease, RunStatus.COLLECTING)
    queue.advance(lease, RunStatus.COLLECTED)
    return lease


def test_forwarded_requests_are_mapped_to_operations(
    queue: ScanQueue, queue_seed: Seeder, world: World, runs: Path, tmp_path: Path
) -> None:
    lease = _collected_engine_run(queue, queue_seed, world, sent=2)
    _forwarded(tmp_path, lease.run_id, ("/me", False), ("/items/5", True))

    _worker(queue, runs, tmp_path).drain()

    [ordinal] = [row.ordinal for row in queue_seed.query("SELECT ordinal FROM scan_operations")]
    assert _coverage(queue_seed, lease.run_id) == (True, [(ordinal, True)])


def test_preflight_requests_are_not_coverage(
    queue: ScanQueue, queue_seed: Seeder, world: World, runs: Path, tmp_path: Path
) -> None:
    """preflight 是平台的健檢探測，不是安全測試：它的請求不算進 observed（審查發現）。"""
    lease = _collected_preflight(queue, queue_seed, world, runs, {}, sent=2)
    _forwarded(tmp_path, lease.run_id, ("/items/5", True), ("/items/5", False))

    _worker(queue, runs, tmp_path).drain()

    assert _coverage(queue_seed, lease.run_id) == (True, [])


def test_a_worker_interrupted_after_recording_coverage_finishes_on_retry(
    queue: ScanQueue, queue_seed: Seeder, world: World, runs: Path, tmp_path: Path
) -> None:
    """coverage 寫入之後、succeeded 之前中斷：退回 collected 再解析一次仍能完成（審查發現）。"""
    lease = _collected_engine_run(queue, queue_seed, world, sent=0)
    parsing = queue.claim_collected("worker-1", FAKE)
    assert parsing is not None
    queue.record_coverage(parsing, {})
    queue_seed.execute(
        "UPDATE scanner_runs SET lease_expires_at = now() - interval '1 second' WHERE id = :id",
        id=lease.run_id,
    )

    [report] = _worker(queue, runs, tmp_path).drain()

    assert report.run_status is RunStatus.SUCCEEDED
    assert _coverage(queue_seed, lease.run_id) == (True, [])


def test_a_run_without_traffic_is_measured_with_nothing_covered(
    queue: ScanQueue, queue_seed: Seeder, world: World, runs: Path, tmp_path: Path
) -> None:
    lease = _collected_engine_run(queue, queue_seed, world, sent=0)

    _worker(queue, runs, tmp_path).drain()

    assert _coverage(queue_seed, lease.run_id) == (True, [])


@pytest.mark.parametrize(
    ("sent", "requests"),
    [
        (None, [("/items/5", True)]),  # 轉送數不明（guard 重啟或 telemetry 遺失）
        (2, []),  # 沒有 telemetry 檔
        (1, [("/items/5", True), ("/items/6", True)]),  # 行數比轉送數多：不一致
    ],
    ids=["unknown", "missing", "inconsistent"],
)
def test_incomplete_telemetry_leaves_the_run_unmeasured(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    runs: Path,
    tmp_path: Path,
    sent: int | None,
    requests: list[tuple[str, bool]],
) -> None:
    lease = _collected_engine_run(queue, queue_seed, world, sent=sent)
    if requests:
        _forwarded(tmp_path, lease.run_id, *requests)

    _worker(queue, runs, tmp_path).drain()

    assert _coverage(queue_seed, lease.run_id) == (False, [])


def test_coverage_is_recorded_once(
    queue: ScanQueue, queue_seed: Seeder, world: World, runs: Path
) -> None:
    lease = _collected_preflight(queue, queue_seed, world, runs, {}, sent=0)
    parsing = queue.claim_collected("worker-1", frozenset({ScanEngine.PREFLIGHT}))
    assert parsing is not None
    queue.record_coverage(parsing, {})

    with pytest.raises(LeaseLostError):
        queue.record_coverage(parsing, {})
    assert _coverage(queue_seed, lease.run_id) == (True, [])


def test_a_lost_lease_skips_the_run_instead_of_stopping_the_worker(
    queue: ScanQueue, queue_seed: Seeder, world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """解析中 lease 失效（例如解析太久）：記下來、留給對帳，繼續處理其他 run（審查發現）。"""
    first = _collected(queue, queue_seed, world)
    second = _collected(queue, queue_seed, world)
    advance = queue.advance

    def lose_the_first(lease: Lease, to: RunStatus, **options: Any) -> Any:
        if lease.run_id == first.run_id and to is RunStatus.SUCCEEDED:
            raise LeaseLostError("lease 已過期")
        return advance(lease, to, **options)

    monkeypatch.setattr(queue, "advance", lose_the_first)

    reports = Worker(queue, owner="worker-1").drain()

    assert [report.run_id for report in reports] == [second.run_id]
