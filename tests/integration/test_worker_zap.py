"""worker 解析 zap 的輸出（docs/DECISIONS.md §19.7）：真實的輸出經 runner 的收集，走到 DB。

每份 fixture 得到預期的 run、scan、observation 與 artifact；壞掉的輸出是判定，不是崩潰；寫入之後、
run 結束之前中斷時，重試以存下的判定結束；解析中要求取消不影響結果；解析期間延長 lease。
每個測試用自己的資料庫（queue_database）。
"""

import json
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.guard.domain.telemetry import telemetry_file_name
from secscan.runner.workspace import Workspace
from secscan.scanners.domain.plan import InputFile
from secscan.scanners.domain.zap.policy import REQUIRED_ADDONS, ZAP_IMAGE, ZAP_VERSION
from secscan.scanners.domain.zap.results import PARSER_VERSION
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.catalog import ScanProfile
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.domain.model import Lease
from secscan.scans.domain.observation import (
    ArtifactKind,
    ArtifactRecord,
    ParsedRun,
    RunOutcome,
)
from secscan.scans.domain.request import BudgetRequest, ScanRequest
from secscan.scans.queue import Heartbeat, LeaseLostError, RunUsage, ScanQueue
from secscan.targets.domain import TargetKind
from secscan.worker.artifacts import ArtifactReader
from secscan.worker.service import Worker
from secscan.worker.telemetry import TelemetryReader
from tests.integration.api_support import LAB, Seeder, World

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "zap"
MANIFEST = json.loads((FIXTURES.parent / "manifest.json").read_text(encoding="utf-8"))
ZAP = frozenset({ScanEngine.ZAP})
PLAN = InputFile("plan.yaml", b'{"jobs": []}')
SUCCEEDED_LOG = b"Job report finished\nAutomation plan succeeded!\n"


def _entry(scenario: str, name: str) -> dict[str, Any]:
    [entry] = [item for item in MANIFEST["fixtures"] if item["path"] == f"zap/{scenario}/{name}"]
    return dict(entry)


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


def _scan(seed: Seeder, world: World, origin: str) -> UUID:
    target = seed.target(world.operator_a, world.project_a.id, origin, kind=TargetKind.WEB)
    grant = seed.approve(
        world.admin,
        seed.grant(
            world.operator_a,
            target,
            paths=(),
            allow_all_paths=True,
            excluded_paths=("/admin",),
            methods=("GET", "HEAD"),
        ),
    )
    request = ScanRequest(
        target_id=target.id,
        scope_grant_id=grant.id,
        api_spec_id=None,
        auth_profile_id=None,
        profile=ScanProfile.WEB_ACTIVE_LAB,
        engines=(ScanEngine.ZAP,),
        budget=BudgetRequest(),
    )
    return seed.create_scan(world.operator_a, request).id


def _collected(
    queue: ScanQueue,
    seed: Seeder,
    world: World,
    dirs: Dirs,
    scenario: str,
    *,
    origin: str | None = None,
    exit_code: int | None = None,
    change: Callable[[Path], None] = lambda out: None,
) -> Lease:
    """一個 zap 的 run 收集好這份 fixture 的輸出（runner 的 workspace 寫的 manifest）。"""
    log = _entry(scenario, "zap.log")
    _scan(seed, world, origin or log["target"])
    lease = queue.claim("runner-1", ZAP)
    assert lease is not None
    queue.prepare_launch(lease, image_ref=str(ZAP_IMAGE))
    workspace = Workspace(dirs.runs, dirs.secrets)
    workspace.prepare(lease.run_id, (PLAN,))
    out = dirs.runs / str(lease.run_id) / "out"
    source = FIXTURES / scenario
    shutil.copyfile(source / "zap.log", out / "zap.log")
    if (source / "report.json").exists():
        shutil.copyfile(source / "report.json", out / "zap-report.json")
    change(out)
    sent = 0
    if (source / "telemetry.jsonl").exists():
        lines = (source / "telemetry.jsonl").read_bytes()
        (dirs.telemetry / telemetry_file_name(lease.run_id)).write_bytes(lines)
        sent = sum(1 for line in lines.splitlines() if b'"e":"request"' in line.replace(b" ", b""))
    queue.record_usage(lease, RunUsage(requests_sent=sent, requests_denied=0, traffic_seconds=1))
    queue.advance(lease, RunStatus.COLLECTING)
    code = exit_code if exit_code is not None else log["exit_code"]
    workspace.collect(lease.run_id, exit_code=code, inputs=(PLAN,))
    queue.advance(lease, RunStatus.COLLECTED)
    return lease


def _worker(queue: ScanQueue, dirs: Dirs, **options: Any) -> Worker:
    return Worker(
        queue,
        owner="worker-1",
        artifacts=ArtifactReader(dirs.runs),
        telemetry=TelemetryReader(dirs.telemetry),
        **options,
    )


def _run(seed: Seeder, run_id: UUID) -> Any:
    [row] = seed.query(
        "SELECT status, error_code, results_recorded, parser_version, engine_version, exit_code, "
        "observation_count, result_details, coverage_recorded FROM scanner_runs WHERE id = :id",
        id=run_id,
    )
    return row


def _scan_status(seed: Seeder, scan_id: UUID) -> str:
    [row] = seed.query("SELECT status FROM scans WHERE id = :id", id=scan_id)
    return str(row.status)


def _observations(seed: Seeder, run_id: UUID) -> list[Any]:
    return list(
        seed.query(
            "SELECT * FROM observations WHERE scanner_run_id = :id ORDER BY ordinal", id=run_id
        )
    )


def _artifacts(seed: Seeder, run_id: UUID) -> list[Any]:
    rows = seed.query("SELECT * FROM artifacts WHERE scanner_run_id = :id", id=run_id)
    return sorted(rows, key=lambda row: (row.kind, row.path))


@pytest.mark.parametrize(
    ("scenario", "status", "error_code", "scan_status", "observations"),
    [
        ("clean", "succeeded", None, "completed", 0),
        ("findings", "succeeded", None, "completed", 11),
        ("timeout", "timed_out", "ENGINE_TIMEOUT", "timed_out", 11),
        ("unanswered", "failed", "NO_TARGET_TRAFFIC", "failed", 0),
        ("unreachable", "failed", "ENGINE_REPORTED_ERRORS", "failed", 0),
        ("engine-error", "failed", "ENGINE_FAILED", "failed", 0),
    ],
)
def test_each_recorded_output_ends_as_expected(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    dirs: Dirs,
    scenario: str,
    status: str,
    error_code: str | None,
    scan_status: str,
    observations: int,
) -> None:
    lease = _collected(queue, queue_seed, world, dirs, scenario)

    [report] = _worker(queue, dirs).drain()

    assert report.run_status.value == status
    run = _run(queue_seed, lease.run_id)
    assert (run.status, run.error_code) == (status, error_code)
    assert _scan_status(queue_seed, lease.scan_id) == scan_status
    assert run.results_recorded is True
    assert run.parser_version == PARSER_VERSION
    assert run.exit_code == _entry(scenario, "zap.log")["exit_code"]
    assert run.observation_count == observations
    assert len(_observations(queue_seed, lease.run_id)) == observations
    assert run.result_details["status"] == status
    assert run.result_details["error_code"] == error_code


def test_the_observations_keep_the_tool_values_and_the_run(
    queue: ScanQueue, queue_seed: Seeder, world: World, dirs: Dirs
) -> None:
    lease = _collected(queue, queue_seed, world, dirs, "findings")

    _worker(queue, dirs).drain()

    rows = _observations(queue_seed, lease.run_id)
    assert [row.ordinal for row in rows] == list(range(1, 12))
    first = rows[0]
    assert first.scan_id == lease.scan_id
    assert (first.source_rule, first.rule_variant) == ("10202", "10202")
    assert first.title == "Absence of Anti-CSRF Tokens"
    assert (first.raw_severity, first.raw_confidence) == ("2", "1")
    assert (first.cwe_id, first.wasc_id) == (352, 9)
    assert (first.method, first.path, first.query) == ("GET", "/", None)
    assert first.parameter_location == "unknown"
    assert first.evidence == '<form action="/login" method="post">'
    assert first.auth_role == "anonymous"
    assert first.parser_version == PARSER_VERSION
    query = [row for row in rows if row.query == "q=hello"]
    assert query
    assert {row.path for row in query} == {"/search"}


def test_the_artifacts_describe_the_collected_files(
    queue: ScanQueue, queue_seed: Seeder, world: World, dirs: Dirs
) -> None:
    lease = _collected(queue, queue_seed, world, dirs, "findings")

    _worker(queue, dirs).drain()

    rows = _artifacts(queue_seed, lease.run_id)
    assert [(row.kind, row.path) for row in rows] == [
        ("input", "plan.yaml"),
        ("output", "zap-report.json"),
        ("output", "zap.log"),
    ]
    plan, report, log = rows
    assert plan.classification == "input"
    assert report.classification == log.classification == "masked"
    assert report.storage_key == f"{lease.run_id}/out/zap-report.json"
    assert plan.storage_key == f"{lease.run_id}/in/plan.yaml"
    assert report.size == (FIXTURES / "findings" / "report.json").stat().st_size
    assert report.sha256 == _entry("findings", "report.json")["sha256"]
    assert {row.report_artifact_id for row in _observations(queue_seed, lease.run_id)} == {
        report.id
    }


def test_the_versions_of_the_run_are_stored(
    queue: ScanQueue, queue_seed: Seeder, world: World, dirs: Dirs
) -> None:
    lease = _collected(queue, queue_seed, world, dirs, "clean")

    _worker(queue, dirs).drain()

    run = _run(queue_seed, lease.run_id)
    assert run.engine_version == ZAP_VERSION
    assert run.result_details["components"] == dict(REQUIRED_ADDONS)
    assert run.result_details["traffic_verified"] is True


def test_coverage_is_recorded_for_a_zap_run(
    queue: ScanQueue, queue_seed: Seeder, world: World, dirs: Dirs
) -> None:
    lease = _collected(queue, queue_seed, world, dirs, "findings")

    _worker(queue, dirs).drain()

    assert _run(queue_seed, lease.run_id).coverage_recorded is True


# --- 壞掉的輸出 ---------------------------------------------------------------------------


def _write(name: str, content: bytes) -> Callable[[Path], None]:
    def write(out: Path) -> None:
        (out / name).write_bytes(content)

    return write


def _remove(name: str) -> Callable[[Path], None]:
    return lambda out: (out / name).unlink()


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        (_write("zap-report.json", b"{"), "report_not_json"),
        (_write("zap-report.json", b""), "report_not_json"),
        (_write("zap-report.json", b"\xff\xfe"), "report_not_json"),
        (_write("zap.log", b"no summary"), "summary_missing"),
        (_remove("zap-report.json"), "report_unreadable"),
        (_remove("zap.log"), "log_unreadable"),
    ],
    ids=["truncated", "empty", "binary", "no-summary", "no-report", "no-log"],
)
def test_broken_output_is_an_outcome_not_a_crash(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    dirs: Dirs,
    change: Callable[[Path], None],
    problem: str,
) -> None:
    lease = _collected(queue, queue_seed, world, dirs, "findings", change=change)

    [report] = _worker(queue, dirs).drain()

    assert report.run_status is RunStatus.FAILED
    run = _run(queue_seed, lease.run_id)
    assert run.error_code == "OUTPUT_INVALID"
    assert run.result_details["problem"] == problem
    assert run.observation_count == 0
    assert _observations(queue_seed, lease.run_id) == []


def test_text_that_postgres_cannot_store_does_not_stop_the_worker(
    queue: ScanQueue, queue_seed: Seeder, world: World, dirs: Dirs
) -> None:
    """NUL 與孤立的 surrogate：原本 psycopg 會拒絕，worker 反覆崩潰。"""

    def poison(out: Path) -> None:
        document = json.loads((out / "zap-report.json").read_bytes())
        instance = document["site"][0]["alerts"][0]["instances"][0]
        instance["evidence"] = "nul\x00 lone\ud800"
        (out / "zap-report.json").write_text(json.dumps(document))

    lease = _collected(queue, queue_seed, world, dirs, "findings", change=poison)

    [report] = _worker(queue, dirs).drain()

    assert report.run_status is RunStatus.SUCCEEDED
    first = _observations(queue_seed, lease.run_id)[0]
    assert first.evidence == "nul� lone�"


def test_a_report_of_another_version_is_not_parsed(
    queue: ScanQueue, queue_seed: Seeder, world: World, dirs: Dirs
) -> None:
    def older(out: Path) -> None:
        document = json.loads((out / "zap-report.json").read_bytes())
        document["@version"] = "2.16.1"
        (out / "zap-report.json").write_text(json.dumps(document))

    lease = _collected(queue, queue_seed, world, dirs, "findings", change=older)

    _worker(queue, dirs).drain()

    run = _run(queue_seed, lease.run_id)
    assert (run.error_code, run.result_details["problem"]) == ("OUTPUT_INVALID", "report_version")


def test_an_unreadable_manifest_is_invalid_output(
    queue: ScanQueue, queue_seed: Seeder, world: World, dirs: Dirs
) -> None:
    lease = _collected(queue, queue_seed, world, dirs, "findings")
    manifest = dirs.runs / str(lease.run_id) / "manifest.json"
    manifest.chmod(0o600)
    manifest.write_bytes(b"{")

    _worker(queue, dirs).drain()

    run = _run(queue_seed, lease.run_id)
    assert run.error_code == "OUTPUT_INVALID"
    assert run.exit_code is None
    assert _artifacts(queue_seed, lease.run_id) == []


def test_a_worker_without_the_volumes_cannot_read_the_output(
    queue: ScanQueue, queue_seed: Seeder, world: World, dirs: Dirs
) -> None:
    lease = _collected(queue, queue_seed, world, dirs, "findings")

    Worker(queue, owner="worker-1").drain()

    assert _run(queue_seed, lease.run_id).error_code == "OUTPUT_INVALID"


def test_missing_telemetry_keeps_the_observations_unverified(
    queue: ScanQueue, queue_seed: Seeder, world: World, dirs: Dirs
) -> None:
    lease = _collected(queue, queue_seed, world, dirs, "findings")
    (dirs.telemetry / telemetry_file_name(lease.run_id)).unlink()

    _worker(queue, dirs).drain()

    run = _run(queue_seed, lease.run_id)
    assert run.status == "succeeded"
    assert run.result_details["traffic_verified"] is False
    assert run.observation_count == 11


# --- 寫入與重試 ---------------------------------------------------------------------------


def _parsed(outcome: RunOutcome | None = None) -> ParsedRun:
    return ParsedRun("p/1", outcome or RunOutcome(RunStatus.SUCCEEDED))


def test_results_are_written_only_once(
    queue: ScanQueue, queue_seed: Seeder, world: World, dirs: Dirs
) -> None:
    _collected(queue, queue_seed, world, dirs, "clean")
    parsing = queue.claim_collected("worker-1", ZAP)
    assert parsing is not None
    queue.record_results(parsing, _parsed(), (), exit_code=0)

    with pytest.raises(LeaseLostError):
        queue.record_results(parsing, _parsed(), (), exit_code=0)


def test_results_need_the_lease(
    queue: ScanQueue, queue_seed: Seeder, world: World, dirs: Dirs
) -> None:
    lease = _collected(queue, queue_seed, world, dirs, "clean")

    with pytest.raises(LeaseLostError):
        queue.record_results(lease, _parsed(), (), exit_code=0)

    assert _run(queue_seed, lease.run_id).results_recorded is False


def test_the_results_are_written_together(
    queue: ScanQueue, queue_seed: Seeder, world: World, dirs: Dirs
) -> None:
    """同一個 transaction：artifact 寫不進去時，run 也沒有結果。"""
    _collected(queue, queue_seed, world, dirs, "clean")
    parsing = queue.claim_collected("worker-1", ZAP)
    assert parsing is not None
    bad = ArtifactRecord(ArtifactKind.OUTPUT, "a", "not-a-hash", 1)

    with pytest.raises(Exception, match="sha256_valid"):
        queue.record_results(parsing, _parsed(), (bad,), exit_code=0)

    assert _run(queue_seed, parsing.run_id).results_recorded is False
    assert _artifacts(queue_seed, parsing.run_id) == []


def test_a_retry_uses_the_stored_outcome(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    dirs: Dirs,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """寫入之後、run 結束之前中斷：輸出已經刪掉也能結束，而且不重複寫入。"""
    lease = _collected(queue, queue_seed, world, dirs, "timeout")
    real = queue.advance

    def crash(*_: object, **__: object) -> None:
        raise RuntimeError("crashed before the transition")

    monkeypatch.setattr(queue, "advance", crash)
    assert _worker(queue, dirs).drain() == []
    monkeypatch.setattr(queue, "advance", real)
    assert _run(queue_seed, lease.run_id).status == "normalizing"
    assert _run(queue_seed, lease.run_id).results_recorded is True
    queue_seed.execute(
        "UPDATE scanner_runs SET lease_expires_at = now() - interval '1 second' WHERE id = :id",
        id=lease.run_id,
    )
    shutil.rmtree(dirs.runs / str(lease.run_id))

    [report] = _worker(queue, dirs).drain()

    assert report.run_status is RunStatus.TIMED_OUT
    run = _run(queue_seed, lease.run_id)
    assert run.error_code == "ENGINE_TIMEOUT"
    assert len(_observations(queue_seed, lease.run_id)) == 11


def test_a_cancel_request_does_not_interrupt_parsing(
    queue: ScanQueue, queue_seed: Seeder, world: World, dirs: Dirs
) -> None:
    """沒有 normalizing → cancelled：解析照常完成，scan 由彙總成為 cancelled（§13.4）。"""
    lease = _collected(queue, queue_seed, world, dirs, "findings")
    queue_seed.execute(
        "UPDATE scans SET cancel_requested_at = now() WHERE id = :id", id=lease.scan_id
    )

    [report] = _worker(queue, dirs).drain()

    assert report.run_status is RunStatus.SUCCEEDED
    assert _scan_status(queue_seed, lease.scan_id) == "cancelled"
    assert _run(queue_seed, lease.run_id).observation_count == 11


def test_parsing_extends_the_lease_and_reports_the_heartbeat(
    queue: ScanQueue, queue_seed: Seeder, world: World, dirs: Dirs
) -> None:
    lease = _collected(queue, queue_seed, world, dirs, "findings")
    moments = iter(range(0, 6000, 6))
    beats: list[int] = []
    worker = _worker(queue, dirs, monotonic=lambda: float(next(moments)))

    [report] = worker.drain(on_heartbeat=lambda: beats.append(1))

    assert report.run_id == lease.run_id
    assert beats


def test_a_stop_reason_does_not_interrupt_parsing(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    dirs: Dirs,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """授權撤回只停止還在送流量的 run；解析不送流量，輸出仍然要保留。"""
    lease = _collected(queue, queue_seed, world, dirs, "findings")
    moments = iter(range(0, 6000, 6))
    monkeypatch.setattr(
        queue,
        "heartbeat",
        lambda _: Heartbeat(
            valid=True, cancel_requested=False, stop_reason=RunErrorCode.SCOPE_REVOKED
        ),
    )

    [report] = _worker(queue, dirs, monotonic=lambda: float(next(moments))).drain()

    assert (report.run_id, report.run_status) == (lease.run_id, RunStatus.SUCCEEDED)


def test_a_lost_lease_leaves_the_run_to_the_reconciler(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    dirs: Dirs,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lease = _collected(queue, queue_seed, world, dirs, "findings")
    moments = iter(range(0, 6000, 6))
    monkeypatch.setattr(
        queue, "heartbeat", lambda _: Heartbeat(valid=False, cancel_requested=False)
    )

    reports = _worker(queue, dirs, monotonic=lambda: float(next(moments))).drain()

    assert reports == []
    run = _run(queue_seed, lease.run_id)
    assert run.status == "normalizing"
    assert run.results_recorded is False
