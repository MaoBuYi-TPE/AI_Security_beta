"""secscan-admin runner／worker（docs/DECISIONS.md §14.6、§14.8）：輸出只到 stderr。

Docker 以記憶體中的假 runtime 取代（測試程序連不到 daemon）；每個測試用自己的資料庫。
"""

import logging
import os
import signal
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from secscan.cli import EXIT_FAILURE, EXIT_OK, main
from secscan.cli.services import stop_signals
from secscan.runner.docker_runtime import DockerRuntime
from secscan.runner.layout import init_layout
from secscan.runner.loop import RunnerLoop
from secscan.scanners.domain.zap.policy import ZAP_IMAGE
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.queue import ScanQueue
from secscan.worker.loop import WorkerLoop
from tests.guard_support import GuardDouble
from tests.integration.api_support import LAB, Scannable, Seeder, World
from tests.integration.database import ProvisionedDatabase
from tests.runner_fakes import FakeContainerRuntime
from tests.secret_support import (
    TEST_CONTENT_ENCRYPTION_KEYS,
    TEST_EVIDENCE_ENCRYPTION_KEYS,
    TEST_SECRET_ENCRYPTION_KEYS,
)

pytestmark = pytest.mark.integration

UNREACHABLE_PORT = 1


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


@pytest.fixture
def scannable(queue_seed: Seeder, world: World) -> Scannable:
    return queue_seed.scannable(world)


@pytest.fixture
def runtime(monkeypatch: pytest.MonkeyPatch) -> FakeContainerRuntime:
    fake = FakeContainerRuntime()
    # 這裡測的是 CLI 組好的 fake 流程：沒有 zap 的映像，就不會建立 zap 的 probe 容器。
    del fake.images[str(ZAP_IMAGE)]
    monkeypatch.setattr(DockerRuntime, "connect", lambda _url: fake)
    return fake


@pytest.fixture
def environment(
    queue_database: ProvisionedDatabase, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Path:
    """以環境變數指向測試的資料庫與暫存目錄（runs volume 是新的 layout；worker 只看 active/）。"""
    for name in ("runs", "secrets"):
        (tmp_path / name).mkdir()
    init_layout(tmp_path / "runs")
    monkeypatch.setenv("WORKER_RUNS_DIR", str(tmp_path / "runs" / "active"))
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("DB_HOST", queue_database.host)
    monkeypatch.setenv("DB_PORT", str(queue_database.port))
    monkeypatch.setenv("DB_NAME", queue_database.name)
    monkeypatch.setenv("DB_USER", queue_database.user)
    monkeypatch.setenv("DB_PASSWORD", queue_database.password)
    monkeypatch.setenv("SECRET_ENCRYPTION_KEYS", TEST_SECRET_ENCRYPTION_KEYS)
    monkeypatch.setenv("EVIDENCE_ENCRYPTION_KEYS", TEST_EVIDENCE_ENCRYPTION_KEYS)
    monkeypatch.setenv("CONTENT_ENCRYPTION_KEYS", TEST_CONTENT_ENCRYPTION_KEYS)
    monkeypatch.setenv("RUNNER_RUNS_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("RUNNER_SECRETS_DIR", str(tmp_path / "secrets"))
    guard = GuardDouble.create(tmp_path)
    monkeypatch.setenv("RUNNER_GUARD_POLICIES_DIR", str(guard.policies))
    monkeypatch.setenv("RUNNER_GUARD_STATUS_DIR", str(guard.status_dir))
    monkeypatch.setenv("RUNNER_GUARD_TELEMETRY_DIR", str(guard.telemetry))
    return tmp_path


def _run_status(seed: Seeder, scan_id: UUID) -> tuple[str, str | None]:
    [row] = seed.query(
        "SELECT status, error_code FROM scanner_runs WHERE scan_id = :id", id=scan_id
    )
    return row.status, row.error_code


def test_the_runner_and_the_worker_finish_a_fake_scan(
    environment: Path,
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    capsys: pytest.CaptureFixture[str],
) -> None:
    scan = queue_seed.scan(world.operator_a, scannable)

    assert main(["runner", "--once"]) == EXIT_OK
    assert _run_status(queue_seed, scan.id) == ("collected", None)
    assert main(["worker", "--once"]) == EXIT_OK

    out, err = capsys.readouterr()
    assert out == ""
    assert _run_status(queue_seed, scan.id) == ("succeeded", None)
    assert f"scan {scan.id}" in err
    assert "collected" in err
    assert "succeeded" in err
    assert len(runtime.created) == 1
    [row] = queue_seed.query("SELECT count(*) AS n FROM runner_instances")
    assert row.n == 2


def test_the_next_runner_pass_seals_the_finished_run(
    environment: Path,
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--once 在處理之前與結束之前各跑一輪 keeper（docs/DECISIONS.md §30.3）：解析完成之後的下一次
    runner 加密這個 run 的目錄，之後只剩 sealed/。"""
    scan = queue_seed.scan(world.operator_a, scannable)
    assert main(["runner", "--once"]) == EXIT_OK
    [run] = queue_seed.query("SELECT id FROM scanner_runs WHERE scan_id = :id", id=scan.id)
    root = environment / "runs" / "active" / str(run.id)
    assert (root / "manifest.json").exists()
    assert main(["worker", "--once"]) == EXIT_OK

    assert main(["runner", "--once"]) == EXIT_OK

    [evidence] = queue_seed.query(
        "SELECT status, file_count FROM run_evidence WHERE scanner_run_id = :id", id=run.id
    )
    assert evidence.status == "sealed"
    assert evidence.file_count >= 1
    assert {entry.name for entry in root.iterdir()} == {"sealed"}
    capsys.readouterr()


def test_the_runner_stops_claiming_when_evidence_cannot_be_sealed(
    environment: Path,
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    queue_engine: Engine,
    world: World,
    scannable: Scannable,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """一個已終止的 run 無法加密：保留原狀、不記下 sealed；--once 不認領新的 run，exit 1。

    sealed/ 中有不認得的檔案（fail closed；缺少權限的目錄 keeper 會自己補上，§30.11）。
    """
    caplog.set_level(logging.ERROR)
    queue = ScanQueue(
        sessionmaker(queue_engine, expire_on_commit=False), lab=LAB, clock=lambda: datetime.now(UTC)
    )
    queue_seed.scan(world.operator_a, scannable)
    lease = queue.claim("runner-elsewhere", frozenset({ScanEngine.FAKE}))
    assert lease is not None
    out = environment / "runs" / "active" / str(lease.run_id) / "out"
    out.mkdir(parents=True)
    (out / "report.json").write_bytes(b"canary-unsealable")
    queue.prepare(lease)
    queue.advance(lease, RunStatus.FAILED, error_code=RunErrorCode.ENGINE_FAILED)
    second = queue_seed.scan(world.operator_a, queue_seed.scannable(world))
    sealed = out.parent / "sealed"
    sealed.mkdir()
    (sealed / "unexpected").write_bytes(b"x")

    assert main(["runner", "--once"]) == EXIT_FAILURE

    err = capsys.readouterr().err
    assert "原始證據無法加密或清除" in err
    assert str(lease.run_id) in caplog.text
    assert str(environment) not in caplog.text
    assert (out / "report.json").read_bytes() == b"canary-unsealable"
    assert (
        queue_seed.query("SELECT 1 FROM run_evidence WHERE scanner_run_id = :id", id=lease.run_id)
        == []
    )
    assert _run_status(queue_seed, second.id) == ("queued", None)
    assert runtime.created == []


@pytest.mark.parametrize(
    ("arguments", "environment_value"),
    [(["--outcome", "fail"], None), ([], "fail")],
)
def test_the_fake_outcome_comes_from_the_flag_or_the_environment(
    environment: Path,
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    monkeypatch: pytest.MonkeyPatch,
    arguments: list[str],
    environment_value: str | None,
) -> None:
    scan = queue_seed.scan(world.operator_a, scannable)
    if environment_value is not None:
        monkeypatch.setenv("RUNNER_FAKE_OUTCOME", environment_value)

    assert main(["runner", "--once", *arguments]) == EXIT_OK
    assert _run_status(queue_seed, scan.id) == ("failed", "ENGINE_FAILED")


def test_nothing_to_do(
    environment: Path, runtime: FakeContainerRuntime, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["runner", "--once"]) == EXIT_OK
    assert main(["worker", "--once"]) == EXIT_OK

    err = capsys.readouterr().err
    assert "沒有排隊中的 run" in err
    assert "沒有等待解析的 run" in err


def test_an_unready_environment_fails(
    environment: Path,
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    capsys: pytest.CaptureFixture[str],
) -> None:
    scan = queue_seed.scan(world.operator_a, scannable)
    runtime.volumes.clear()

    assert main(["runner", "--once"]) == EXIT_FAILURE
    assert "沒有可用的引擎" in capsys.readouterr().err
    assert _run_status(queue_seed, scan.id) == ("queued", None)


def test_an_unavailable_guard_claims_nothing(
    environment: Path,
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """guard 停機（status 標成不再檢查）：runner 不認領，run 留在 queued（DECISIONS §15.7）。"""
    scan = queue_seed.scan(world.operator_a, scannable)
    GuardDouble(
        environment / "guard-policies",
        environment / "guard-status",
        environment / "guard-telemetry",
        uuid4(),
    ).stop()

    assert main(["runner", "--once"]) == EXIT_FAILURE
    assert "沒有可用的引擎" in capsys.readouterr().err
    assert _run_status(queue_seed, scan.id) == ("queued", None)
    assert runtime.created == []


def test_docker_lost_mid_run_fails_the_command(
    environment: Path,
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    capsys: pytest.CaptureFixture[str],
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    runtime.failing.update({"state", "remove"})

    assert main(["runner", "--once"]) == EXIT_FAILURE
    assert "對帳" in capsys.readouterr().err


def test_without_encryption_keys_authenticated_scans_fail(
    environment: Path,
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    scan = queue_seed.scan(world.operator_a, scannable, auth_profile_id=scannable.profile.id)
    monkeypatch.delenv("SECRET_ENCRYPTION_KEYS")

    assert main(["runner", "--once"]) == EXIT_OK
    assert "SECRET_UNAVAILABLE" in capsys.readouterr().err
    # 第一個 run 是 preflight（§16.5）：解不開 secret 就不建立容器。
    [preflight] = queue_seed.query(
        "SELECT status, error_code FROM scanner_runs WHERE scan_id = :id AND sequence = 1",
        id=scan.id,
    )
    assert (preflight.status, preflight.error_code) == ("failed", "SECRET_UNAVAILABLE")
    assert runtime.created == []


# --- 金鑰（KEY-01；docs/DECISIONS.md §30.2）-------------------------------------------------


@pytest.mark.parametrize("value", [None, "not-a-key"])
def test_the_runner_refuses_to_start_without_evidence_keys(
    environment: Path,
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    value: str | None,
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    if value is None:
        monkeypatch.delenv("EVIDENCE_ENCRYPTION_KEYS")
    else:
        monkeypatch.setenv("EVIDENCE_ENCRYPTION_KEYS", value)

    assert main(["runner", "--once"]) == EXIT_FAILURE

    err = capsys.readouterr().err
    assert "EVIDENCE_ENCRYPTION_KEYS" in err
    assert "runner 不啟動" in err
    assert runtime.created == []
    assert TEST_SECRET_ENCRYPTION_KEYS not in err


def test_the_runner_refuses_an_evidence_key_shared_with_the_secret_ring(
    environment: Path,
    runtime: FakeContainerRuntime,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("EVIDENCE_ENCRYPTION_KEYS", TEST_SECRET_ENCRYPTION_KEYS)

    assert main(["runner", "--once"]) == EXIT_FAILURE

    err = capsys.readouterr().err
    assert "相同的金鑰" in err
    assert TEST_SECRET_ENCRYPTION_KEYS not in err
    assert runtime.created == []


@pytest.mark.parametrize("value", [None, "not-a-key"])
def test_the_worker_refuses_to_start_without_content_keys(
    environment: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    value: str | None,
) -> None:
    if value is None:
        monkeypatch.delenv("CONTENT_ENCRYPTION_KEYS")
    else:
        monkeypatch.setenv("CONTENT_ENCRYPTION_KEYS", value)

    assert main(["worker", "--once"]) == EXIT_FAILURE

    err = capsys.readouterr().err
    assert "CONTENT_ENCRYPTION_KEYS" in err
    assert "worker 不啟動" in err


@pytest.mark.parametrize(
    ("name", "value", "message"),
    [
        ("RUNNER_POLL_SECONDS", "0", "RUNNER_*"),
        ("RUNNER_DOCKER_URL", "http://socket-proxy:2375", "RUNNER_DOCKER_URL"),
        ("RUNNER_GUARD_PROXY", "guard:8080", "RUNNER_*"),
        ("RUNNER_GUARD_PROXY", "10.89.8.254", "RUNNER_*"),
    ],
)
def test_bad_runner_settings_fail(
    environment: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    name: str,
    value: str,
    message: str,
) -> None:
    monkeypatch.setenv(name, value)

    assert main(["runner", "--once"]) == EXIT_FAILURE
    assert message in capsys.readouterr().err


@pytest.mark.parametrize("command", ["runner", "worker"])
def test_an_unreachable_database_fails(
    environment: Path,
    runtime: FakeContainerRuntime,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
) -> None:
    monkeypatch.setenv("DB_PORT", str(UNREACHABLE_PORT))

    assert main([command, "--once"]) == EXIT_FAILURE
    assert "無法連線資料庫" in capsys.readouterr().err


@pytest.mark.parametrize(("command", "loop"), [("runner", RunnerLoop), ("worker", WorkerLoop)])
def test_database_errors_stop_the_command(
    environment: Path,
    runtime: FakeContainerRuntime,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
    loop: type[RunnerLoop] | type[WorkerLoop],
) -> None:
    def broken(*_args: object, **_kwargs: object) -> list[object]:
        raise OperationalError("SELECT 1", None, Exception("connection reset"))

    monkeypatch.setattr(loop, "run", broken)

    assert main([command, "--once"]) == EXIT_FAILURE
    err = capsys.readouterr().err
    assert "OperationalError" in err
    assert "connection reset" not in err


def test_sigterm_requests_a_stop_and_the_handlers_are_restored() -> None:
    before = signal.getsignal(signal.SIGTERM)

    with stop_signals() as stop:
        os.kill(os.getpid(), signal.SIGTERM)
        assert stop.wait(timeout=5)

    assert signal.getsignal(signal.SIGTERM) is before


def test_the_runner_does_not_start_on_the_old_layout(
    environment: Path, runtime: FakeContainerRuntime, capsys: pytest.CaptureFixture[str]
) -> None:
    """根目錄還有沒搬移的 run 目錄（舊的 layout）：runner 不啟動，提示執行搬移（§30.13）。"""
    (environment / "runs" / str(uuid4())).mkdir()

    assert main(["runner", "--once"]) == EXIT_FAILURE

    err = capsys.readouterr().err
    assert "make runs-layout-migrate" in err
    assert runtime.created == []


def test_the_worker_refuses_the_volume_root(
    environment: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """安全審查 LOW-1：worker 看得到 held/ 或 .layout（subpath 沒有生效、掛到根目錄）就不啟動。"""
    monkeypatch.setenv("WORKER_RUNS_DIR", str(environment / "runs"))

    assert main(["worker", "--once"]) == EXIT_FAILURE

    assert "held/ 或 .layout" in capsys.readouterr().err
