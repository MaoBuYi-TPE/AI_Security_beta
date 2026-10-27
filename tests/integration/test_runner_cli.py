"""secscan-admin runner／worker（docs/DECISIONS.md §14.6、§14.8）：輸出只到 stderr。

Docker 以記憶體中的假 runtime 取代（測試程序連不到 daemon）；每個測試用自己的資料庫。
"""

import os
import signal
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy.exc import OperationalError

from secscan.cli import EXIT_FAILURE, EXIT_OK, main
from secscan.cli.services import stop_signals
from secscan.runner.docker_runtime import DockerRuntime
from secscan.runner.loop import RunnerLoop
from secscan.worker.loop import WorkerLoop
from tests.integration.api_support import Scannable, Seeder, World
from tests.integration.database import ProvisionedDatabase
from tests.runner_fakes import FakeContainerRuntime
from tests.secret_support import TEST_SECRET_ENCRYPTION_KEYS

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
    monkeypatch.setattr(DockerRuntime, "connect", lambda _url: fake)
    return fake


@pytest.fixture
def environment(
    queue_database: ProvisionedDatabase, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Path:
    """以環境變數指向測試的資料庫與暫存目錄。"""
    for name in ("runs", "secrets"):
        (tmp_path / name).mkdir()
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("DB_HOST", queue_database.host)
    monkeypatch.setenv("DB_PORT", str(queue_database.port))
    monkeypatch.setenv("DB_NAME", queue_database.name)
    monkeypatch.setenv("DB_USER", queue_database.user)
    monkeypatch.setenv("DB_PASSWORD", queue_database.password)
    monkeypatch.setenv("SECRET_ENCRYPTION_KEYS", TEST_SECRET_ENCRYPTION_KEYS)
    monkeypatch.setenv("RUNNER_RUNS_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("RUNNER_SECRETS_DIR", str(tmp_path / "secrets"))
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


def test_docker_lost_mid_run_fails_the_command(
    environment: Path,
    runtime: FakeContainerRuntime,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    capsys: pytest.CaptureFixture[str],
) -> None:
    queue_seed.scan(world.operator_a, scannable)
    runtime.failing.add("state")

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
    scan = queue_seed.scan(world.operator_a, scannable)
    monkeypatch.delenv("SECRET_ENCRYPTION_KEYS")

    assert main(["runner", "--once"]) == EXIT_OK
    assert "SECRET_UNAVAILABLE" in capsys.readouterr().err
    assert _run_status(queue_seed, scan.id) == ("failed", "SECRET_UNAVAILABLE")
    assert runtime.created == []


@pytest.mark.parametrize(
    ("name", "value", "message"),
    [
        ("RUNNER_POLL_SECONDS", "0", "RUNNER_*"),
        ("RUNNER_DOCKER_URL", "http://socket-proxy:2375", "RUNNER_DOCKER_URL"),
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
