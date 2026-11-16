"""CSEC-09：api、runner、worker 以 `*_FILE` 讀取秘密，以 SCRAM 連上 db-test。

範圍（docs/DECISIONS.md §32；計畫 §12.11 的「驗證範圍的分類」）：只驗證主機端的設定讀取、`*_FILE`、
SCRAM 與這三個程序的資料庫連線。秘密檔放在 pytest 的暫存目錄（拋棄式的值），不是 compose secrets 的
實際掛載；容器的部署（Docker build、`/run/secrets`、entrypoint）留給 G3 的 Live。
Docker 以記憶體中的假 runtime 取代（測試程序連不到 daemon）。
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from secscan.cli import EXIT_OK, main
from secscan.core.config import Settings
from secscan.core.db import create_db_engine
from secscan.main import create_app
from secscan.runner.docker_runtime import DockerRuntime
from secscan.runner.layout import init_layout
from secscan.scanners.domain.zap.policy import ZAP_IMAGE
from tests.guard_support import GuardDouble
from tests.integration.api_support import Scannable, Seeder, World
from tests.integration.database import ProvisionedDatabase
from tests.runner_fakes import FakeContainerRuntime
from tests.secret_support import (
    TEST_CONTENT_ENCRYPTION_KEYS,
    TEST_EVIDENCE_ENCRYPTION_KEYS,
    TEST_SECRET_ENCRYPTION_KEYS,
)

pytestmark = pytest.mark.integration


def _secret_file(directory: Path, name: str, value: str) -> Path:
    path = directory / name
    path.write_text(value, encoding="ascii")
    path.chmod(0o600)
    return path


@pytest.fixture
def secret_files(
    queue_database: ProvisionedDatabase, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Path:
    """只有 `*_FILE` 指向暫存的秘密檔；環境變數中沒有任何秘密的值。"""
    directory = tmp_path / "run-secrets"
    directory.mkdir(mode=0o700)
    files = {
        "DB_PASSWORD_FILE": ("db_password", queue_database.password),
        "SECRET_ENCRYPTION_KEYS_FILE": ("secret_encryption_keys", TEST_SECRET_ENCRYPTION_KEYS),
        "EVIDENCE_ENCRYPTION_KEYS_FILE": (
            "evidence_encryption_keys",
            TEST_EVIDENCE_ENCRYPTION_KEYS,
        ),
        "CONTENT_ENCRYPTION_KEYS_FILE": ("content_encryption_keys", TEST_CONTENT_ENCRYPTION_KEYS),
    }
    for variable, (name, value) in files.items():
        monkeypatch.setenv(variable, str(_secret_file(directory, name, value)))
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("DB_HOST", queue_database.host)
    monkeypatch.setenv("DB_PORT", str(queue_database.port))
    monkeypatch.setenv("DB_NAME", queue_database.name)
    monkeypatch.setenv("DB_USER", queue_database.user)
    return directory


@pytest.fixture
def runner_environment(
    secret_files: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> FakeContainerRuntime:
    for name in ("runs", "secrets"):
        (tmp_path / name).mkdir()
    init_layout(tmp_path / "runs")
    monkeypatch.setenv("WORKER_RUNS_DIR", str(tmp_path / "runs" / "active"))
    monkeypatch.setenv("RUNNER_RUNS_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("RUNNER_SECRETS_DIR", str(tmp_path / "secrets"))
    guard = GuardDouble.create(tmp_path)
    monkeypatch.setenv("RUNNER_GUARD_POLICIES_DIR", str(guard.policies))
    monkeypatch.setenv("RUNNER_GUARD_STATUS_DIR", str(guard.status_dir))
    monkeypatch.setenv("RUNNER_GUARD_TELEMETRY_DIR", str(guard.telemetry))
    fake = FakeContainerRuntime()
    del fake.images[str(ZAP_IMAGE)]
    monkeypatch.setattr(DockerRuntime, "connect", lambda _url: fake)
    return fake


def test_settings_from_files_connect_with_scram(
    secret_files: Path, queue_database: ProvisionedDatabase
) -> None:
    settings = Settings()
    assert settings.db_password is not None
    assert settings.db_password_file is None
    engine = create_db_engine(settings, pooled=False)
    try:
        with engine.connect() as connection:
            # system_user（PostgreSQL 16 起）：「認證方式:身分」。
            identity = connection.execute(text("SELECT system_user")).scalar_one()
    finally:
        engine.dispose()

    assert identity == f"scram-sha-256:{queue_database.user}"


def test_the_api_starts_from_files_and_is_ready(secret_files: Path) -> None:
    with TestClient(create_app()) as client:
        response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json()["data"]["status"] == "ready"


def test_the_runner_and_the_worker_start_from_files(
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    runner_environment: FakeContainerRuntime,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # 測試資料（queue_seed、world、scannable）先以測試自己的 Settings 建立；之後才設定 *_FILE。
    scan = queue_seed.scan(world.operator_a, scannable)

    assert main(["runner", "--once"]) == EXIT_OK
    assert main(["worker", "--once"]) == EXIT_OK

    [row] = queue_seed.query("SELECT status FROM scanner_runs WHERE scan_id = :id", id=scan.id)
    assert row.status == "succeeded"
    assert len(runner_environment.created) == 1
    _, err = capsys.readouterr()
    assert "succeeded" in err


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


@pytest.fixture
def scannable(queue_seed: Seeder, world: World) -> Scannable:
    return queue_seed.scannable(world)
