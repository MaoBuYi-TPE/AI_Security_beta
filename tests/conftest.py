from collections.abc import Callable, Iterator

import psycopg
import pytest
from fastapi.testclient import TestClient
from hypothesis import settings as hypothesis_settings
from pydantic import SecretStr

from secscan.cli.db_roles import AdminCredentials
from secscan.core.config import AppEnv, Settings
from secscan.main import create_app
from secscan.migrations.credentials import MigrationCredentials
from secscan.runner.config import RunnerSettings
from secscan.worker.config import WorkerSettings
from tests.secret_support import content_keys, encryption_keys

# tests.isolation：測試程序連不到 Docker daemon（docs/DECISIONS.md §14.9）。
pytest_plugins = ("pytester", "tests.isolation")

type ClientFactory = Callable[[AppEnv], TestClient]

# Hypothesis 的 property test：亂數由測試內容決定（derandomize），每次執行的輸入都相同，
# 失敗可以重現；也不在工作目錄寫入 .hypothesis/ 範例資料庫。
hypothesis_settings.register_profile("secscan", derandomize=True, database=None)
hypothesis_settings.load_profile("secscan")

# 應用程式的 DB 連線設定。測試一律不得沿用開發者 shell 或 .env 裡的值，以免連到開發或正式資料庫；
# 整合測試另有 TEST_DB_* 設定（tests/integration/database.py）。
DB_ENV_KEYS = (
    "DB_HOST",
    "DB_PORT",
    "DB_NAME",
    "DB_USER",
    "DB_PASSWORD",
    "DB_CONNECT_TIMEOUT_SECONDS",
    "DB_STATEMENT_TIMEOUT_SECONDS",
    "DB_LOCK_TIMEOUT_SECONDS",
    "DB_IDLE_IN_TRANSACTION_TIMEOUT_SECONDS",
    # migration 的 owner 與 migrate-db-roles 的 superuser（T23b-b1）。
    "DB_OWNER_USER",
    "DB_OWNER_PASSWORD",
    "DB_ADMIN_USER",
    "DB_ADMIN_PASSWORD",
)
# 三組加密金鑰也一樣不沿用（shell 或 .env 裡可能是真的金鑰）；需要的 fixture 帶測試用的金鑰。
SECRET_ENV_KEYS = (
    "SECRET_ENCRYPTION_KEYS",
    "EVIDENCE_ENCRYPTION_KEYS",
    "CONTENT_ENCRYPTION_KEYS",
)
# 保留期限、明文期限與 bench 的金鑰檔（docs/DECISIONS.md §30）：測試以預設值或自己指定的值執行。
RETENTION_ENV_KEYS = (
    "EVIDENCE_RETENTION_DAYS",
    "REPORT_RETENTION_DAYS",
    "EXCERPT_RETENTION_DAYS",
    "EVIDENCE_PLAINTEXT_MAX_MINUTES",
    "BENCH_KEY_FILE",
)
# runner 的設定（RUNNER_*）同樣不沿用：可能指向真的 Docker 或掛載的目錄。
RUNNER_ENV_KEYS = (
    "RUNNER_DOCKER_URL",
    "RUNNER_SCAN_NETWORK",
    "RUNNER_RUNS_VOLUME",
    "RUNNER_SECRETS_VOLUME",
    "RUNNER_RUNS_DIR",
    "RUNNER_SECRETS_DIR",
    "RUNNER_POLL_SECONDS",
    "RUNNER_FAKE_OUTCOME",
    "RUNNER_FAKE_HOLD_SECONDS",
    "RUNNER_GUARD_PROXY",
    "RUNNER_GUARD_POLICIES_DIR",
    "RUNNER_GUARD_STATUS_DIR",
    "RUNNER_GUARD_TELEMETRY_DIR",
)
# 127.0.0.1:1 沒有服務：就算有測試誤打需要 DB 的端點，也只會立刻失敗。
UNREACHABLE_DB_PORT = 1


class DatabaseAccessBlockedError(RuntimeError):
    """非整合測試嘗試連線資料庫。"""


@pytest.fixture(autouse=True)
def _isolate_app_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Settings、RunnerSettings、WorkerSettings、MigrationCredentials 與 AdminCredentials 不讀
    .env（pytest 在 repo 根目錄執行，那裡有真實的本機密碼與金鑰），也不讀 DB_*、RUNNER_*、金鑰與
    保留期限等環境變數。

    要測 .env 讀取行為的測試，自行把 env_file 設回來。
    """
    for settings_class in (
        Settings,
        RunnerSettings,
        WorkerSettings,
        MigrationCredentials,
        AdminCredentials,
    ):
        monkeypatch.setitem(settings_class.model_config, "env_file", None)
    for key in (*DB_ENV_KEYS, *SECRET_ENV_KEYS, *RETENTION_ENV_KEYS, *RUNNER_ENV_KEYS):
        monkeypatch.delenv(key, raising=False)


@pytest.fixture(autouse=True)
def _forbid_database_outside_integration(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    """unit/contract 測試不得連 DB。psycopg 經 libpq 連線，pytest-socket 擋不到，所以另外封鎖。"""
    if request.node.get_closest_marker("integration") is not None:
        return

    def _blocked(*_args: object, **_kwargs: object) -> None:
        raise DatabaseAccessBlockedError("只有標記 integration 的測試可以連線資料庫")

    monkeypatch.setattr(psycopg, "connect", _blocked)
    monkeypatch.setattr(psycopg.Connection, "connect", _blocked)


@pytest.fixture
def make_client() -> Iterator[ClientFactory]:
    """依指定的 APP_ENV 建立測試用 client。

    DB 密碼是假的、port 指向沒有服務的位置：engine 不會在建立時連線，這些測試也不打需要 DB 的端點。
    """
    clients: list[TestClient] = []

    def factory(app_env: AppEnv) -> TestClient:
        settings = Settings(
            app_env=app_env,
            db_port=UNREACHABLE_DB_PORT,
            db_password=SecretStr("not-a-real-password"),
            secret_encryption_keys=encryption_keys(),
            content_encryption_keys=content_keys(),
            _env_file=None,
        )
        test_client = TestClient(create_app(settings))
        clients.append(test_client)
        return test_client

    yield factory
    for test_client in clients:
        test_client.close()


@pytest.fixture
def client(make_client: ClientFactory) -> TestClient:
    return make_client("test")
