"""secscan-admin fake-runner（docs/DECISIONS.md §13.7）：處理排隊中的 fake run，輸出只到 stderr。

每個測試用自己的資料庫（queue_database）：runner 會認領任何排隊中的 fake run。
"""

from uuid import UUID

import pytest
from sqlalchemy.exc import OperationalError

from secscan.cli import EXIT_FAILURE, EXIT_OK, main
from secscan.runner.fake import FakeRunner
from secscan.scans.queue import LeaseLostError
from tests.integration.api_support import Scannable, Seeder, World
from tests.integration.database import ProvisionedDatabase

pytestmark = pytest.mark.integration

UNREACHABLE_PORT = 1


def _use(
    monkeypatch: pytest.MonkeyPatch, database: ProvisionedDatabase, *, port: int | None = None
) -> None:
    """以環境變數指向測試的資料庫；不設定 SECRET_ENCRYPTION_KEYS（fake-runner 不需要它）。"""
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("DB_HOST", database.host)
    monkeypatch.setenv("DB_PORT", str(port if port is not None else database.port))
    monkeypatch.setenv("DB_NAME", database.name)
    monkeypatch.setenv("DB_USER", database.user)
    monkeypatch.setenv("DB_PASSWORD", database.password)


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


@pytest.fixture
def scannable(queue_seed: Seeder, world: World) -> Scannable:
    return queue_seed.scannable(world)


def _status(seed: Seeder, scan_id: UUID) -> str:
    [row] = seed.query("SELECT status FROM scans WHERE id = :id", id=scan_id)
    return str(row.status)


def test_runs_every_queued_fake_run(
    queue_database: ProvisionedDatabase,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    first = queue_seed.scan(world.operator_a, scannable)
    second = queue_seed.scan(world.operator_a, queue_seed.scannable(world))
    _use(monkeypatch, queue_database)

    exit_code = main(["fake-runner"])

    out, err = capsys.readouterr()
    assert exit_code == EXIT_OK
    assert out == ""
    assert (_status(queue_seed, first.id), _status(queue_seed, second.id)) == (
        "completed",
        "completed",
    )
    for scan in (first, second):
        assert f"scan {scan.id}" in err
        assert f"run {scan.runs[0].id}" in err
    assert err.count("completed") == 2


def test_once_runs_a_single_fake_run(
    queue_database: ProvisionedDatabase,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = queue_seed.scan(world.operator_a, scannable)
    second = queue_seed.scan(world.operator_a, queue_seed.scannable(world))
    _use(monkeypatch, queue_database)

    assert main(["fake-runner", "--once", "--outcome", "fail"]) == EXIT_OK

    assert (_status(queue_seed, first.id), _status(queue_seed, second.id)) == ("failed", "queued")


def test_an_empty_queue_is_not_an_error(
    queue_database: ProvisionedDatabase,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _use(monkeypatch, queue_database)

    assert main(["fake-runner"]) == EXIT_OK
    assert "沒有排隊中的 fake run" in capsys.readouterr().err


def test_expired_runs_are_reconciled_first(
    queue_database: ProvisionedDatabase,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """上一次被強制終止的 fake run：lease 過期之後，下一次執行把它標成 interrupted。"""
    scan = queue_seed.scan(world.operator_a, scannable)
    queue_seed.execute(
        "UPDATE scanner_runs SET status = 'preparing', started_at = now(), "
        "lease_owner = 'killed-runner', lease_expires_at = now() - interval '1 second', "
        "heartbeat_at = now() WHERE scan_id = :id",
        id=scan.id,
    )
    _use(monkeypatch, queue_database)

    assert main(["fake-runner"]) == EXIT_OK

    assert _status(queue_seed, scan.id) == "interrupted"
    assert "1 個" in capsys.readouterr().err


def test_an_unreachable_database_is_reported(
    queue_database: ProvisionedDatabase,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """不需要 SECRET_ENCRYPTION_KEYS：設定沒有它也會走到連線，連不上時說明原因。"""
    _use(monkeypatch, queue_database, port=UNREACHABLE_PORT)

    exit_code = main(["fake-runner", "--once"])

    out, err = capsys.readouterr()
    assert exit_code == EXIT_FAILURE
    assert out == ""
    assert "make db-up" in err
    assert "SECRET_ENCRYPTION_KEYS" not in err
    assert queue_database.password not in err


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (LeaseLostError("lease"), "lease 已失效"),
        (
            OperationalError("SELECT 1", None, Exception("canary-db-detail-0005")),
            "OperationalError",
        ),
        (KeyboardInterrupt(), "已中斷"),
    ],
    ids=["lease-lost", "database", "interrupted"],
)
def test_a_stopped_runner_reports_why_and_exits_1(
    queue_database: ProvisionedDatabase,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    error: BaseException,
    message: str,
) -> None:
    """runner 停下來的原因寫到 stderr，exit 1；DB 錯誤只報例外類別，不帶訊息。"""
    _use(monkeypatch, queue_database)

    def stop(*_args: object, **_kwargs: object) -> None:
        raise error

    monkeypatch.setattr(FakeRunner, "drain", stop)

    exit_code = main(["fake-runner"])

    out, err = capsys.readouterr()
    assert exit_code == EXIT_FAILURE
    assert out == ""
    assert message in err
    assert "canary-db-detail-0005" not in err
