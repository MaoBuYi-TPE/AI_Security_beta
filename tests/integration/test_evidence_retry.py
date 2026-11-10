"""secscan-admin retry-evidence 與 retention-status 的隔離段落（EVID-09；DECISIONS §30.12）。

- 沒有隔離時 exit 1、沒有任何改變；audit 寫不進去就不開始；等不到 keeper 的鎖時不動任何檔案。
- 仍然超過上限：隔離與明文保留原狀，寫 audit；指定較高的上限之後加密、解除隔離、寫入 sealed 的
  run_evidence，之後照常保留到期再清除。孤兒目錄只解除隔離。
- 目錄不存在時不會記成「沒有目錄」；加密之後 DB 寫入失敗，再執行一次就完成。
- retention-status：數量、錯誤代碼與目錄名稱，不含路徑。
設定以環境變數指向這個測試的資料庫與暫存的 runs 目錄（同 test_evidence_cli.py）。
"""

import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from secscan.cli import EXIT_FAILURE, EXIT_OK, main
from secscan.cli import evidence as evidence_cli
from secscan.runner.evidence import SEALED_DIR, EvidenceVault
from secscan.runner.keeper import EvidenceKeeper, KeeperSettings
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.evidence import EvidenceHoldCode
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.evidence_holds import EvidenceHolds
from secscan.scans.evidence_records import EvidenceRun, EvidenceStore
from secscan.scans.queue import ScanQueue
from secscan.security.key_rings import evidence_cipher
from tests.integration.api_support import LAB, Seeder
from tests.integration.database import ProvisionedDatabase

pytestmark = pytest.mark.integration

FAKE = frozenset({ScanEngine.FAKE})
CANARY = b"canary-evidence-retry-6a1b"
# out/ 之下 33 層：深度 34，超過一般的上限 32、在 --max-depth 40 之內。
LEVELS = 33
REASON = "工具異常建立過深的目錄，人工確認後提高上限重試"


@pytest.fixture
def runs(tmp_path: Path) -> Path:
    directory = tmp_path / "runs"
    directory.mkdir()
    return directory


@pytest.fixture
def key() -> str:
    return Fernet.generate_key().decode()


@pytest.fixture
def environment(
    queue_database: ProvisionedDatabase, monkeypatch: pytest.MonkeyPatch, runs: Path, key: str
) -> None:
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("DB_HOST", queue_database.host)
    monkeypatch.setenv("DB_PORT", str(queue_database.port))
    monkeypatch.setenv("DB_NAME", queue_database.name)
    monkeypatch.setenv("DB_USER", queue_database.user)
    monkeypatch.setenv("DB_PASSWORD", queue_database.password)
    monkeypatch.setenv("EVIDENCE_ENCRYPTION_KEYS", key)
    monkeypatch.setenv("RUNNER_RUNS_DIR", str(runs))


@pytest.fixture
def store(queue_engine: Engine) -> EvidenceStore:
    return EvidenceStore(sessionmaker(queue_engine, expire_on_commit=False), engine=queue_engine)


def _deep(runs: Path, name: UUID) -> Path:
    leaf = runs / str(name) / "out" / Path(*(["d"] * LEVELS))
    leaf.mkdir(parents=True)
    (leaf / "messages.txt").write_bytes(CANARY)
    (runs / str(name) / "manifest.json").write_bytes(b"{}")
    return leaf / "messages.txt"


@pytest.fixture
def held_run(
    environment: None, queue_seed: Seeder, queue_engine: Engine, runs: Path, store: EvidenceStore
) -> EvidenceRun:
    """一個已終止、目錄超過深度上限、已被隔離的 run（兩個檔案）。"""
    queue = ScanQueue(
        sessionmaker(queue_engine, expire_on_commit=False), lab=LAB, clock=lambda: datetime.now(UTC)
    )
    world = queue_seed.world()
    queue_seed.scan(world.operator_a, queue_seed.scannable(world))
    lease = queue.claim("runner-retry", FAKE)
    assert lease is not None
    queue.prepare(lease)
    queue.advance(lease, RunStatus.FAILED, error_code=RunErrorCode.ENGINE_FAILED)
    run = EvidenceRun(lease.run_id, lease.scan_id)
    _deep(runs, run.run_id)
    store.hold(run.run_id, run, EvidenceHoldCode.TREE_TOO_DEEP, 3)
    return run


def _retry(directory: UUID, *extra: str) -> int:
    return main(["retry-evidence", "--directory", str(directory), "--reason", REASON, *extra])


def _leaf(runs: Path, name: UUID) -> Path:
    return runs / str(name) / "out" / Path(*(["d"] * LEVELS)) / "messages.txt"


def _audits(seed: Seeder, action: str) -> list[Any]:
    return list(
        seed.query(
            "SELECT redacted_changes, actor_key_id, object_type, object_id, project_id "
            "FROM audit_events WHERE action = :action ORDER BY created_at",
            action=action,
        )
    )


def _hold(seed: Seeder, directory: UUID) -> Any:
    [row] = seed.query("SELECT * FROM evidence_holds WHERE directory = :id", id=directory)
    return row


def _evidence(seed: Seeder, run_id: UUID) -> list[Any]:
    return list(seed.query("SELECT * FROM run_evidence WHERE scanner_run_id = :id", id=run_id))


def _err(capsys: pytest.CaptureFixture[bytes]) -> str:
    return capsys.readouterr().err.decode()


# --- 沒有隔離、仍然超過上限 ---------------------------------------------------------------------


def test_without_a_hold_nothing_changes(
    environment: None, queue_seed: Seeder, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    assert _retry(uuid4()) == EXIT_FAILURE

    assert "沒有需要人工處理的隔離" in _err(capsysbinary)
    assert _audits(queue_seed, "evidence.retry") == []


def test_still_over_the_limit_keeps_the_hold_and_the_plaintext(
    held_run: EvidenceRun,
    queue_seed: Seeder,
    runs: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    assert _retry(held_run.run_id) == EXIT_FAILURE

    err = _err(capsysbinary)
    assert "--max-depth" in err
    assert str(runs) not in err
    assert _leaf(runs, held_run.run_id).read_bytes() == CANARY
    assert _hold(queue_seed, held_run.run_id).resolved_at is None
    assert _evidence(queue_seed, held_run.run_id) == []
    [retry] = _audits(queue_seed, "evidence.retry")
    assert retry.redacted_changes == {
        "kind": "run",
        "error_code": "EVIDENCE_TREE_TOO_DEEP",
        "reason": REASON,
        "max_depth": 32,
        "max_entries": 20_000,
    }
    assert (retry.actor_key_id, retry.object_id) == (None, held_run.run_id)
    assert retry.project_id is not None
    [failed] = _audits(queue_seed, "evidence.retry_failed")
    assert failed.redacted_changes["error_code"] == "EVIDENCE_TREE_TOO_DEEP"


# --- 成功 --------------------------------------------------------------------------------------


def test_a_higher_limit_seals_resolves_and_is_purged_later(
    held_run: EvidenceRun,
    queue_seed: Seeder,
    queue_engine: Engine,
    runs: Path,
    key: str,
    store: EvidenceStore,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    assert _retry(held_run.run_id, "--max-depth", "40") == EXIT_OK

    assert "解除隔離" in _err(capsysbinary)
    root = runs / str(held_run.run_id)
    assert {entry.name for entry in root.iterdir()} == {SEALED_DIR}
    vault = EvidenceVault(runs, evidence_cipher(key))
    assert len(vault.listing(str(held_run.run_id))) == 2
    [row] = _evidence(queue_seed, held_run.run_id)
    assert (row.status, row.file_count) == ("sealed", 2)
    assert _hold(queue_seed, held_run.run_id).resolved_at is not None
    [resolve] = _audits(queue_seed, "evidence.resolve")
    assert resolve.redacted_changes == {
        "kind": "run",
        "files": 2,
        "plaintext_bytes": len(CANARY) + 2,
        "max_depth": 40,
        "max_entries": 20_000,
    }

    later = datetime.now(UTC) + timedelta(days=8)
    keeper = EvidenceKeeper(
        store,
        vault,
        KeeperSettings(retention_days=7, plaintext_max_minutes=60),
        clock=lambda: later,
    )
    assert keeper.run_pass().purged == 1
    assert not root.exists()
    assert _hold(queue_seed, held_run.run_id).resolved_at is not None


def test_an_orphan_is_resolved_without_run_evidence(
    environment: None,
    queue_seed: Seeder,
    runs: Path,
    store: EvidenceStore,
) -> None:
    name = uuid4()
    _deep(runs, name)
    store.hold(name, None, EvidenceHoldCode.TREE_TOO_MANY_ENTRIES, 3)

    assert _retry(name, "--max-depth", "40", "--max-entries", "20000") == EXIT_OK

    assert _hold(queue_seed, name).resolved_at is not None
    assert _evidence(queue_seed, name) == []
    assert {entry.name for entry in (runs / str(name)).iterdir()} == {SEALED_DIR}
    [resolve] = _audits(queue_seed, "evidence.resolve")
    assert (resolve.redacted_changes["kind"], resolve.project_id) == ("orphan", None)


# --- 故障 --------------------------------------------------------------------------------------


def test_a_missing_directory_is_not_recorded_as_none(
    held_run: EvidenceRun, queue_seed: Seeder, runs: Path
) -> None:
    shutil.rmtree(runs / str(held_run.run_id))

    assert _retry(held_run.run_id, "--max-depth", "40") == EXIT_FAILURE

    assert _evidence(queue_seed, held_run.run_id) == []
    assert _hold(queue_seed, held_run.run_id).resolved_at is None
    [failed] = _audits(queue_seed, "evidence.retry_failed")
    assert failed.redacted_changes["error_code"] == "EVIDENCE_DIRECTORY_MISSING"


def test_the_audit_is_written_before_any_file_changes(
    held_run: EvidenceRun,
    queue_seed: Seeder,
    runs: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    def broken(*_args: object, **_kwargs: object) -> None:
        raise OperationalError("INSERT", {}, Exception("db down"))

    monkeypatch.setattr(EvidenceHolds, "audit", broken)

    assert _retry(held_run.run_id, "--max-depth", "40") == EXIT_FAILURE

    assert "沒有開始加密" in _err(capsysbinary)
    assert _leaf(runs, held_run.run_id).read_bytes() == CANARY
    assert not (runs / str(held_run.run_id) / SEALED_DIR).exists()
    assert _hold(queue_seed, held_run.run_id).resolved_at is None


def test_a_database_failure_after_sealing_is_finished_by_running_again(
    held_run: EvidenceRun,
    queue_seed: Seeder,
    runs: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    def broken(*_args: object, **_kwargs: object) -> None:
        raise OperationalError("UPDATE", {}, Exception("db down"))

    with monkeypatch.context() as patched:
        patched.setattr(EvidenceHolds, "resolve", broken)
        assert _retry(held_run.run_id, "--max-depth", "40") == EXIT_FAILURE
    assert "請再執行一次" in _err(capsysbinary)
    assert {entry.name for entry in (runs / str(held_run.run_id)).iterdir()} == {SEALED_DIR}
    assert _hold(queue_seed, held_run.run_id).resolved_at is None
    assert _evidence(queue_seed, held_run.run_id) == []
    [unrecorded] = _audits(queue_seed, "evidence.retry_failed")
    assert unrecorded.redacted_changes["error_code"] == "EVIDENCE_SEALED_NOT_RECORDED"
    assert unrecorded.redacted_changes["files"] == 2

    assert _retry(held_run.run_id) == EXIT_OK

    [row] = _evidence(queue_seed, held_run.run_id)
    assert (row.status, row.file_count) == ("sealed", 2)
    assert _hold(queue_seed, held_run.run_id).resolved_at is not None


def test_retry_waits_for_the_keeper_and_gives_up_without_changes(
    held_run: EvidenceRun,
    queue_seed: Seeder,
    runs: Path,
    store: EvidenceStore,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    monkeypatch.setattr(evidence_cli, "LOCK_ATTEMPTS", 2)
    monkeypatch.setattr(evidence_cli, "LOCK_WAIT_SECONDS", 0.0)

    with store.exclusive() as acquired:
        assert acquired
        assert _retry(held_run.run_id, "--max-depth", "40") == EXIT_FAILURE

    assert "等不到鎖" in _err(capsysbinary)
    assert _leaf(runs, held_run.run_id).read_bytes() == CANARY
    assert _audits(queue_seed, "evidence.retry") == []


@pytest.mark.parametrize(
    "argv",
    [
        ["--directory", "not-a-uuid", "--reason", REASON],
        ["--directory", str(UUID(int=1)).upper(), "--reason", REASON],
        ["--directory", str(UUID(int=1)), "--reason", "   "],
        ["--directory", str(UUID(int=1)), "--reason", "第一行\n第二行"],
        ["--directory", str(UUID(int=1)), "--reason", "x" * 201],
    ],
)
def test_bad_arguments_change_nothing(
    environment: None, queue_seed: Seeder, argv: list[str]
) -> None:
    assert main(["retry-evidence", *argv]) == EXIT_FAILURE

    assert _audits(queue_seed, "evidence.retry") == []


def test_a_reason_that_is_not_utf8_is_rejected_before_anything_changes(
    held_run: EvidenceRun,
    queue_seed: Seeder,
    runs: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    """不合法的 UTF-8 經 surrogateescape 解碼成孤立的 surrogate，寫進 audit 時才會失敗
    （安全審查 L4）：在開始之前就拒絕。"""
    argv = ["--directory", str(held_run.run_id), "--reason", "理由\udcff", "--max-depth", "40"]

    assert main(["retry-evidence", *argv]) == EXIT_FAILURE

    assert "UTF-8" in _err(capsysbinary)
    assert _audits(queue_seed, "evidence.retry") == []
    assert _leaf(runs, held_run.run_id).read_bytes() == CANARY


@pytest.mark.parametrize(
    "limit",
    [
        ["--max-depth", "31"],
        ["--max-depth", "65"],
        ["--max-entries", "19999"],
        ["--max-entries", "50001"],
        ["--max-depth", "deep"],
    ],
)
def test_limits_outside_the_range_are_rejected(environment: None, limit: list[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        _retry(UUID(int=1), *limit)

    assert raised.value.code == 2


# --- retention-status --------------------------------------------------------------------------


def test_retention_status_lists_holds_without_paths(
    held_run: EvidenceRun, runs: Path, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    assert main(["retention-status"]) == EXIT_OK

    err = _err(capsysbinary)
    assert "需要人工處理（manual_intervention_required）：run 1、孤兒目錄 0" in err
    assert "EVIDENCE_TREE_TOO_DEEP 1" in err
    assert "已人工處理 0" in err
    assert "已終止但未加密 0" in err
    assert str(held_run.run_id) in err
    assert "retry-evidence" in err
    assert str(runs) not in err
