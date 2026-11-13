"""secscan-admin retry-evidence 與 retention-status 的隔離段落（EVID-09、EVID-12；DECISIONS §30.12、
§30.13）。

- 沒有隔離時 exit 1、沒有任何改變；audit 寫不進去就不開始；等不到 keeper 的鎖時不動任何檔案。
- 隔離的目錄先由 keeper 搬到 held/；隔離中（還沒搬）exit 1、不做任何改變。
- 仍然超過上限：隔離與明文（在 held/）保留原狀，寫 audit；指定較高的上限之後在 held/ 加密並驗證、
  開始解除、搬回 active/、再驗證，才解除隔離、寫入 sealed 的 run_evidence，之後照常保留到期再清除。
  孤兒目錄只解除隔離。
- 每個中斷點（§30.13 的中斷表）之後，active/ 中只有已驗證的加密檔；再執行一次就從正確的步驟完成。
- 目錄不存在時不會記成「沒有目錄」。
- retention-status：數量、錯誤代碼與目錄名稱，不含路徑。
設定以環境變數指向這個測試的資料庫與暫存的 runs 目錄（同 test_evidence_cli.py）。
"""

import logging
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
from secscan.cli import evidence_holds as retry_cli
from secscan.runner.evidence import SEALED_DIR, EvidenceError, EvidenceVault
from secscan.runner.fs import TreeLimits
from secscan.runner.hold_moves import HoldMoves, MoveError
from secscan.runner.keeper import EvidenceKeeper, KeeperSettings
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.evidence import EvidenceHoldCode, HoldMoveCode, SealedEvidence
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.evidence_hold_isolation import HoldIsolationStore
from secscan.scans.evidence_holds import EvidenceHolds
from secscan.scans.evidence_records import EvidenceRun, EvidenceStore
from secscan.scans.queue import ScanQueue
from secscan.security.key_rings import evidence_cipher
from tests.integration.api_support import LAB, Seeder
from tests.integration.database import ProvisionedDatabase
from tests.runs_volume_support import hold_isolation, inode, isolate, runs_volume

pytestmark = pytest.mark.integration

FAKE = frozenset({ScanEngine.FAKE})
CANARY = b"canary-evidence-retry-6a1b"
# out/ 之下 33 層：深度 34，超過一般的上限 32、在 --max-depth 40 之內。
LEVELS = 33
REASON = "工具異常建立過深的目錄，人工確認後提高上限重試"


@pytest.fixture
def runs(tmp_path: Path) -> Path:
    """runs volume 的 active/（§30.13）；vault 以 volume 的根目錄（.parent）建立。"""
    return runs_volume(tmp_path)


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
    monkeypatch.setenv("RUNNER_RUNS_DIR", str(runs.parent))


@pytest.fixture
def store(queue_engine: Engine) -> EvidenceStore:
    return EvidenceStore(sessionmaker(queue_engine, expire_on_commit=False), engine=queue_engine)


def _held(runs: Path) -> Path:
    return runs.parent / "held"


def _deep(runs: Path, name: UUID) -> Path:
    leaf = runs / str(name) / "out" / Path(*(["d"] * LEVELS))
    leaf.mkdir(parents=True)
    (leaf / "messages.txt").write_bytes(CANARY)
    (runs / str(name) / "manifest.json").write_bytes(b"{}")
    return leaf / "messages.txt"


@pytest.fixture
def held_run(
    environment: None,
    queue_seed: Seeder,
    queue_engine: Engine,
    runs: Path,
    key: str,
    store: EvidenceStore,
) -> EvidenceRun:
    """一個已終止、目錄超過深度上限、已被隔離（搬到 held/）的 run（兩個檔案）。"""
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
    store.hold(run.run_id, run, EvidenceHoldCode.TREE_TOO_DEEP, 3, inode(runs, run.run_id))
    isolate(queue_engine, runs, _vault(runs, key))
    assert (_held(runs) / str(run.run_id)).is_dir()
    return run


def _vault(runs: Path, key: str) -> EvidenceVault:
    return EvidenceVault(runs.parent, evidence_cipher(key))


def _retry(directory: UUID, *extra: str) -> int:
    return main(["retry-evidence", "--directory", str(directory), "--reason", REASON, *extra])


def _leaf(runs: Path, name: UUID) -> Path:
    """held/ 中的明文（隔離之後的位置）。"""
    return _held(runs) / str(name) / "out" / Path(*(["d"] * LEVELS)) / "messages.txt"


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
        "stage": "isolated",
        "max_depth": 32,
        "max_entries": 20_000,
        "max_path_chars": 8 * 1024 * 1024,
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
    assert not (_held(runs) / str(held_run.run_id)).exists()
    vault = _vault(runs, key)
    assert len(vault.listing(str(held_run.run_id))) == 2
    [row] = _evidence(queue_seed, held_run.run_id)
    assert (row.status, row.file_count) == ("sealed", 2)
    hold = _hold(queue_seed, held_run.run_id)
    assert hold.isolated_at <= hold.releasing_at <= hold.resolved_at
    [release] = _audits(queue_seed, "evidence.release")
    assert release.redacted_changes["kind"] == "run"
    [resolve] = _audits(queue_seed, "evidence.resolve")
    assert resolve.redacted_changes == {
        "kind": "run",
        "files": 2,
        "plaintext_bytes": len(CANARY) + 2,
        "max_depth": 40,
        "max_entries": 20_000,
        "max_path_chars": 8 * 1024 * 1024,
    }

    later = datetime.now(UTC) + timedelta(days=8)
    keeper = EvidenceKeeper(
        store,
        vault,
        KeeperSettings(retention_days=7, plaintext_max_minutes=60),
        isolation=hold_isolation(queue_engine, runs, vault),
        clock=lambda: later,
    )
    assert keeper.run_pass().purged == 1
    assert not root.exists()
    assert _hold(queue_seed, held_run.run_id).resolved_at is not None


def test_an_orphan_is_resolved_without_run_evidence(
    environment: None,
    queue_seed: Seeder,
    queue_engine: Engine,
    runs: Path,
    key: str,
    store: EvidenceStore,
) -> None:
    name = uuid4()
    _deep(runs, name)
    store.hold(name, None, EvidenceHoldCode.TREE_TOO_MANY_ENTRIES, 3, inode(runs, name))
    isolate(queue_engine, runs, _vault(runs, key))

    assert _retry(name, "--max-depth", "40", "--max-entries", "20000") == EXIT_OK

    assert _hold(queue_seed, name).resolved_at is not None
    assert _evidence(queue_seed, name) == []
    assert {entry.name for entry in (runs / str(name)).iterdir()} == {SEALED_DIR}
    [resolve] = _audits(queue_seed, "evidence.resolve")
    assert (resolve.redacted_changes["kind"], resolve.project_id) == ("orphan", None)


# --- 故障 --------------------------------------------------------------------------------------


def test_a_missing_directory_is_not_recorded_as_none(
    held_run: EvidenceRun,
    queue_seed: Seeder,
    runs: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    """位置和隔離紀錄不符（兩邊都沒有）：交給 keeper 對帳，不寫 audit、不做任何改變。"""
    shutil.rmtree(_held(runs) / str(held_run.run_id))

    assert _retry(held_run.run_id, "--max-depth", "40") == EXIT_FAILURE

    assert "位置和隔離紀錄不符" in _err(capsysbinary)
    assert _evidence(queue_seed, held_run.run_id) == []
    assert _hold(queue_seed, held_run.run_id).resolved_at is None
    assert _audits(queue_seed, "evidence.retry") == []


def test_an_unfinished_isolation_is_refused(
    environment: None,
    queue_seed: Seeder,
    runs: Path,
    store: EvidenceStore,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    """隔離中（目錄還在 active/）：先由 keeper 搬到 held/，retry 不做任何改變（§30.13）。"""
    name = uuid4()
    leaf = _deep(runs, name)
    store.hold(name, None, EvidenceHoldCode.TREE_TOO_DEEP, 3, inode(runs, name))

    assert _retry(name, "--max-depth", "40") == EXIT_FAILURE

    assert "EVIDENCE_HOLD_NOT_ISOLATED" in _err(capsysbinary)
    assert leaf.read_bytes() == CANARY
    assert _audits(queue_seed, "evidence.retry") == []


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
    assert not (_held(runs) / str(held_run.run_id) / SEALED_DIR).exists()
    assert _hold(queue_seed, held_run.run_id).resolved_at is None


def test_a_database_failure_after_sealing_is_finished_by_running_again(
    held_run: EvidenceRun,
    queue_seed: Seeder,
    queue_engine: Engine,
    runs: Path,
    key: str,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """審查的反例：搬回 active/ 之後、寫入 resolved_at 之前中斷。active/ 中只有已驗證的加密檔，
    對帳標記「解除待完成」、不搬回；再執行一次就完成（§30.13 的中斷點 6）。"""

    def broken(*_args: object, **_kwargs: object) -> None:
        raise OperationalError("UPDATE", {}, Exception("db down"))

    with monkeypatch.context() as patched:
        patched.setattr(EvidenceHolds, "resolve", broken)
        assert _retry(held_run.run_id, "--max-depth", "40") == EXIT_FAILURE
    assert "請再執行一次" in _err(capsysbinary)
    assert {entry.name for entry in (runs / str(held_run.run_id)).iterdir()} == {SEALED_DIR}
    assert not (_held(runs) / str(held_run.run_id)).exists()
    hold = _hold(queue_seed, held_run.run_id)
    assert (hold.releasing_at is not None, hold.resolved_at) == (True, None)
    assert _evidence(queue_seed, held_run.run_id) == []
    caplog.set_level(logging.WARNING)
    isolate(queue_engine, runs, _vault(runs, key))
    assert "解除待完成" in caplog.text
    assert {entry.name for entry in (runs / str(held_run.run_id)).iterdir()} == {SEALED_DIR}
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
        ["--max-path-chars", str(8 * 1024 * 1024 - 1)],
        ["--max-path-chars", str(16 * 1024 * 1024 + 1)],
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
    assert "已隔離（在 held/，worker 讀不到）1、解除中 0、隔離未完成 0" in err
    assert "EVIDENCE_TREE_TOO_DEEP 1" in err
    assert "已人工處理 0" in err
    assert "已終止但未加密 0" in err
    assert str(held_run.run_id) in err
    assert "retry-evidence" in err
    assert str(runs) not in err


def test_paths_over_the_limit_need_a_higher_path_limit(
    held_run: EvidenceRun,
    queue_seed: Seeder,
    runs: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    """路徑總長度是第三種上限：預設的上限不夠時失敗、隔離不變；指定較高的上限（不超過絕對
    上限）之後成功（使用者，2026-11-10；§30.12）。以較小的常數代替 8M／16M 字元。"""
    monkeypatch.setattr(retry_cli, "DEFAULT_LIMITS", TreeLimits(max_path_chars=500))
    monkeypatch.setattr(retry_cli, "MAX_PATH_CHARS", 5_000)

    assert _retry(held_run.run_id, "--max-depth", "40") == EXIT_FAILURE
    assert "--max-path-chars" in _err(capsysbinary)
    [failed] = _audits(queue_seed, "evidence.retry_failed")
    assert failed.redacted_changes["error_code"] == "EVIDENCE_TREE_PATHS_TOO_LONG"
    assert _leaf(runs, held_run.run_id).read_bytes() == CANARY
    with pytest.raises(SystemExit):
        _retry(held_run.run_id, "--max-depth", "40", "--max-path-chars", "5001")

    assert _retry(held_run.run_id, "--max-depth", "40", "--max-path-chars", "5000") == EXIT_OK
    assert _hold(queue_seed, held_run.run_id).resolved_at is not None


# --- 中斷點（§30.13 的中斷表）--------------------------------------------------------------------


def _only_sealed(directory: Path) -> bool:
    return {entry.name for entry in directory.iterdir()} == {SEALED_DIR}


def test_a_failure_before_releasing_keeps_the_ciphertext_in_held(
    held_run: EvidenceRun,
    queue_seed: Seeder,
    runs: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """中斷點 4：在 held/ 加密之後、寫入 releasing_at 之前 → 已隔離、held/ 只有加密檔。"""

    def broken(*_args: object, **_kwargs: object) -> bool:
        raise OperationalError("UPDATE", {}, Exception("db down"))

    with monkeypatch.context() as patched:
        patched.setattr(HoldIsolationStore, "begin_release", broken)
        assert _retry(held_run.run_id, "--max-depth", "40") == EXIT_FAILURE

    assert _only_sealed(_held(runs) / str(held_run.run_id))
    assert not (runs / str(held_run.run_id)).exists()
    hold = _hold(queue_seed, held_run.run_id)
    assert (hold.isolated_at is not None, hold.releasing_at) == (True, None)
    assert _retry(held_run.run_id, "--max-depth", "40") == EXIT_OK
    assert _hold(queue_seed, held_run.run_id).resolved_at is not None


def test_a_failure_while_moving_back_keeps_the_directory_in_held(
    held_run: EvidenceRun,
    queue_seed: Seeder,
    queue_engine: Engine,
    runs: Path,
    key: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """中斷點 5：寫入 releasing_at 之後、搬回之前 → 解除中、目錄在 held/；對帳不動它。"""

    def broken(*_args: object, **_kwargs: object) -> None:
        raise MoveError(HoldMoveCode.MOVE_FAILED, "無法搬移（EIO）")

    with monkeypatch.context() as patched:
        patched.setattr(HoldMoves, "move", broken)
        assert _retry(held_run.run_id, "--max-depth", "40") == EXIT_FAILURE

    [failed] = _audits(queue_seed, "evidence.retry_failed")
    assert failed.redacted_changes["error_code"] == "EVIDENCE_HOLD_MOVE_FAILED"
    assert _hold(queue_seed, held_run.run_id).releasing_at is not None
    isolate(queue_engine, runs, _vault(runs, key))
    assert _only_sealed(_held(runs) / str(held_run.run_id))
    assert _retry(held_run.run_id) == EXIT_OK
    assert _only_sealed(runs / str(held_run.run_id))


def test_a_failed_check_in_active_moves_the_directory_back(
    held_run: EvidenceRun,
    queue_seed: Seeder,
    runs: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    """第 8 步在 active/ 驗證不通過 → 搬回 held/、exit 1；再執行一次從第 4 步重新開始。"""
    calls: list[Path] = []
    real = retry_cli.verified

    def failing_in_active(vault: EvidenceVault, name: str) -> SealedEvidence:
        calls.append(vault.volume)
        if len(calls) == 2:
            raise EvidenceError("加密檔解不開：金鑰不對，或內容被改過")
        return real(vault, name)

    with monkeypatch.context() as patched:
        patched.setattr(retry_cli, "verified", failing_in_active)
        assert _retry(held_run.run_id, "--max-depth", "40") == EXIT_FAILURE

    assert "已搬回 held/" in _err(capsysbinary)
    assert _only_sealed(_held(runs) / str(held_run.run_id))
    assert not (runs / str(held_run.run_id)).exists()
    assert _hold(queue_seed, held_run.run_id).resolved_at is None
    assert _retry(held_run.run_id) == EXIT_OK


def test_rotation_also_rewrites_ciphertext_in_held(
    held_run: EvidenceRun,
    queue_seed: Seeder,
    runs: Path,
    key: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """解除中的目錄已有加密檔：rotate-evidence-keys 也處理 held/（§30.13）。"""

    def broken(*_args: object, **_kwargs: object) -> bool:
        raise OperationalError("UPDATE", {}, Exception("db down"))

    with monkeypatch.context() as patched:
        patched.setattr(HoldIsolationStore, "begin_release", broken)
        _retry(held_run.run_id, "--max-depth", "40")
    new_key = Fernet.generate_key().decode()
    monkeypatch.setenv("EVIDENCE_ENCRYPTION_KEYS", f"{new_key},{key}")

    assert main(["rotate-evidence-keys"]) == EXIT_OK

    [rotated] = _audits(queue_seed, "evidence_keys.rotate")
    assert rotated.redacted_changes == {"files": 2, "failures": 0}
    monkeypatch.setenv("EVIDENCE_ENCRYPTION_KEYS", new_key)
    assert _retry(held_run.run_id, "--max-depth", "40") == EXIT_OK


def test_retention_status_shows_unfinished_isolation_as_urgent(
    environment: None,
    queue_engine: Engine,
    runs: Path,
    store: EvidenceStore,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    """隔離未完成（明文仍在 active/）：數量、警告、經過時間與搬移失敗；超過門檻的列為需要緊急處理
    （主動告警是 T35）。以 0 分鐘的門檻代替 15 分鐘。"""
    name = uuid4()
    _deep(runs, name)
    store.hold(name, None, EvidenceHoldCode.TREE_TOO_DEEP, 3, inode(runs, name))
    isolation = HoldIsolationStore(sessionmaker(queue_engine, expire_on_commit=False))
    assert isolation.record_move_failure(name, HoldMoveCode.CONFLICT)
    monkeypatch.setattr(evidence_cli, "ISOLATION_URGENT_AFTER", timedelta(0))

    assert main(["retention-status"]) == EXIT_OK

    err = _err(capsysbinary)
    assert "隔離未完成 1（其中超過 0 分鐘、需要緊急處理 1）" in err
    assert "worker 可能讀得到" in err
    assert "T35" in err
    assert f"{name}（需要緊急處理，已 0 分鐘）" in err
    assert "搬移失敗 1 次，最近一次 EVIDENCE_HOLD_CONFLICT" in err
    assert str(runs) not in err


@pytest.mark.parametrize(
    ("host_offset", "urgent_after", "urgent"),
    [
        # 主機的時鐘比 DB 慢：以主機的時間計算，經過時間是負的、不會列為緊急。
        (timedelta(hours=-1), timedelta(0), 1),
        # 主機的時鐘比 DB 快：以主機的時間計算，剛隔離的目錄也會超過 15 分鐘的門檻。
        (timedelta(hours=1), timedelta(minutes=15), 0),
    ],
)
def test_retention_status_measures_isolation_time_with_the_database_clock(
    environment: None,
    queue_engine: Engine,
    runs: Path,
    store: EvidenceStore,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
    host_offset: timedelta,
    urgent_after: timedelta,
    urgent: int,
) -> None:
    """held_at 由 DB 的時鐘寫入：經過時間與緊急的判斷也用 DB 的時鐘，主機與 DB 容器的時鐘誤差
    不影響結果（原本以主機的時間計算，誤差幾毫秒就讓上面的測試間歇性失敗）。"""

    class SkewedClock(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> datetime:  # type: ignore[override]
            return datetime.now(tz) + host_offset

    name = uuid4()
    _deep(runs, name)
    store.hold(name, None, EvidenceHoldCode.TREE_TOO_DEEP, 3, inode(runs, name))
    monkeypatch.setattr(evidence_cli, "datetime", SkewedClock)
    monkeypatch.setattr(evidence_cli, "ISOLATION_URGENT_AFTER", urgent_after)
    threshold = int(urgent_after.total_seconds() // 60)

    assert main(["retention-status"]) == EXIT_OK

    err = _err(capsysbinary)
    assert f"隔離未完成 1（其中超過 {threshold} 分鐘、需要緊急處理 {urgent}）" in err
    label = "需要緊急處理，已 0 分鐘" if urgent else "已 0 分鐘"
    assert f"{name}（{label}）" in err


def test_a_failed_check_in_held_does_not_start_the_release(
    held_run: EvidenceRun,
    queue_seed: Seeder,
    runs: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """第 5 步：held/ 中的加密檔沒有逐一驗證通過，就不寫 releasing_at、不搬回 active/。"""

    def failing(_vault: EvidenceVault, _name: str) -> SealedEvidence:
        raise EvidenceError("加密檔解不開：金鑰不對，或內容被改過")

    monkeypatch.setattr(retry_cli, "verified", failing)

    assert _retry(held_run.run_id, "--max-depth", "40") == EXIT_FAILURE

    assert _hold(queue_seed, held_run.run_id).releasing_at is None
    assert (_held(runs) / str(held_run.run_id)).is_dir()
    assert not (runs / str(held_run.run_id)).exists()


def test_unexpected_entries_in_sealed_stop_the_release(
    held_run: EvidenceRun,
    queue_seed: Seeder,
    runs: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    """安全審查 LOW-2：sealed/ 中有加密檔以外的條目（例如點開頭的檔案）就不搬回 active/。"""
    sealed = _held(runs) / str(held_run.run_id) / SEALED_DIR
    sealed.mkdir()
    (sealed / ".hidden").write_bytes(CANARY)

    assert _retry(held_run.run_id, "--max-depth", "40") == EXIT_FAILURE

    assert "加密檔以外的條目" in _err(capsysbinary)
    assert _hold(queue_seed, held_run.run_id).releasing_at is None
    assert not (runs / str(held_run.run_id)).exists()
