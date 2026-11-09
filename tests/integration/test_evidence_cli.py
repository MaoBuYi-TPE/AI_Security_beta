"""secscan-admin 的原始證據指令（EVID-07、ROT-01；docs/DECISIONS.md §30.3、§30.6）。

- export-evidence：列出加密檔；匯出時先完整驗證、寫入 audit，才把明文寫到 stdout；解不開時不輸出、
  不寫 audit。
- rotate-evidence-keys：換版之後只有新金鑰也解得開；keeper 持有鎖時不動任何檔案。
- retention-status：只有數量。
設定以環境變數指向這個測試的資料庫與暫存的 runs 目錄。
"""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.cli import EXIT_FAILURE, EXIT_OK, main
from secscan.cli import evidence as evidence_cli
from secscan.runner.evidence import SEALED_DIR, EvidenceError, EvidenceVault
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.evidence_records import EvidenceRun, EvidenceStore
from secscan.scans.queue import ScanQueue
from secscan.security.key_rings import evidence_cipher
from tests.integration.api_support import LAB, Seeder
from tests.integration.database import ProvisionedDatabase

pytestmark = pytest.mark.integration

FAKE = frozenset({ScanEngine.FAKE})
CANARY = b"canary-evidence-export-9b4c"
REPORT = b'{"alerts": "' + CANARY + b'"}'


@pytest.fixture
def runs(tmp_path: Path) -> Path:
    directory = tmp_path / "runs"
    directory.mkdir()
    return directory


@pytest.fixture
def old_key() -> str:
    return Fernet.generate_key().decode()


@pytest.fixture
def environment(
    queue_database: ProvisionedDatabase,
    monkeypatch: pytest.MonkeyPatch,
    runs: Path,
    old_key: str,
) -> None:
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("DB_HOST", queue_database.host)
    monkeypatch.setenv("DB_PORT", str(queue_database.port))
    monkeypatch.setenv("DB_NAME", queue_database.name)
    monkeypatch.setenv("DB_USER", queue_database.user)
    monkeypatch.setenv("DB_PASSWORD", queue_database.password)
    monkeypatch.setenv("EVIDENCE_ENCRYPTION_KEYS", old_key)
    monkeypatch.setenv("RUNNER_RUNS_DIR", str(runs))


@pytest.fixture
def sealed_run(
    environment: None, queue_seed: Seeder, queue_engine: Engine, runs: Path, old_key: str
) -> EvidenceRun:
    """一個已終止、已加密的 run（三個檔案）。"""
    queue = ScanQueue(
        sessionmaker(queue_engine, expire_on_commit=False), lab=LAB, clock=lambda: datetime.now(UTC)
    )
    world = queue_seed.world()
    queue_seed.scan(world.operator_a, queue_seed.scannable(world))
    lease = queue.claim("runner-cli", FAKE)
    assert lease is not None
    root = runs / str(lease.run_id)
    (root / "out").mkdir(parents=True)
    (root / "out" / "report.json").write_bytes(REPORT)
    (root / "manifest.json").write_bytes(b"{}")
    queue.prepare(lease)
    queue.advance(lease, RunStatus.FAILED, error_code=RunErrorCode.ENGINE_FAILED)
    run = EvidenceRun(lease.run_id, lease.scan_id)
    sealed = EvidenceVault(runs, evidence_cipher(old_key)).seal(str(run.run_id))
    store = EvidenceStore(sessionmaker(queue_engine), engine=queue_engine)
    assert store.record(run, sealed)
    return run


def _audits(seed: Seeder, action: str) -> list[dict[str, object]]:
    rows = seed.query(
        "SELECT redacted_changes, actor_key_id, object_id, project_id FROM audit_events "
        "WHERE action = :action ORDER BY created_at",
        action=action,
    )
    return [dict(row._mapping) for row in rows]


def test_listing_shows_paths_sizes_and_hashes(
    sealed_run: EvidenceRun, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    assert main(["export-evidence", "--run", str(sealed_run.run_id)]) == EXIT_OK

    out, _err = capsysbinary.readouterr()
    lines = [json.loads(line) for line in out.decode().splitlines()]
    assert {line["path"] for line in lines} == {"out/report.json", "manifest.json"}
    [report] = [line for line in lines if line["path"] == "out/report.json"]
    assert report == {
        "path": "out/report.json",
        "sha256": hashlib.sha256(REPORT).hexdigest(),
        "size_bytes": len(REPORT),
    }
    assert CANARY not in out


def test_export_is_audited_before_the_plaintext_is_written(
    sealed_run: EvidenceRun, queue_seed: Seeder, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    run_id = str(sealed_run.run_id)

    assert main(["export-evidence", "--run", run_id, "--path", "out/report.json"]) == EXIT_OK

    out, err = capsysbinary.readouterr()
    assert out == REPORT
    assert hashlib.sha256(REPORT).hexdigest() in err.decode()
    [audit] = _audits(queue_seed, "evidence.export")
    assert audit["object_id"] == sealed_run.run_id
    assert audit["actor_key_id"] is None
    assert audit["project_id"] is not None
    changes = audit["redacted_changes"]
    assert isinstance(changes, dict)
    assert changes["path_sha256"] == hashlib.sha256(b"out/report.json").hexdigest()
    assert "report.json" not in json.dumps(changes)


def test_an_unreadable_export_writes_nothing(
    sealed_run: EvidenceRun,
    queue_seed: Seeder,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    monkeypatch.setenv("EVIDENCE_ENCRYPTION_KEYS", Fernet.generate_key().decode())
    run_id = str(sealed_run.run_id)

    assert main(["export-evidence", "--run", run_id, "--path", "out/report.json"]) == EXIT_FAILURE

    out, err = capsysbinary.readouterr()
    assert out == b""
    assert "解不開" in err.decode()
    assert _audits(queue_seed, "evidence.export") == []


def test_export_needs_the_evidence_keys(
    sealed_run: EvidenceRun,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    monkeypatch.delenv("EVIDENCE_ENCRYPTION_KEYS")

    assert main(["export-evidence", "--run", str(sealed_run.run_id)]) == EXIT_FAILURE

    assert "EVIDENCE_ENCRYPTION_KEYS" in capsysbinary.readouterr().err.decode()


def test_rotation_moves_everything_to_the_new_key(
    sealed_run: EvidenceRun,
    queue_seed: Seeder,
    runs: Path,
    old_key: str,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    new_key = Fernet.generate_key().decode()
    monkeypatch.setenv("EVIDENCE_ENCRYPTION_KEYS", f"{new_key},{old_key}")

    assert main(["rotate-evidence-keys"]) == EXIT_OK

    assert "2 個檔案" in capsysbinary.readouterr().err.decode()
    only_new = EvidenceVault(runs, evidence_cipher(new_key))
    assert {info.path for info in only_new.listing(str(sealed_run.run_id))} == {
        "out/report.json",
        "manifest.json",
    }
    [audit] = _audits(queue_seed, "evidence_keys.rotate")
    assert audit["redacted_changes"] == {"files": 2, "failures": 0}
    monkeypatch.setenv("EVIDENCE_ENCRYPTION_KEYS", new_key)
    assert main(["rotate-evidence-keys"]) == EXIT_OK


def test_rotation_without_the_old_key_keeps_the_files(
    sealed_run: EvidenceRun,
    runs: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    sealed = runs / str(sealed_run.run_id) / SEALED_DIR
    before = {path.name: path.read_bytes() for path in sealed.iterdir()}
    monkeypatch.setenv("EVIDENCE_ENCRYPTION_KEYS", Fernet.generate_key().decode())

    assert main(["rotate-evidence-keys"]) == EXIT_FAILURE

    err = capsysbinary.readouterr().err.decode()
    assert str(sealed_run.run_id) in err
    assert {path.name: path.read_bytes() for path in sealed.iterdir()} == before


def test_rotation_waits_for_the_keeper_and_gives_up_without_changes(
    sealed_run: EvidenceRun,
    queue_engine: Engine,
    runs: Path,
    old_key: str,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    monkeypatch.setattr(evidence_cli, "LOCK_ATTEMPTS", 2)
    monkeypatch.setattr(evidence_cli, "LOCK_WAIT_SECONDS", 0.0)
    monkeypatch.setenv("EVIDENCE_ENCRYPTION_KEYS", f"{Fernet.generate_key().decode()},{old_key}")
    sealed = runs / str(sealed_run.run_id) / SEALED_DIR
    before = {path.name: path.read_bytes() for path in sealed.iterdir()}
    store = EvidenceStore(sessionmaker(queue_engine), engine=queue_engine)

    with store.exclusive() as acquired:
        assert acquired
        assert main(["rotate-evidence-keys"]) == EXIT_FAILURE

    assert "等不到鎖" in capsysbinary.readouterr().err.decode()
    assert {path.name: path.read_bytes() for path in sealed.iterdir()} == before


def test_the_keeper_lock_is_exclusive(sealed_run: EvidenceRun, queue_engine: Engine) -> None:
    store = EvidenceStore(sessionmaker(queue_engine), engine=queue_engine)

    with store.exclusive() as first, store.exclusive() as second:
        assert (first, second) == (True, False)
    with store.exclusive() as again:
        assert again


def test_retention_status_shows_only_counts(
    sealed_run: EvidenceRun, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    assert main(["retention-status"]) == EXIT_OK

    err = capsysbinary.readouterr().err.decode()
    assert "已加密 1" in err
    assert "報告內容：保留中 0" in err
    assert "人工複測摘錄：保留中 0" in err
    assert str(sealed_run.run_id) not in err


# --- 審查之後（docs/DECISIONS.md §30.11）--------------------------------------------------------


def test_listing_is_audited_and_escapes_tool_controlled_names(
    environment: None,
    queue_seed: Seeder,
    queue_engine: Engine,
    runs: Path,
    old_key: str,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    """檔名由工具決定：列表以 ASCII 跳脫（控制字元與 bidi 不直接印到終端），而且也寫 audit
    （列表會解密驗證每個檔案；安全審查 L5）。"""
    queue = ScanQueue(
        sessionmaker(queue_engine, expire_on_commit=False), lab=LAB, clock=lambda: datetime.now(UTC)
    )
    world = queue_seed.world()
    queue_seed.scan(world.operator_a, queue_seed.scannable(world))
    lease = queue.claim("runner-cli", FAKE)
    assert lease is not None
    tricky = "out/‮report\x1b[31m.json"
    root = runs / str(lease.run_id)
    (root / "out").mkdir(parents=True)
    (root / tricky).write_bytes(REPORT)
    EvidenceVault(runs, evidence_cipher(old_key)).seal(str(lease.run_id))

    assert main(["export-evidence", "--run", str(lease.run_id)]) == EXIT_OK

    out, _err = capsysbinary.readouterr()
    assert out.isascii()
    [line] = [json.loads(item) for item in out.decode().splitlines()]
    assert line["path"] == tricky
    [audit] = _audits(queue_seed, "evidence.list")
    assert audit["object_id"] == lease.run_id
    assert audit["redacted_changes"] == {"run_id": str(lease.run_id), "files": 1}


def test_rotation_fails_without_changes_when_the_volume_cannot_be_listed(
    sealed_run: EvidenceRun,
    runs: Path,
    old_key: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """runs volume 的目錄超過上限或列不出來時不能截斷、回報成功（安全審查 L2）。"""
    before = {
        path: path.read_bytes()
        for path in (runs / str(sealed_run.run_id)).rglob("*")
        if path.is_file()
    }
    monkeypatch.setattr(evidence_cli, "EvidenceVault", _OverflowingVault)

    assert main(["rotate-evidence-keys"]) == EXIT_FAILURE

    assert "上限" in capsys.readouterr().err
    after = {
        path: path.read_bytes()
        for path in (runs / str(sealed_run.run_id)).rglob("*")
        if path.is_file()
    }
    assert after == before


class _OverflowingVault(EvidenceVault):
    def entries(self) -> tuple[str, ...]:
        raise EvidenceError("runs volume 中的目錄數量超過上限")
