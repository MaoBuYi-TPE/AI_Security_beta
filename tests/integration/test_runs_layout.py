"""secscan-admin migrate-runs-layout（EVID-12；docs/DECISIONS.md §30.13）。

舊的 runs volume（run 目錄直接在根目錄）搬到新的 layout：
- 有還沒解除的隔離紀錄的目錄搬到 held/（先記下來源 inode，確認身分之後寫入 isolated_at），其他的
  搬到 active/；其他條目不動。--dry-run 不做任何改變。
- 可以重跑；中斷之後（暫存目錄、還沒寫 isolated_at）再執行一次就完成；有衝突時不完成 layout。
- 前提：容器內的 volume 名稱與掛載、沒有 lease 有效的 run、沒有容器還沒確認刪除的 run、拿得到鎖。
"""

import argparse
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from secscan.cli import EXIT_FAILURE, EXIT_OK, runs_layout
from secscan.cli import evidence as evidence_cli
from secscan.core.config import Settings
from secscan.runner.layout import LAYOUT_FILE, MIGRATING_DIR, check_layout
from secscan.runner.plans import ENGINE_IMAGES
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.evidence_records import EvidenceStore
from secscan.scans.queue import ScanQueue
from tests.integration.api_support import LAB, Seeder
from tests.integration.database import ProvisionedDatabase

pytestmark = pytest.mark.integration

CANARY = b"canary-runs-layout-5f3a"


@pytest.fixture
def volume(tmp_path: Path) -> Path:
    """舊的 layout：run 目錄直接在根目錄。"""
    root = tmp_path / "runs"
    root.mkdir()
    return root


@pytest.fixture
def messages() -> list[str]:
    return []


def _run_directory(volume: Path, name: str | None = None) -> str:
    name = name or str(uuid4())
    (volume / name / "out").mkdir(parents=True)
    (volume / name / "out" / "messages.txt").write_bytes(CANARY)
    return name


def _legacy_hold(engine: Engine, directory: str) -> None:
    """v0024 之前留下、還沒解除的孤兒目錄的隔離紀錄（沒有 inode；測試暫時關閉 trigger 寫入）。"""
    with Session(engine) as session, session.begin():
        session.execute(text("ALTER TABLE evidence_holds DISABLE TRIGGER evidence_holds_guard"))
        session.execute(
            text(
                "INSERT INTO evidence_holds (directory, error_code, attempts) "
                "VALUES (:directory, 'EVIDENCE_TREE_TOO_DEEP', 3)"
            ),
            {"directory": directory},
        )
        session.execute(text("ALTER TABLE evidence_holds ENABLE TRIGGER evidence_holds_guard"))


def _migrate(engine: Engine, volume: Path, messages: list[str], *, dry_run: bool = False) -> int:
    return runs_layout.migrate_volume(engine, volume, dry_run=dry_run, report=messages.append)


def _hold(seed: Seeder, directory: str) -> Any:
    [row] = seed.query("SELECT * FROM evidence_holds WHERE directory = :id", id=UUID(directory))
    return row


def _audits(seed: Seeder, action: str) -> list[Any]:
    return list(
        seed.query(
            "SELECT redacted_changes FROM audit_events WHERE action = :action", action=action
        )
    )


def _tree(volume: Path) -> set[str]:
    return {str(path.relative_to(volume)) for path in volume.rglob("*")}


# --- 搬移 --------------------------------------------------------------------------------------


def test_dry_run_changes_nothing(
    queue_engine: Engine, queue_seed: Seeder, volume: Path, messages: list[str]
) -> None:
    normal = _run_directory(volume)
    held = _run_directory(volume)
    _legacy_hold(queue_engine, held)
    (volume / "notes\x1b[31m.txt").write_bytes(b"x")
    before = _tree(volume)

    assert _migrate(queue_engine, volume, messages, dry_run=True) == EXIT_OK

    assert _tree(volume) == before
    output = "\n".join(messages)
    assert "搬到 active/ 1 個、搬到 held/（還沒解除的隔離）1 個" in output
    assert f"搬到 held/：{held}" in output
    assert "notes\\x1b[31m.txt" in output
    assert normal not in output
    assert _audits(queue_seed, "runs_layout.migrate") == []


def test_the_volume_is_migrated_and_legacy_holds_are_isolated(
    queue_engine: Engine, queue_seed: Seeder, volume: Path, messages: list[str]
) -> None:
    normal = _run_directory(volume)
    held = _run_directory(volume)
    held_ino = (volume / held).stat().st_ino
    _legacy_hold(queue_engine, held)
    (volume / "notes.txt").write_bytes(b"x")

    assert _migrate(queue_engine, volume, messages) == EXIT_OK

    assert (volume / "active" / normal / "out" / "messages.txt").read_bytes() == CANARY
    assert (volume / "held" / held / "out" / "messages.txt").read_bytes() == CANARY
    assert (volume / "notes.txt").exists()
    assert not (volume / MIGRATING_DIR).exists()
    assert check_layout(volume).others == 1
    row = _hold(queue_seed, held)
    assert (row.source_ino, row.isolated_at is not None) == (held_ino, True)
    [planned] = _audits(queue_seed, "runs_layout.migrate")
    assert planned.redacted_changes == {
        "to_active": 1,
        "to_held": 1,
        "others": 1,
        "has_marker": False,
        "blocking": 0,
    }
    [done] = _audits(queue_seed, "runs_layout.migrated")
    assert done.redacted_changes == {
        "moved_active": 1,
        "moved_held": 1,
        "isolated": 1,
        "unverified": 0,
        "conflicts": 0,
    }

    assert _migrate(queue_engine, volume, messages) == EXIT_OK
    assert check_layout(volume).others == 1


def test_an_empty_volume_only_gets_the_structure(
    queue_engine: Engine, volume: Path, messages: list[str]
) -> None:
    assert _migrate(queue_engine, volume, messages) == EXIT_OK

    assert sorted(entry.name for entry in volume.iterdir()) == [LAYOUT_FILE, "active", "held"]


def test_an_interrupted_migration_is_finished_by_running_again(
    queue_engine: Engine, queue_seed: Seeder, volume: Path, messages: list[str]
) -> None:
    """中斷在搬進暫存目錄之後、改名成 active 之前，以及搬到 held/ 之後、寫 isolated_at 之前。"""
    moved = _run_directory(volume)
    remaining = _run_directory(volume)
    held = _run_directory(volume)
    held_ino = (volume / held).stat().st_ino
    _legacy_hold(queue_engine, held)
    with Session(queue_engine) as session, session.begin():
        session.execute(
            text("UPDATE evidence_holds SET source_ino = :ino WHERE directory = :id"),
            {"ino": held_ino, "id": held},
        )
    (volume / MIGRATING_DIR).mkdir(mode=0o700)
    (volume / moved).rename(volume / MIGRATING_DIR / moved)
    (volume / "held").mkdir(mode=0o700)
    (volume / held).rename(volume / "held" / held)

    assert _migrate(queue_engine, volume, messages) == EXIT_OK

    assert (volume / "active" / moved).is_dir()
    assert (volume / "active" / remaining).is_dir()
    assert _hold(queue_seed, held).isolated_at is not None
    check_layout(volume)


def test_a_conflict_keeps_both_directories_and_does_not_finish(
    queue_engine: Engine, queue_seed: Seeder, volume: Path, messages: list[str]
) -> None:
    held = _run_directory(volume)
    _legacy_hold(queue_engine, held)
    (volume / "held" / held).mkdir(parents=True)
    (volume / "held" / held / "existing.txt").write_bytes(b"keep")
    normal = _run_directory(volume)

    assert _migrate(queue_engine, volume, messages) == EXIT_FAILURE

    assert (volume / held / "out" / "messages.txt").read_bytes() == CANARY
    assert (volume / "held" / held / "existing.txt").read_bytes() == b"keep"
    assert (volume / MIGRATING_DIR / normal).is_dir()
    assert not (volume / LAYOUT_FILE).exists()
    assert _hold(queue_seed, held).isolated_at is None
    assert held in "\n".join(messages)
    [failed] = _audits(queue_seed, "runs_layout.migrate_failed")
    assert failed.redacted_changes["conflicts"] == 1


def test_a_uuid_named_symlink_is_not_followed_and_blocks_the_plan(
    queue_engine: Engine, queue_seed: Seeder, volume: Path, tmp_path: Path, messages: list[str]
) -> None:
    """程式碼審查 L1：UUID 名稱、但不是目錄的條目在計畫階段就阻擋（layout 不允許它們），不跟隨、
    不做任何改變。"""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_bytes(CANARY)
    link = str(uuid4())
    (volume / link).symlink_to(outside)
    normal = _run_directory(volume)

    assert _migrate(queue_engine, volume, messages) == EXIT_FAILURE

    assert (volume / link).is_symlink()
    assert (volume / normal).is_dir()
    assert not (volume / "active").exists()
    assert (outside / "secret.txt").read_bytes() == CANARY
    output = "\n".join(messages)
    assert f"UUID 名稱、但不是目錄（阻擋）：{link}" in output
    assert _audits(queue_seed, "runs_layout.migrate") == []


def test_an_unverified_isolation_does_not_stop_the_others(
    queue_engine: Engine, queue_seed: Seeder, volume: Path, messages: list[str]
) -> None:
    """程式碼審查 L1：held/ 中的目錄身分和紀錄不符時不寫入 isolated_at，其他紀錄照常完成。"""
    good = _run_directory(volume)
    _legacy_hold(queue_engine, good)
    stray = str(uuid4())
    _legacy_hold(queue_engine, stray)
    with Session(queue_engine) as session, session.begin():
        session.execute(
            text("UPDATE evidence_holds SET source_ino = 1 WHERE directory = :id"), {"id": stray}
        )
    (volume / "held").mkdir(mode=0o700)
    _run_directory(volume / "held", stray)

    assert _migrate(queue_engine, volume, messages) == EXIT_OK

    assert _hold(queue_seed, good).isolated_at is not None
    assert _hold(queue_seed, stray).isolated_at is None
    assert f"身分和紀錄不符（{stray}）" in "\n".join(messages)
    [done] = _audits(queue_seed, "runs_layout.migrated")
    assert done.redacted_changes["unverified"] == 1


# --- 前提 --------------------------------------------------------------------------------------


def test_a_run_with_a_valid_lease_blocks_the_migration(
    queue_engine: Engine, queue_seed: Seeder, volume: Path, messages: list[str]
) -> None:
    queue = ScanQueue(
        sessionmaker(queue_engine, expire_on_commit=False), lab=LAB, clock=lambda: datetime.now(UTC)
    )
    world = queue_seed.world()
    queue_seed.scan(world.operator_a, queue_seed.scannable(world))
    assert queue.claim("runner-elsewhere", frozenset({ScanEngine.FAKE})) is not None
    name = _run_directory(volume)

    assert _migrate(queue_engine, volume, messages) == EXIT_FAILURE

    assert (volume / name).is_dir()
    assert "lease" in "\n".join(messages)
    assert _audits(queue_seed, "runs_layout.migrate") == []


def test_an_unconfirmed_container_blocks_the_migration_with_a_way_out(
    queue_engine: Engine, queue_seed: Seeder, volume: Path, messages: list[str]
) -> None:
    """runner 異常結束留下容器還沒確認刪除的 run：拒絕，並說明以升級之前的版本對帳
    （資料庫審查 M2）。"""
    queue = ScanQueue(
        sessionmaker(queue_engine, expire_on_commit=False), lab=LAB, clock=lambda: datetime.now(UTC)
    )
    world = queue_seed.world()
    queue_seed.scan(world.operator_a, queue_seed.scannable(world))
    lease = queue.claim("runner-elsewhere", frozenset({ScanEngine.FAKE}))
    assert lease is not None
    queue.prepare_launch(lease, image_ref=str(ENGINE_IMAGES[ScanEngine.FAKE]))
    queue.advance(lease, RunStatus.FAILED, error_code=RunErrorCode.ENGINE_FAILED)
    name = _run_directory(volume)

    assert _migrate(queue_engine, volume, messages) == EXIT_FAILURE

    output = "\n".join(messages)
    assert "容器還沒確認刪除" in output
    assert "人工修復" in output
    assert (volume / name).is_dir()


def test_a_busy_evidence_lock_blocks_the_migration(
    queue_engine: Engine, volume: Path, messages: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(evidence_cli, "LOCK_ATTEMPTS", 1)
    store = EvidenceStore(sessionmaker(queue_engine), engine=queue_engine)
    name = _run_directory(volume)

    with store.exclusive() as acquired:
        assert acquired
        assert _migrate(queue_engine, volume, messages) == EXIT_FAILURE

    assert (volume / name).is_dir()


@pytest.fixture
def environment(
    queue_database: ProvisionedDatabase, monkeypatch: pytest.MonkeyPatch, volume: Path
) -> Settings:
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("DB_HOST", queue_database.host)
    monkeypatch.setenv("DB_PORT", str(queue_database.port))
    monkeypatch.setenv("DB_NAME", queue_database.name)
    monkeypatch.setenv("DB_USER", queue_database.user)
    monkeypatch.setenv("DB_PASSWORD", queue_database.password)
    monkeypatch.setenv("RUNNER_RUNS_DIR", str(volume))
    monkeypatch.setenv("RUNNER_RUNS_VOLUME", "custom_runs")
    return Settings()


def _command(
    settings: Settings, messages: list[str], expected: str, mounted: Callable[[Path], bool]
) -> int | None:
    args = argparse.Namespace(
        command=runs_layout.MIGRATE_COMMAND, expect_volume=expected, dry_run=False
    )
    return runs_layout.run(args, settings, messages.append, mounted=mounted)


@pytest.mark.parametrize(
    ("expected", "mounted", "message"),
    [
        ("secscan_runs", True, "RUNNER_RUNS_VOLUME"),
        ("custom_runs", False, "掛載點"),
        ("bad name", True, "不是合法的 volume 名稱"),
    ],
)
def test_the_container_checks_the_volume_before_anything(
    environment: Settings,
    volume: Path,
    messages: list[str],
    expected: str,
    mounted: bool,
    message: str,
) -> None:
    """主機解析的 volume 和容器內的不同、或 runs 不是掛載點：拒絕，沒有做任何改變。"""
    name = _run_directory(volume)

    assert _command(environment, messages, expected, lambda _path: mounted) == EXIT_FAILURE

    assert message in "\n".join(messages)
    assert (volume / name).is_dir()
    assert not (volume / "active").exists()


def test_the_command_migrates_the_expected_volume(
    environment: Settings, volume: Path, messages: list[str]
) -> None:
    name = _run_directory(volume)

    assert _command(environment, messages, "custom_runs", lambda path: path == volume) == EXIT_OK

    assert (volume / "active" / name).is_dir()
    assert runs_layout.run(argparse.Namespace(command="other"), environment, print) is None
