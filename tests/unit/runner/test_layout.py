"""runs volume 的 layout 檢查與初始化（EVID-12；docs/DECISIONS.md §30.13）。

有 .layout 也重新檢查全部條件：標記檔、沒有搬移的 UUID 目錄、搬移中的暫存目錄、active/ 與 held/。
"""

import os
from pathlib import Path
from uuid import uuid4

import pytest

from secscan.cli import EXIT_FAILURE, EXIT_OK, main
from secscan.runner.layout import (
    LAYOUT_CONTENT,
    LAYOUT_FILE,
    MIGRATING_DIR,
    LayoutError,
    check_layout,
    init_layout,
)


@pytest.fixture
def volume(tmp_path: Path) -> Path:
    root = tmp_path / "runs"
    root.mkdir()
    return root


def test_an_empty_volume_gets_the_new_layout(volume: Path) -> None:
    report = init_layout(volume)

    assert (report.created, report.others) == (True, 0)
    assert sorted(entry.name for entry in volume.iterdir()) == [LAYOUT_FILE, "active", "held"]
    assert (volume / LAYOUT_FILE).read_bytes() == LAYOUT_CONTENT
    for area in ("active", "held"):
        assert (volume / area).stat().st_mode & 0o777 == 0o700
    assert check_layout(volume).created is False


def test_init_is_idempotent_and_counts_other_entries(volume: Path) -> None:
    init_layout(volume)
    (volume / "lost+found").mkdir()

    report = init_layout(volume)

    assert (report.created, report.others) == (False, 1)


def test_a_marker_does_not_hide_unmigrated_run_directories(volume: Path) -> None:
    """審查的反例：runs-init 看到 .layout，但根目錄仍有還沒搬移的 UUID 目錄 → 啟動失敗。"""
    init_layout(volume)
    (volume / str(uuid4())).mkdir()

    with pytest.raises(LayoutError, match="make runs-layout-migrate"):
        init_layout(volume)
    with pytest.raises(LayoutError, match="沒搬移的 run 目錄"):
        check_layout(volume)


def test_a_uuid_named_file_or_symlink_also_blocks(volume: Path, tmp_path: Path) -> None:
    init_layout(volume)
    (volume / str(uuid4())).symlink_to(tmp_path)

    with pytest.raises(LayoutError, match="沒搬移"):
        check_layout(volume)


def test_the_old_layout_needs_the_migration(volume: Path) -> None:
    (volume / str(uuid4())).mkdir()

    with pytest.raises(LayoutError, match=r"沒有 \.layout"):
        init_layout(volume)
    assert not (volume / "active").exists()


def test_an_unfinished_migration_blocks(volume: Path) -> None:
    init_layout(volume)
    (volume / MIGRATING_DIR).mkdir()

    with pytest.raises(LayoutError, match="搬移還沒完成"):
        check_layout(volume)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b'{"layout": 1}', "不是預期的版本"),
        (b"x" * 65, "不是預期的一般檔案"),
        (b"", "不是預期的版本"),
    ],
)
def test_the_marker_must_be_exactly_the_expected_version(
    volume: Path, content: bytes, message: str
) -> None:
    init_layout(volume)
    (volume / LAYOUT_FILE).write_bytes(content)

    with pytest.raises(LayoutError, match=message):
        check_layout(volume)


def test_a_symlinked_or_special_marker_is_refused(volume: Path, tmp_path: Path) -> None:
    init_layout(volume)
    target = tmp_path / "elsewhere"
    target.write_bytes(LAYOUT_CONTENT)
    (volume / LAYOUT_FILE).unlink()
    (volume / LAYOUT_FILE).symlink_to(target)
    with pytest.raises(LayoutError, match="一般檔案"):
        check_layout(volume)

    (volume / LAYOUT_FILE).unlink()
    os.mkfifo(volume / LAYOUT_FILE)
    with pytest.raises(LayoutError, match="一般檔案"):
        check_layout(volume)


@pytest.mark.parametrize("area", ["active", "held"])
def test_each_area_must_be_a_private_real_directory(
    volume: Path, tmp_path: Path, area: str
) -> None:
    init_layout(volume)
    (volume / area).chmod(0o755)
    with pytest.raises(LayoutError, match="0700"):
        check_layout(volume)

    (volume / area).rmdir()
    with pytest.raises(LayoutError, match=f"沒有 {area}/"):
        check_layout(volume)

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    (volume / area).symlink_to(elsewhere)
    with pytest.raises(LayoutError, match="不是目錄"):
        check_layout(volume)


def test_a_missing_volume_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(LayoutError, match="無法開啟 runs volume"):
        check_layout(tmp_path / "missing")


def test_a_failed_marker_write_leaves_no_partial_file(
    volume: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_args: object, **_kwargs: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "rename", broken)

    with pytest.raises(LayoutError, match="ENOSPC"):
        init_layout(volume)
    assert sorted(entry.name for entry in volume.iterdir()) == ["active", "held"]


# --- secscan-admin init-runs-layout（compose 的 runs-init）---------------------------------------


@pytest.fixture
def bare_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """runs-init 沒有任何環境變數與 .env：Settings 會失敗，指令仍然要能執行。"""
    for name in list(os.environ):
        if name.startswith(("DB_", "APP_", "RUNNER_")) or name.endswith("_ENCRYPTION_KEYS"):
            monkeypatch.delenv(name)
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.chdir(tmp_path)


def test_init_runs_without_database_or_keys(
    bare_environment: None, volume: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["init-runs-layout", "--runs-dir", str(volume)]) == EXIT_OK
    assert "已建立" in capsys.readouterr().err
    assert main(["init-runs-layout", "--runs-dir", str(volume)]) == EXIT_OK
    assert "layout 正確" in capsys.readouterr().err


def test_init_fails_on_the_old_layout(
    bare_environment: None, volume: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (volume / str(uuid4())).mkdir()

    assert main(["init-runs-layout", "--runs-dir", str(volume)]) == EXIT_FAILURE

    err = capsys.readouterr().err
    assert "make runs-layout-migrate" in err
    assert "runner 與 worker 不會啟動" in err
    assert str(volume) not in err
