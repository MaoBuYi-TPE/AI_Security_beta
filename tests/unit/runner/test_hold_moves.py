"""隔離目錄在 active/ 與 held/ 之間的搬移（EVID-11；docs/DECISIONS.md §30.13）。

- 搬移只處理真的目錄、inode 必須相符、目的地必須不存在；之後 fsync 兩個區域、確認結果。
- 審查的反例：檢查與 rename 之間出現同名、非空的目錄 → rename 失敗、不覆寫；已有空的同名目錄
  → 事前檢查判定為衝突、不被取代。
- identify：真的目錄、同一個裝置、inode 相符；不符就是衝突。
"""

import errno
import os
from collections.abc import Callable
from pathlib import Path
from uuid import uuid4

import pytest

from secscan.runner import fs, hold_moves
from secscan.runner.hold_moves import MAX_HELD_ENTRIES, HoldMoves, MoveError
from secscan.runner.layout import Area
from secscan.runner.sealed_files import EvidenceError
from secscan.scans.domain.evidence import HoldMoveCode
from tests.runs_volume_support import runs_volume

NAME = str(uuid4())
CANARY = b"canary-hold-moves-41c9"


@pytest.fixture
def runs(tmp_path: Path) -> Path:
    return runs_volume(tmp_path)


@pytest.fixture
def held(runs: Path) -> Path:
    return runs.parent / "held"


@pytest.fixture
def moves(runs: Path) -> HoldMoves:
    return HoldMoves(runs.parent)


def _directory(area: Path, name: str = NAME) -> int:
    (area / name / "out").mkdir(parents=True)
    (area / name / "out" / "messages.txt").write_bytes(CANARY)
    return (area / name).lstat().st_ino


def _code(action: Callable[[], object]) -> HoldMoveCode:
    with pytest.raises(MoveError) as raised:
        action()
    return raised.value.code


def test_a_directory_moves_to_held_with_its_contents(
    runs: Path, held: Path, moves: HoldMoves
) -> None:
    source_ino = _directory(runs)

    moves.move(NAME, Area.ACTIVE, Area.HELD, source_ino)

    assert not (runs / NAME).exists()
    assert (held / NAME / "out" / "messages.txt").read_bytes() == CANARY
    assert (held / NAME).lstat().st_ino == source_ino
    assert moves.presence(NAME) == hold_moves.Presence(active=False, held=True)
    moves.move(NAME, Area.HELD, Area.ACTIVE, source_ino)
    assert moves.presence(NAME) == hold_moves.Presence(active=True, held=False)


def test_both_areas_are_synced_after_the_rename(
    runs: Path, moves: HoldMoves, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_ino = _directory(runs)
    calls: list[str] = []
    real_rename, real_fsync = os.rename, fs.fsync_directory

    def rename(*args: object, **kwargs: object) -> None:
        calls.append("rename")
        real_rename(*args, **kwargs)  # type: ignore[arg-type]

    def fsync(fd: int) -> None:
        calls.append(f"fsync:{os.fstat(fd).st_ino}")
        real_fsync(fd)

    monkeypatch.setattr(os, "rename", rename)
    monkeypatch.setattr(hold_moves, "fsync_directory", fsync)

    moves.move(NAME, Area.ACTIVE, Area.HELD, source_ino)

    held_ino = (runs.parent / "held").stat().st_ino
    active_ino = runs.stat().st_ino
    assert calls == ["rename", f"fsync:{held_ino}", f"fsync:{active_ino}"]


@pytest.mark.parametrize(
    ("prepare", "code"),
    [
        (lambda runs: None, HoldMoveCode.DIRECTORY_MISSING),
        (lambda runs: (runs / NAME).write_bytes(b"file"), HoldMoveCode.NOT_DIRECTORY),
        (lambda runs: (runs / NAME).symlink_to(runs.parent / "held"), HoldMoveCode.NOT_DIRECTORY),
        (lambda runs: (runs / NAME).mkdir(), HoldMoveCode.CONFLICT),
    ],
    ids=["missing", "file", "symlink", "other-inode"],
)
def test_only_the_recorded_directory_is_moved(
    runs: Path, held: Path, moves: HoldMoves, prepare: Callable[[Path], object], code: HoldMoveCode
) -> None:
    prepare(runs)

    assert _code(lambda: moves.move(NAME, Area.ACTIVE, Area.HELD, 1)) is code
    assert not (held / NAME).exists()


def test_an_empty_directory_in_the_destination_is_a_conflict(
    runs: Path, held: Path, moves: HoldMoves
) -> None:
    """rename 會默默取代空的目錄：事前檢查判定為衝突，來源與目的地都不動（審查的反例）。"""
    source_ino = _directory(runs)
    (held / NAME).mkdir()
    placeholder = (held / NAME).lstat().st_ino

    assert _code(lambda: moves.move(NAME, Area.ACTIVE, Area.HELD, source_ino)) is (
        HoldMoveCode.CONFLICT
    )
    assert (held / NAME).lstat().st_ino == placeholder
    assert (runs / NAME / "out" / "messages.txt").read_bytes() == CANARY


def test_a_directory_appearing_before_the_rename_is_not_overwritten(
    runs: Path, held: Path, moves: HoldMoves, monkeypatch: pytest.MonkeyPatch
) -> None:
    """審查的反例：檢查與 rename 之間出現同名、非空的目錄 → rename 失敗，既有的內容不被覆寫。"""
    source_ino = _directory(runs)
    real_rename = os.rename

    def racing(*args: object, **kwargs: object) -> None:
        (held / NAME / "existing").mkdir(parents=True)
        (held / NAME / "existing" / "evidence.txt").write_bytes(b"keep")
        real_rename(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "rename", racing)

    assert _code(lambda: moves.move(NAME, Area.ACTIVE, Area.HELD, source_ino)) is (
        HoldMoveCode.CONFLICT
    )
    assert (held / NAME / "existing" / "evidence.txt").read_bytes() == b"keep"
    assert (runs / NAME / "out" / "messages.txt").read_bytes() == CANARY


@pytest.mark.parametrize(
    ("number", "code"),
    [
        (errno.ENOTEMPTY, HoldMoveCode.CONFLICT),
        (errno.EEXIST, HoldMoveCode.CONFLICT),
        (errno.ENOENT, HoldMoveCode.DIRECTORY_MISSING),
        (errno.EXDEV, HoldMoveCode.MOVE_FAILED),
        (errno.EACCES, HoldMoveCode.MOVE_FAILED),
    ],
)
def test_rename_errors_have_codes(
    runs: Path, moves: HoldMoves, monkeypatch: pytest.MonkeyPatch, number: int, code: HoldMoveCode
) -> None:
    source_ino = _directory(runs)

    def broken(*_args: object, **_kwargs: object) -> None:
        raise OSError(number, os.strerror(number))

    monkeypatch.setattr(os, "rename", broken)

    assert _code(lambda: moves.move(NAME, Area.ACTIVE, Area.HELD, source_ino)) is code
    assert (runs / NAME).is_dir()


def test_a_failed_sync_is_a_move_failure_after_the_rename(
    runs: Path, held: Path, moves: HoldMoves, monkeypatch: pytest.MonkeyPatch
) -> None:
    """fsync 失敗時 rename 已經發生：回報失敗（DB 不寫 isolated_at），對帳之後確認身分再補寫。"""
    source_ino = _directory(runs)

    def broken(_fd: int) -> None:
        raise fs.TreeError("無法同步目錄（EIO）")

    monkeypatch.setattr(hold_moves, "fsync_directory", broken)

    assert _code(lambda: moves.move(NAME, Area.ACTIVE, Area.HELD, source_ino)) is (
        HoldMoveCode.MOVE_FAILED
    )
    assert (held / NAME).is_dir()


def test_identify_checks_type_device_and_inode(
    runs: Path, held: Path, moves: HoldMoves, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_ino = _directory(held)
    moves.identify(NAME, Area.HELD, source_ino)

    assert _code(lambda: moves.identify(NAME, Area.HELD, source_ino + 1)) is HoldMoveCode.CONFLICT
    assert _code(lambda: moves.identify(NAME, Area.ACTIVE, source_ino)) is (
        HoldMoveCode.DIRECTORY_MISSING
    )
    other = str(uuid4())
    (held / other).symlink_to(held / NAME)
    assert _code(lambda: moves.identify(other, Area.HELD, source_ino)) is HoldMoveCode.CONFLICT

    real_fstat = os.fstat

    def other_device(fd: int) -> os.stat_result:
        info = real_fstat(fd)
        return os.stat_result((*info[:2], info.st_dev + 1, *info[3:]))

    monkeypatch.setattr(os, "fstat", other_device)
    assert _code(lambda: moves.identify(NAME, Area.HELD, source_ino)) is HoldMoveCode.CONFLICT


def test_held_entries_list_uuid_directories_and_count_the_rest(
    held: Path, moves: HoldMoves
) -> None:
    _directory(held)
    (held / "notes.txt").write_bytes(b"x")
    (held / str(uuid4())).symlink_to(held / NAME)

    listing = moves.held_entries()

    assert listing.directories == (NAME,)
    assert listing.others == 2


def test_too_many_held_entries_fail_closed(
    held: Path, moves: HoldMoves, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(hold_moves, "MAX_HELD_ENTRIES", 2)
    for _ in range(3):
        (held / str(uuid4())).mkdir()

    with pytest.raises(EvidenceError, match="上限"):
        moves.held_entries()
    assert MAX_HELD_ENTRIES == 20_000


def test_a_missing_area_is_a_global_error(runs: Path, moves: HoldMoves) -> None:
    (runs.parent / "held").rmdir()

    with pytest.raises(EvidenceError, match="held/") as raised:
        moves.presence(NAME)
    assert not isinstance(raised.value, MoveError)
    with pytest.raises(ValueError, match="UUID"):
        moves.presence("not-a-uuid")


def test_the_direction_must_be_between_two_areas(runs: Path, moves: HoldMoves) -> None:
    """審查 L3：來源與目的地相同是呼叫端的錯誤，不能被當成任一方向搬移。"""
    source_ino = _directory(runs)

    for area in Area:
        with pytest.raises(ValueError, match="不同的區域"):
            moves.move(NAME, area, area, source_ino)
    assert (runs / NAME).is_dir()
