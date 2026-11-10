"""runs volume 的檔案操作（runner/fs.py）：不跟隨 symlink、有上限，錯誤只帶種類不帶路徑。"""

import os
from pathlib import Path
from typing import Any

import pytest

from secscan.runner import fs
from secscan.runner.fs import (
    TreeError,
    TreeLimit,
    TreeLimitError,
    TreeLimits,
    list_tree,
    open_directory,
    opened,
    remove_empty_directories,
    remove_tree,
    unlink_at,
)


def _tree(root: Path) -> None:
    (root / "a" / "b").mkdir(parents=True)
    (root / "a" / "b" / "file.txt").write_bytes(b"x")
    (root / "top.txt").write_bytes(b"y")


def test_listing_is_complete_and_skips_only_the_top_level(tmp_path: Path) -> None:
    _tree(tmp_path)
    (tmp_path / "skip").mkdir()
    (tmp_path / "skip" / "inside.txt").write_bytes(b"z")
    (tmp_path / "link").symlink_to(tmp_path / "top.txt")

    with opened(open_directory(tmp_path)) as root:
        tree = list_tree(root, TreeLimits(), skip=frozenset({"skip"}))

    assert sorted(tree.files) == ["a/b/file.txt", "top.txt"]
    assert tree.others == ["link"]
    assert sorted(tree.directories) == ["a", "a/b"]
    assert tree.newest_mtime > 0


@pytest.mark.parametrize("limits", [TreeLimits(max_depth=1), TreeLimits(max_entries=2)])
def test_limits_fail_closed(tmp_path: Path, limits: TreeLimits) -> None:
    _tree(tmp_path)

    with opened(open_directory(tmp_path)) as root, pytest.raises(TreeError, match="上限"):
        list_tree(root, limits)


@pytest.mark.parametrize(
    ("limits", "limit"),
    [(TreeLimits(max_depth=1), TreeLimit.DEPTH), (TreeLimits(max_entries=2), TreeLimit.ENTRIES)],
)
def test_limit_errors_say_which_limit(tmp_path: Path, limits: TreeLimits, limit: TreeLimit) -> None:
    """keeper 只對這兩種失敗計數、隔離（EVID-08；docs/DECISIONS.md §30.12）。"""
    _tree(tmp_path)

    with opened(open_directory(tmp_path)) as root, pytest.raises(TreeLimitError) as raised:
        list_tree(root, limits)

    assert raised.value.limit is limit
    assert str(tmp_path) not in str(raised.value)


def test_the_total_path_length_is_limited_and_not_a_hold(tmp_path: Path) -> None:
    """很長的路徑會讓整棵樹的記憶體超過 runner 的上限：另外限制總長度，超過時是一般的
    TreeError（不隔離；安全審查 M1，§30.12）。"""
    _tree(tmp_path)

    with opened(open_directory(tmp_path)) as root, pytest.raises(TreeError) as raised:
        list_tree(root, TreeLimits(max_path_chars=22))

    assert "路徑總長度" in str(raised.value)
    assert not isinstance(raised.value, TreeLimitError)
    with opened(open_directory(tmp_path)) as root:
        assert list_tree(root, TreeLimits(max_path_chars=23)).path_chars == 23


def test_errors_carry_only_the_kind(tmp_path: Path) -> None:
    with pytest.raises(TreeError) as raised:
        open_directory(tmp_path / "missing")

    assert "ENOENT" in str(raised.value)
    assert str(tmp_path) not in str(raised.value)
    assert not isinstance(raised.value, TreeLimitError)


def test_a_symlinked_directory_is_not_opened(tmp_path: Path) -> None:
    (tmp_path / "real").mkdir()
    (tmp_path / "alias").symlink_to(tmp_path / "real", target_is_directory=True)

    with opened(open_directory(tmp_path)) as root, pytest.raises(TreeError):
        fs.open_child("alias", root)


def test_an_unreadable_directory_is_reported(tmp_path: Path) -> None:
    _tree(tmp_path)
    (tmp_path / "a").chmod(0o000)
    try:
        with opened(open_directory(tmp_path)) as root, pytest.raises(TreeError):
            list_tree(root, TreeLimits())
    finally:
        (tmp_path / "a").chmod(0o700)


def test_unlinking_is_idempotent_and_reports_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _tree(tmp_path)
    with opened(open_directory(tmp_path)) as root:
        unlink_at(root, "a/b/file.txt")
        unlink_at(root, "a/b/file.txt")

        def denied(*_args: Any, **_kwargs: Any) -> None:
            raise PermissionError(13, "denied")

        monkeypatch.setattr(os, "unlink", denied)
        with pytest.raises(TreeError, match="EACCES"):
            unlink_at(root, "top.txt")


def test_only_empty_directories_are_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _tree(tmp_path)
    (tmp_path / "empty" / "deeper").mkdir(parents=True)
    with opened(open_directory(tmp_path)) as root:
        remove_empty_directories(root, ["a", "a/b", "empty", "empty/deeper", "gone"])

    assert (tmp_path / "a" / "b" / "file.txt").exists()
    assert not (tmp_path / "empty").exists()

    def denied(*_args: Any, **_kwargs: Any) -> None:
        raise PermissionError(13, "denied")

    (tmp_path / "other").mkdir()
    monkeypatch.setattr(os, "rmdir", denied)
    with opened(open_directory(tmp_path)) as root, pytest.raises(TreeError, match="EACCES"):
        remove_empty_directories(root, ["other"])


def test_removing_a_tree_does_not_follow_links(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_bytes(b"keep")
    target = tmp_path / "target"
    _tree(target)
    (target / "link").symlink_to(outside, target_is_directory=True)

    with opened(open_directory(tmp_path)) as parent:
        remove_tree(parent, "target", TreeLimits())
        remove_tree(parent, "target", TreeLimits())

    assert not target.exists()
    assert (outside / "keep.txt").read_bytes() == b"keep"


def test_removing_a_tree_reports_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _tree(tmp_path / "target")
    real_rmdir = os.rmdir

    def denied(path: Any, *, dir_fd: int | None = None) -> None:
        if path == "target":
            raise PermissionError(13, "denied")
        real_rmdir(path, dir_fd=dir_fd)

    monkeypatch.setattr(os, "rmdir", denied)
    with opened(open_directory(tmp_path)) as parent, pytest.raises(TreeError, match="EACCES"):
        remove_tree(parent, "target", TreeLimits())
    (tmp_path / "file").write_bytes(b"")
    with opened(open_directory(tmp_path)) as parent, pytest.raises(TreeError):
        remove_tree(parent, "file", TreeLimits())


def test_fsync_failures_are_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(_fd: int) -> None:
        raise OSError(5, "I/O error")

    monkeypatch.setattr(os, "fsync", broken)
    with opened(open_directory(tmp_path)) as root, pytest.raises(TreeError, match="EIO"):
        fs.fsync_directory(root)
